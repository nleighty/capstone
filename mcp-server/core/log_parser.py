"""BreachTracker: the per-endpoint "tripwire" described in docs/design-notes.md.

Tracks two separate signals per endpoint (URL path, query string stripped):

- **Blocked** requests: ModSecurity's error log, i.e. what the WAF stopped.
- **Bypassed** requests: the WAF's access log, filtered to only requests that
  carry `fire.py`'s `_wave_marker` query param (so this only ever counts
  traffic the offensive pipeline actually fired, never real user traffic) and
  that got anything other than a 403 - i.e. the WAF didn't block it, full
  stop, regardless of what the app did with it afterward.

Only *bypasses* trip config.BREACH_THRESHOLD. This matches the proposal's own
language ("analyzes successful WAF bypasses", "endpoint breach threshold") -
a payload the WAF blocks is already handled, so a "significantly"
(>5 bypasses for this project)successful mutation
wave is exactly the scenario that should trip the
threshold. See docs/design-notes.md's "Threshold tracking"
section for the full rationale, including why a bypass means any non-403
response rather than specifically a 2xx. Blocked counts are still tracked
and returned - they're useful telemetry (e.g. sizing read_waf_logs()'s
default `lines`) - they just don't decide `tripped_endpoints`.

Correlating on `_wave_marker` rather than re-inspecting payload content is a
closed-loop-simulation shortcut: it works because only this project's own
attacker pipeline ever attaches that marker, so its presence is a reliable
stand-in for "this was attacker traffic" without needing real signature
matching. `harness/log_reader.py` on the attacker-pipeline side already
relies on the same marker for the same reason.

In addition to counts, this module keeps a small rolling sample of the raw
bypassing request lines themselves, bucketed by (endpoint, attack family), so
the Sprint 4 defensive agent has something to actually read when deciding
what a new rule should match - a bare count says a bypass happened, not what
it looked like. Family is read off the *marker's own structure*
(`_wave_marker=w<wave>-<family>-<seed>-<idx>`, e.g. `w3-sqli-05-2`), not by
inspecting payload content: this project's premise is that the offensive LLM
generates obfuscated, polymorphic mutations specifically to evade
keyword/signature matching, so classifying by scanning payload text for
`<script>` or `UNION SELECT` would be exactly the naive detection this
project exists to defeat, and could misclassify the very payloads that
matter most. Reading the family out of the marker is the same category of
shortcut as the bare-presence correlation above - just leaned on a bit
further - rather than a new kind of payload inspection.

Bucketing by family (not just endpoint) matters because a single endpoint can
receive more than one attack family in the same wave (e.g.
`/rest/products/search` is targeted by both sqli and xss seeds in
`attacker-pipeline/payloads/seeds.py`) - a flat per-endpoint sample cap would
let whichever family bypasses later in the wave silently evict every example
of the other family before the agent ever sees them.

A GET attack's payload is visible in the access-log line itself (it's in the
query string), but a POST attack's payload is not - nginx's access log has no
body field, and neither does its error log (confirmed empirically: the
`[data ""]` field is empty for POST-body SQLi blocks). The only place the
actual injected value shows up at all is ModSecurity's own JSON audit log
(`config.WAF_AUDIT_LOG`, enabled via docker-compose.yml's MODSEC_AUDIT_LOG/
MODSEC_AUDIT_ENGINE env vars), which includes a `messages[].details.data`
field like `"Matched Data: ... found within ARGS:json.email: ' OR 1=1--"`
whenever a CRS rule's signature matched - straight from ModSecurity's own
detection engine, not our own guesswork. This module additionally scans that
log and feeds matching entries into the same per-(endpoint, family) sample
buckets, purely as enrichment - bypass_counts stays sourced from the access
log alone, unchanged.
"""

import json
import re
import time
from collections import defaultdict
from pathlib import Path

import config

# Matches the `request: "METHOD /path?query HTTP/1.1"` field ModSecurity's
# error log includes on every blocked request (see waf-defense/logs/error.log
# for real examples). Capturing group 1 is the raw path+query.
_ERROR_LINE_RE = re.compile(r'request: "[A-Z]+ (\S+) HTTP')

# Matches the request line + status code in nginx's combined access-log
# format, e.g. `"GET /path?q=x HTTP/1.1" 200 824 ...`.
_ACCESS_LINE_RE = re.compile(r'"([A-Z]+) (\S+) HTTP/[\d.]+" (\d{3})')

# Pulls the attack family straight out of _wave_marker's own value - see the
# module docstring for why this beats inspecting payload content. Matches
# attacker-pipeline/harness/orchestrator.py's payload_id format exactly:
# f"w{wave_id}-{seed['id']}-{idx}", where seed['id'] is itself "<family>-NN".
_FAMILY_RE = re.compile(r"_wave_marker=w\d+-([a-z]+)-")


# The full `_wave_marker=<value>` token, used to recognise two log lines as the
# same request (see BreachTracker._add_sample). The value ends at '&' or a
# space/quote, none of which appear in a marker.
_MARKER_RE = re.compile(r"_wave_marker=[\w-]+")


# The seed id inside a marker (`w3-sqli-05-2` -> `sqli-05`): which seed payload
# in attacker-pipeline/payloads/seeds.py a variant was mutated from. Used to
# keep the sample buffer *diverse across seeds* rather than recency-ordered -
# see BreachTracker._add_sample. Like the family, it is read off the marker's
# own structure, never off payload content.
_SEED_RE = re.compile(r"_wave_marker=w\d+-([a-z]+-\d+)-")


def _make_sample(text: str, method: str | None, uri: str | None, body: str | None = None,
                 content_type: str | None = None) -> dict:
    """Build the structured record stored for one bypassing request.

    `text` is what the defensive agent reads (unchanged from when samples were
    bare strings). The remaining fields exist so a later replay check
    (Sprint 4.5 step B) can re-send the *same* request without having to
    re-parse `text` - method/uri/body/content_type are the minimum needed to
    reconstruct it. `body` is stored in full (not truncated like `text`): a
    chopped JSON body would no longer parse and would replay as a different
    request than the one that bypassed.
    """
    marker = _MARKER_RE.search(uri or text)
    seed = _SEED_RE.search(uri or text)
    return {
        "text": text,
        "marker": marker.group(0) if marker else None,
        "seed": seed.group(1) if seed else "unknown",
        "method": method,
        "uri": uri,
        "body": body,
        "content_type": content_type,
    }


def _coerce_sample(entry) -> dict:
    """Accept a sample loaded from the persisted state file. Older state
    files stored samples as bare strings; wrap those so a server upgraded
    across this change keeps working (they just aren't replayable)."""
    if isinstance(entry, dict):
        return entry
    return _make_sample(str(entry), method=None, uri=None)


_LOG_TIME_RE = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)")
_LOG_CODE_RE = re.compile(r"Access denied with code (\d+)")
_LOG_RULE_ID_RE = re.compile(r'\[id "(\d+)"\]')
_LOG_MSG_RE = re.compile(r'\[msg "([^"]*)"\]')
_LOG_DATA_RE = re.compile(r'\[data "([^"]*)"\]')
_LOG_REQUEST_RE = re.compile(r'request: "([^"]*)"')


def compact_error_line(line: str) -> str:
    """Reduce one raw ModSecurity error-log line to its informative fields:
    time, status code, rule id, message, matched data (if any), request line.

    A raw "Access denied" line is ~350 tokens, most of it constant boilerplate
    (the CRS file path, version, maturity/accuracy tags, hostname, unique_id)
    - and for the common final-verdict rule 949110 the `[data ""]` field is
    empty, so nothing identifying the payload is lost by dropping the rest.
    Fifty raw lines were ~20k tokens (about 1/6 of an agent run's input, all
    of it written to the prompt cache) for almost no extra evidence beyond
    the bypass samples. Lines that aren't ModSecurity blocks (e.g. nginx
    warnings) are returned unchanged, only stripped.
    """
    if "ModSecurity" not in line or "Access denied" not in line:
        return line.strip()
    parts = []
    for regex in (_LOG_TIME_RE, _LOG_CODE_RE):
        m = regex.search(line)
        parts.append(m.group(1) if m else "?")
    rule_id = _LOG_RULE_ID_RE.search(line)
    msg = _LOG_MSG_RE.search(line)
    data = _LOG_DATA_RE.search(line)
    request = _LOG_REQUEST_RE.search(line)
    out = f"{parts[0]} {parts[1]} id={rule_id.group(1) if rule_id else '?'}"
    if msg:
        out += f' msg="{msg.group(1)}"'
    if data and data.group(1):
        out += f' data="{data.group(1)}"'
    if request:
        out += f" request={request.group(1)}"
    return out


def _extract_family(line: str) -> str:
    """Pull the attack family (e.g. "sqli", "xss") out of a bypass line's
    `_wave_marker` value. Falls back to "unknown" rather than dropping the
    sample outright if the marker doesn't match the expected shape - a
    missing/malformed family tag shouldn't hide the bypass itself.
    """
    match = _FAMILY_RE.search(line)
    return match.group(1) if match else "unknown"


def _new_family_samples() -> "defaultdict[str, list]":
    """Factory for a fresh per-endpoint family->samples map - a defaultdict so
    a newly-seen family at an already-tracked endpoint doesn't need an
    explicit setdefault at every call site. Plain lists, not bounded deques:
    capping is done by BreachTracker._add_sample, which has to evict by seed
    rather than simply dropping the oldest entry.
    """
    return defaultdict(list)


def _extract_blocked_endpoint(line: str) -> str | None:
    """Pull just the URL path out of an error-log line, dropping the query
    string so e.g. two attacks with different `?_wave_marker=...` values
    still count against the same endpoint. Returns None for lines that
    aren't blocked requests (e.g. unrelated nginx warnings).
    """
    if "ModSecurity" not in line or "Access denied" not in line:
        return None
    # Requests sent by core/rule_verifier.py carry `_replay=1`. Unlike the
    # access/audit paths (which only count `_wave_marker` traffic), this
    # function counts *every* block, so without this a verification run would
    # inflate blocked_counts with the agent's own test traffic.
    if "_replay=1" in line:
        return None
    match = _ERROR_LINE_RE.search(line)
    if not match:
        return None
    return match.group(1).split("?", 1)[0]


def _extract_audit_sample(line: str) -> tuple[str, str, dict] | None:
    """Parse one line of ModSecurity's JSON audit log (one transaction per
    line - "Serial" format) and return (endpoint, family, sample_dict) for a
    bypass, or None if this line isn't a wave-marked bypass (or doesn't
    parse - a partially-written last line at scan time, for instance).

    Prefers the actual matched payload data ModSecurity itself extracted
    (e.g. "Matched Data: ... found within ARGS:json.email: ' OR 1=1--") over
    the bare URI, since that's the only place a POST body's content exists
    at all. Falls back to the URI alone when no rule logged matched data
    (e.g. a payload that evaded every CRS rule outright, or a GET request
    where the URI already carries the payload).
    """
    try:
        transaction = json.loads(line)["transaction"]
        uri = transaction["request"]["uri"]
        status = transaction["response"]["http_code"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None

    if "_wave_marker=" not in uri or status == 403:
        return None

    endpoint = uri.split("?", 1)[0]
    family = _extract_family(uri)
    matched_data = [
        m["details"]["data"]
        for m in transaction.get("messages", [])
        if m.get("details", {}).get("data")
    ]
    # The raw request body (audit-log part C, enabled in docker-compose.yml)
    # is the only place a POST payload that evaded every CRS rule exists at
    # all - such a request has no matched data, so without this the sample
    # would be just the bare URI. Capped so one oversized body can't blow up
    # the agent's prompt (the samples are sent to the LLM verbatim).
    body = transaction["request"].get("body")
    parts = [uri]
    if body:
        parts.append(f"body: {body[:config.BYPASS_BODY_MAX_CHARS]}")
    if matched_data:
        parts.append("; ".join(matched_data))
    headers = transaction["request"].get("headers") or {}
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), None)
    sample = _make_sample(
        " - ".join(parts),
        method=transaction["request"].get("method"),
        uri=uri,
        body=body or None,
        content_type=content_type,
    )
    return endpoint, family, sample


def _extract_bypassed_endpoint(line: str) -> str | None:
    """Pull the URL path out of an access-log line if (and only if) it's an
    attacker-fired request (`_wave_marker` present) that the WAF didn't
    block - any status other than 403 (Nginx logs ModSecurity's own blocks as
    403 in the access log too, so excluding it is enough; no need to
    cross-reference the error log here).

    Deliberately not restricted to 2xx: every wave-marked request is a
    genuine mutated SQLi/XSS payload from payloads/seeds.py (fire.py is the
    only thing that ever attaches this marker, and it never fires anything
    else), so there's no benign traffic to accidentally sweep in here. A 401
    or 500 on one of these still means the WAF failed to recognize a real
    attack pattern and let it reach the app - the app then rejecting it for
    its own unrelated reasons (e.g. wrong credentials, a 500 in some other
    code path) doesn't change that the WAF missed it. Requiring 2xx would
    make this metric depend on the app's behavior as much as the WAF's,
    which is a different thing to measure than WAF efficacy - and RFPR
    already covers false-positive risk separately, against a disjoint set of
    genuinely benign requests that never carry this marker.
    """
    if "_wave_marker=" not in line:
        return None
    match = _ACCESS_LINE_RE.search(line)
    if not match:
        return None
    _method, path, status = match.groups()
    if status == "403":
        return None
    return path.split("?", 1)[0]


class _OffsetLog:
    """One growing log file, scanned incrementally from a given starting byte
    offset: each call to new_lines() reads only bytes appended since the last
    call, so repeated calls don't re-scan or double-count old lines. The
    starting offset itself is supplied by the caller (BreachTracker) rather
    than always defaulting to end-of-file, so it can resume from a persisted
    checkpoint after a restart instead of silently skipping activity that
    happened before the restart - see
    docs/debug-notes-sprint3-restart-offset.md for the bug this replaced.
    """

    def __init__(self, log_path: Path, start_offset: int):
        self.log_path = log_path
        self._offset = start_offset

    @property
    def offset(self) -> int:
        return self._offset

    def new_lines(self) -> list[str]:
        if not self.log_path.exists():
            return []
        with self.log_path.open("r", errors="replace") as f:
            f.seek(self._offset)
            lines = f.readlines()
            self._offset = f.tell()
        return lines


class BreachTracker:
    """Tracks per-endpoint blocked- and bypass-counts across the MCP server's
    lifetime, using the same incremental-offset log-scanning technique as
    attacker-pipeline/harness/log_reader.py's LogReader (reimplemented rather
    than imported, since attacker-pipeline is the test-harness layer and this
    is core production code - docs/design-notes.md keeps the two separate).

    Tallies and read offsets are persisted to config.BREACH_STATE_FILE after
    every poll() that sees new activity, and reloaded on construction. This
    is what lets an unplanned restart (crash, host reboot) resume exactly
    where it left off instead of either double-counting already-tallied
    lines or silently losing them - see
    docs/debug-notes-sprint3-restart-offset.md. An *intentional* reset
    (reset_state.py) deletes this file alongside truncating the logs, so
    logs and tallies can never drift out of sync with each other.
    """

    def __init__(
        self,
        error_log_path: str | None = None,
        access_log_path: str | None = None,
        audit_log_path: str | None = None,
    ):
        error_log = Path(error_log_path or config.WAF_ERROR_LOG)
        access_log = Path(access_log_path or config.WAF_ACCESS_LOG)
        audit_log = Path(audit_log_path or config.WAF_AUDIT_LOG)
        state = self._load_state()

        error_offset, error_stale = self._initial_offset(
            "error.log", error_log, state.get("error_offset")
        )
        access_offset, access_stale = self._initial_offset(
            "access.log", access_log, state.get("access_offset")
        )
        # Not fatal if this file doesn't exist yet (e.g. an older
        # docker-compose.yml without MODSEC_AUDIT_LOG set) - _OffsetLog.new_lines()
        # just returns [] forever in that case, same as any other missing log.
        audit_offset, audit_stale = self._initial_offset(
            "modsec_audit.log", audit_log, state.get("audit_offset")
        )
        self._error_log = _OffsetLog(error_log, error_offset)
        self._access_log = _OffsetLog(access_log, access_offset)
        self._audit_log = _OffsetLog(audit_log, audit_offset)

        # If either log needed clamping, one of them was truncated (or
        # replaced with something smaller) without this state file also being
        # cleared - reset_state.py always does both together, so this only
        # happens from a manual/out-of-band truncate. Either way, the saved
        # tallies were counted against log content that no longer exists, so
        # they're just as stale as the offset was - keeping them would silently
        # add fresh counts on top of numbers that no longer correspond to
        # anything on disk. Discard both tallies rather than only the one
        # offset that triggered the clamp, so log and tally state can't drift
        # apart from each other.
        if error_stale or access_stale or audit_stale:
            self._blocked_counts: dict[str, int] = defaultdict(int)
            self._bypass_counts: dict[str, int] = defaultdict(int)
            self._bypass_samples: dict[str, dict[str, list]] = defaultdict(_new_family_samples)
        else:
            self._blocked_counts = defaultdict(int, state.get("blocked_counts", {}))
            self._bypass_counts = defaultdict(int, state.get("bypass_counts", {}))
            self._bypass_samples = defaultdict(_new_family_samples)
            for endpoint, families in state.get("bypass_samples", {}).items():
                for family, entries in families.items():
                    self._bypass_samples[endpoint][family] = [_coerce_sample(e) for e in entries]

    @staticmethod
    def _initial_offset(label: str, log_path: Path, saved_offset: int | None) -> tuple[int, bool]:
        """Where a log's _OffsetLog should start reading from, and whether
        the saved checkpoint had to be clamped (a sign the whole checkpoint
        is stale, not just this one offset).

        Prints a startup line either way, since "started fresh and skipped
        existing content" and "resumed from a checkpoint" otherwise look
        identical from the outside - the server starting after traffic
        already fired silently skips it, and the only symptom is
        get_breach_status() reporting nothing.
        """
        current_size = log_path.stat().st_size if log_path.exists() else 0
        if saved_offset is None:
            # No checkpoint - either the very first time this server has ever
            # run against these logs, or one just cleared by reset_state.py.
            # Start at end-of-file so a fresh tracker doesn't sweep in
            # unrelated pre-existing log history. Not "stale" - there's
            # nothing to distrust when there was no checkpoint to begin with.
            if current_size > 0:
                print(
                    f"[BreachTracker] {label}: no checkpoint, but file already has "
                    f"{current_size} bytes - starting at end-of-file, existing content "
                    f"will NOT be counted. If the server started after traffic already "
                    f"fired, stop it, set this log's offset to 0 in "
                    f"{config.BREACH_STATE_FILE}, and restart."
                )
            else:
                print(f"[BreachTracker] {label}: no checkpoint, file is empty - starting at 0.")
            return current_size, False
        if saved_offset > current_size:
            # The log is now *smaller* than the checkpoint (e.g. someone
            # truncated it by hand without also clearing this state file) -
            # the old offset points past end-of-file and is meaningless
            # against the new content. Treat the log as fresh instead of
            # seeking past its end.
            print(
                f"[BreachTracker] {label}: checkpoint ({saved_offset}) is past the "
                f"current file size ({current_size}) - log was truncated without "
                f"clearing state; resetting to end-of-file."
            )
            return current_size, True
        print(f"[BreachTracker] {label}: resuming from checkpoint at offset {saved_offset}.")
        return saved_offset, False

    @staticmethod
    def _load_state() -> dict:
        try:
            return json.loads(Path(config.BREACH_STATE_FILE).read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_state(self) -> None:
        state_path = Path(config.BREACH_STATE_FILE)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "error_offset": self._error_log.offset,
            "access_offset": self._access_log.offset,
            "audit_offset": self._audit_log.offset,
            "blocked_counts": dict(self._blocked_counts),
            "bypass_counts": dict(self._bypass_counts),
            "bypass_samples": {
                endpoint: {family: list(lines) for family, lines in families.items()}
                for endpoint, families in self._bypass_samples.items()
            },
        }
        # Write to a temp file and rename over the real one so a crash
        # mid-write can't leave a half-written, unparseable state file behind
        # for the next start to trip over (os.replace/Path.replace is atomic
        # on the same filesystem).
        tmp_path = state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload))
        tmp_path.replace(state_path)

    def _add_sample(self, endpoint: str, family: str, sample: dict, enrich: bool) -> None:
        """Add a sample to its (endpoint, family) bucket, with two policies.

        **One entry per request** (identified by its _wave_marker value). The
        access log and the audit log both describe the same request; for a
        POST the access-log line is just a bare URI while the audit entry
        carries the body. Storing both would waste slots on one request. So an
        audit sample (`enrich=True`) replaces any existing sample for its
        marker, and an access-log line (`enrich=False`) is dropped if the
        marker already has one.

        **Diversity across seeds, not recency.** A plain "keep the last N"
        buffer shows the agent whichever mutation family happened to bypass
        most recently (in a real run, all 5 samples came from one seed while
        12 other bypasses were invisible), and across multi-wave runs later
        waves would push out every earlier one. Instead: at most
        config.BYPASS_SAMPLES_PER_SEED per seed, and when the bucket exceeds
        config.BYPASS_SAMPLE_LIMIT, evict the oldest sample of whichever seed
        currently holds the most - so rare seeds survive and common ones get
        thinned first.
        """
        bucket = self._bypass_samples[endpoint][family]
        marker = sample["marker"]
        if marker:
            # Exact comparison, not a substring test: "...-02-3" is a
            # substring of "...-02-30".
            existing = next((s for s in bucket if s["marker"] == marker), None)
            if existing is not None:
                if not enrich:
                    return
                bucket.remove(existing)
        bucket.append(sample)

        seed = sample["seed"]
        same_seed = [s for s in bucket if s["seed"] == seed]
        while len(same_seed) > config.BYPASS_SAMPLES_PER_SEED:
            bucket.remove(same_seed.pop(0))
        while len(bucket) > config.BYPASS_SAMPLE_LIMIT:
            counts: dict[str, int] = defaultdict(int)
            for s in bucket:
                counts[s["seed"]] += 1
            fullest = max(counts, key=counts.get)
            bucket.remove(next(s for s in bucket if s["seed"] == fullest))

    def poll(self) -> tuple[dict[str, int], dict[str, int]]:
        """Scan any newly appended lines across all three logs, update the
        running per-endpoint tallies, persist the result, and return
        (blocked_counts, bypass_counts).
        """
        new_error_lines = self._error_log.new_lines()
        new_access_lines = self._access_log.new_lines()
        new_audit_lines = self._audit_log.new_lines()

        for line in new_error_lines:
            endpoint = _extract_blocked_endpoint(line)
            if endpoint is not None:
                self._blocked_counts[endpoint] += 1

        for line in new_access_lines:
            endpoint = _extract_bypassed_endpoint(line)
            if endpoint is not None:
                self._bypass_counts[endpoint] += 1
                family = _extract_family(line)
                text = line.rstrip("\n")
                access = _ACCESS_LINE_RE.search(text)
                method, uri, _status = access.groups()
                # No body or content-type here (nginx's access log has neither),
                # so this is only replayable if it is a bodiless GET; a POST
                # gets upgraded when its audit entry arrives.
                self._add_sample(
                    endpoint, family, _make_sample(text, method=method, uri=uri), enrich=False
                )

        # Enrichment only - bypass_counts stays sourced from the access log
        # alone, so counting behavior already proven correct is untouched.
        for line in new_audit_lines:
            parsed = _extract_audit_sample(line)
            if parsed is not None:
                endpoint, family, sample = parsed
                self._add_sample(endpoint, family, sample, enrich=True)

        if new_error_lines or new_access_lines or new_audit_lines:
            self._save_state()

        return dict(self._blocked_counts), dict(self._bypass_counts)

    def samples_for(self, endpoint: str) -> list[dict]:
        """Every structured bypass sample held for `endpoint` (all attack
        families), after pulling in any newly logged activity. Server-side
        only - these records carry full request bodies and are what
        rule_verifier replays; the agent only ever sees their `text`.
        """
        self.poll()
        return [s for entries in self._bypass_samples.get(endpoint, {}).values() for s in entries]

    def status(self, endpoint: str | None = None) -> dict:
        """Return the current blocked/bypass tallies plus which endpoints
        have crossed config.BREACH_THRESHOLD on *bypasses* - blocked traffic
        is already handled by the WAF and never trips the threshold. If
        `endpoint` is given, restrict the result to just that one endpoint.

        Also includes `sample_bypasses`: a small rolling sample of the raw
        bypassing request lines, bucketed by (endpoint, attack family) - see
        the module docstring for why it's bucketed by family and not just
        endpoint. This is the evidence the Sprint 4 agent reads to decide
        what a new rule should match; the counts alone only say a bypass
        happened, not what it looked like.
        """
        blocked, bypassed = self.poll()
        # The agent-facing view is just the text of each sample; the structured
        # fields (method/uri/body) stay server-side for the replay check.
        samples = {
            ep: {family: [s["text"] for s in entries] for family, entries in families.items()}
            for ep, families in self._bypass_samples.items()
        }
        if endpoint is not None:
            blocked = {endpoint: blocked.get(endpoint, 0)}
            bypassed = {endpoint: bypassed.get(endpoint, 0)}
            samples = {endpoint: samples.get(endpoint, {})}

        tripped = [ep for ep, count in bypassed.items() if count >= config.BREACH_THRESHOLD]
        return {
            "blocked_counts": blocked,
            "bypass_counts": bypassed,
            "sample_bypasses": samples,
            "threshold": config.BREACH_THRESHOLD,
            "tripped_endpoints": tripped,
            "checked_at": time.time(),
        }
