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
"""

import json
import re
import time
from collections import defaultdict, deque
from pathlib import Path

import config

# Matches the `request: "METHOD /path?query HTTP/1.1"` field ModSecurity's
# error log includes on every blocked request (see waf-defense/logs/error.log
# for real examples). Capturing group 1 is the raw path+query.
_ERROR_LINE_RE = re.compile(r'request: "[A-Z]+ (\S+) HTTP')

# Matches the request line + status code in nginx's combined access-log
# format, e.g. `"GET /path?q=x HTTP/1.1" 200 824 ...`.
_ACCESS_LINE_RE = re.compile(r'"[A-Z]+ (\S+) HTTP/[\d.]+" (\d{3})')

# Pulls the attack family straight out of _wave_marker's own value - see the
# module docstring for why this beats inspecting payload content. Matches
# attacker-pipeline/harness/orchestrator.py's payload_id format exactly:
# f"w{wave_id}-{seed['id']}-{idx}", where seed['id'] is itself "<family>-NN".
_FAMILY_RE = re.compile(r"_wave_marker=w\d+-([a-z]+)-")


def _extract_family(line: str) -> str:
    """Pull the attack family (e.g. "sqli", "xss") out of a bypass line's
    `_wave_marker` value. Falls back to "unknown" rather than dropping the
    sample outright if the marker doesn't match the expected shape - a
    missing/malformed family tag shouldn't hide the bypass itself.
    """
    match = _FAMILY_RE.search(line)
    return match.group(1) if match else "unknown"


def _new_family_samples() -> "defaultdict[str, deque]":
    """Factory for a fresh per-endpoint family->deque map - a defaultdict so
    a newly-seen family at an already-tracked endpoint doesn't need an
    explicit setdefault at every call site.
    """
    return defaultdict(lambda: deque(maxlen=config.BYPASS_SAMPLE_LIMIT))


def _extract_blocked_endpoint(line: str) -> str | None:
    """Pull just the URL path out of an error-log line, dropping the query
    string so e.g. two attacks with different `?_wave_marker=...` values
    still count against the same endpoint. Returns None for lines that
    aren't blocked requests (e.g. unrelated nginx warnings).
    """
    if "ModSecurity" not in line or "Access denied" not in line:
        return None
    match = _ERROR_LINE_RE.search(line)
    if not match:
        return None
    return match.group(1).split("?", 1)[0]


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
    path, status = match.groups()
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

    def __init__(self, error_log_path: str | None = None, access_log_path: str | None = None):
        error_log = Path(error_log_path or config.WAF_ERROR_LOG)
        access_log = Path(access_log_path or config.WAF_ACCESS_LOG)
        state = self._load_state()

        error_offset, error_stale = self._initial_offset(error_log, state.get("error_offset"))
        access_offset, access_stale = self._initial_offset(
            access_log, state.get("access_offset")
        )
        self._error_log = _OffsetLog(error_log, error_offset)
        self._access_log = _OffsetLog(access_log, access_offset)

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
        if error_stale or access_stale:
            self._blocked_counts: dict[str, int] = defaultdict(int)
            self._bypass_counts: dict[str, int] = defaultdict(int)
            self._bypass_samples: dict[str, dict[str, deque]] = defaultdict(_new_family_samples)
        else:
            self._blocked_counts = defaultdict(int, state.get("blocked_counts", {}))
            self._bypass_counts = defaultdict(int, state.get("bypass_counts", {}))
            self._bypass_samples = defaultdict(_new_family_samples)
            for endpoint, families in state.get("bypass_samples", {}).items():
                for family, lines in families.items():
                    self._bypass_samples[endpoint][family] = deque(
                        lines, maxlen=config.BYPASS_SAMPLE_LIMIT
                    )

    @staticmethod
    def _initial_offset(log_path: Path, saved_offset: int | None) -> tuple[int, bool]:
        """Where a log's _OffsetLog should start reading from, and whether
        the saved checkpoint had to be clamped (a sign the whole checkpoint
        is stale, not just this one offset).
        """
        current_size = log_path.stat().st_size if log_path.exists() else 0
        if saved_offset is None:
            # No checkpoint - either the very first time this server has ever
            # run against these logs, or one just cleared by reset_state.py.
            # Start at end-of-file so a fresh tracker doesn't sweep in
            # unrelated pre-existing log history. Not "stale" - there's
            # nothing to distrust when there was no checkpoint to begin with.
            return current_size, False
        if saved_offset > current_size:
            # The log is now *smaller* than the checkpoint (e.g. someone
            # truncated it by hand without also clearing this state file) -
            # the old offset points past end-of-file and is meaningless
            # against the new content. Treat the log as fresh instead of
            # seeking past its end.
            return current_size, True
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

    def poll(self) -> tuple[dict[str, int], dict[str, int]]:
        """Scan any newly appended lines in both logs, update the running
        per-endpoint tallies, persist the result, and return (blocked_counts,
        bypass_counts).
        """
        new_error_lines = self._error_log.new_lines()
        new_access_lines = self._access_log.new_lines()

        for line in new_error_lines:
            endpoint = _extract_blocked_endpoint(line)
            if endpoint is not None:
                self._blocked_counts[endpoint] += 1

        for line in new_access_lines:
            endpoint = _extract_bypassed_endpoint(line)
            if endpoint is not None:
                self._bypass_counts[endpoint] += 1
                family = _extract_family(line)
                self._bypass_samples[endpoint][family].append(line.rstrip("\n"))

        if new_error_lines or new_access_lines:
            self._save_state()

        return dict(self._blocked_counts), dict(self._bypass_counts)

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
        samples = {
            ep: {family: list(lines) for family, lines in families.items()}
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
