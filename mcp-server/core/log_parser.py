"""BreachTracker: the per-endpoint "tripwire" described in docs/design-notes.md.

Tracks two separate signals per endpoint (URL path, query string stripped):

- **Blocked** requests: ModSecurity's error log, i.e. what the WAF stopped.
- **Bypassed** requests: the WAF's access log, filtered to only requests that
  carry `fire.py`'s `_wave_marker` query param (so this only ever counts
  traffic the offensive pipeline actually fired, never real user traffic that
  happens to return 2xx) and that got a 2xx response.

Only *bypasses* trip config.BREACH_THRESHOLD. This matches the proposal's own
language ("analyzes successful WAF bypasses", "endpoint breach threshold") -
an earlier version of this tracker used the blocked count as the tripwire
instead, which was backwards: a payload the WAF blocks is already handled,
and a fully-successful mutation wave (0 blocks) would never have tripped the
threshold at all, even though that's the exact scenario the defensive loop
exists to catch. See docs/design-notes.md's annotation on "Threshold
tracking" for the full writeup of that gap. Blocked counts are still tracked
and returned - they're useful telemetry (e.g. sizing read_waf_logs()'s
default `lines`) - they just no longer decide `tripped_endpoints`.

Correlating on `_wave_marker` rather than re-inspecting payload content is a
closed-loop-simulation shortcut: it works because only this project's own
attacker pipeline ever attaches that marker, so its presence is a reliable
stand-in for "this was attacker traffic" without needing real signature
matching. `harness/log_reader.py` on the attacker-pipeline side already
relies on the same marker for the same reason.
"""

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
_ACCESS_LINE_RE = re.compile(r'"[A-Z]+ (\S+) HTTP/[\d.]+" (\d{3})')


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
    attacker-fired request (`_wave_marker` present) that got a 2xx response -
    i.e. actually reached the app instead of being blocked.
    """
    if "_wave_marker=" not in line:
        return None
    match = _ACCESS_LINE_RE.search(line)
    if not match:
        return None
    path, status = match.groups()
    if not status.startswith("2"):
        return None
    return path.split("?", 1)[0]


class _OffsetLog:
    """One growing log file, scanned incrementally: each poll() only reads
    bytes appended since the last call (via a persisted byte offset) so
    repeated calls don't re-scan or double-count old lines. Starts at
    end-of-file so a fresh server process only counts activity that happens
    after it starts, not the entire log history.
    """

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self._offset = log_path.stat().st_size if log_path.exists() else 0

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
    """

    def __init__(self, error_log_path: str | None = None, access_log_path: str | None = None):
        self._error_log = _OffsetLog(Path(error_log_path or config.WAF_ERROR_LOG))
        self._access_log = _OffsetLog(Path(access_log_path or config.WAF_ACCESS_LOG))
        self._blocked_counts: dict[str, int] = defaultdict(int)
        self._bypass_counts: dict[str, int] = defaultdict(int)

    def poll(self) -> tuple[dict[str, int], dict[str, int]]:
        """Scan any newly appended lines in both logs, update the running
        per-endpoint tallies, and return (blocked_counts, bypass_counts).
        """
        for line in self._error_log.new_lines():
            endpoint = _extract_blocked_endpoint(line)
            if endpoint is not None:
                self._blocked_counts[endpoint] += 1

        for line in self._access_log.new_lines():
            endpoint = _extract_bypassed_endpoint(line)
            if endpoint is not None:
                self._bypass_counts[endpoint] += 1

        return dict(self._blocked_counts), dict(self._bypass_counts)

    def status(self, endpoint: str | None = None) -> dict:
        """Return the current blocked/bypass tallies plus which endpoints
        have crossed config.BREACH_THRESHOLD on *bypasses* - blocked traffic
        is already handled by the WAF and never trips the threshold. If
        `endpoint` is given, restrict the result to just that one endpoint.
        """
        blocked, bypassed = self.poll()
        if endpoint is not None:
            blocked = {endpoint: blocked.get(endpoint, 0)}
            bypassed = {endpoint: bypassed.get(endpoint, 0)}

        tripped = [ep for ep, count in bypassed.items() if count >= config.BREACH_THRESHOLD]
        return {
            "blocked_counts": blocked,
            "bypass_counts": bypassed,
            "threshold": config.BREACH_THRESHOLD,
            "tripped_endpoints": tripped,
            "checked_at": time.time(),
        }
