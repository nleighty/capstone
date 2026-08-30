"""BreachTracker: the per-endpoint "tripwire" described in docs/design-notes.md.

Watches the WAF's error log and keeps a running count of how many times each
endpoint (URL path, query string stripped) has been blocked, so the future
Sprint 4 defensive agent can ask "which endpoint just crossed the threshold?"
instead of reacting to every single blocked request.
"""

import re
import time
from collections import defaultdict
from pathlib import Path

import config

# Matches the `request: "METHOD /path?query HTTP/1.1"` field ModSecurity's
# error log includes on every blocked request (see waf-defense/logs/error.log
# for real examples). Capturing group 1 is the raw path+query.
_REQUEST_LINE_RE = re.compile(r'request: "[A-Z]+ (\S+) HTTP')


def _extract_endpoint(line: str) -> str | None:
    """Pull just the URL path out of a log line, dropping the query string so
    e.g. two logins with different `?_wave_marker=...` values still count
    against the same endpoint. Returns None for lines that aren't blocked
    requests (e.g. unrelated nginx warnings) so they're never counted.
    """
    if "ModSecurity" not in line or "Access denied" not in line:
        return None
    match = _REQUEST_LINE_RE.search(line)
    if not match:
        return None
    return match.group(1).split("?", 1)[0]


class BreachTracker:
    """Tracks per-endpoint breach counts across the MCP server's lifetime.

    Uses the same incremental-offset technique as
    attacker-pipeline/harness/log_reader.py's LogReader (only scan bytes
    appended since the last read) so repeated calls don't re-scan or
    double-count the same lines. Reimplemented here rather than imported,
    since attacker-pipeline is the test-harness layer and this is core
    production code (docs/design-notes.md keeps the two separate).
    """

    def __init__(self, log_path: str | None = None):
        self.log_path = Path(log_path or config.WAF_ERROR_LOG)
        # Start at end-of-file: a fresh server process only counts breaches
        # that happen after it starts, not the entire log history.
        self._offset = self.log_path.stat().st_size if self.log_path.exists() else 0
        self._counts: dict[str, int] = defaultdict(int)

    def poll(self) -> dict[str, int]:
        """Scan any newly appended log lines, update the running per-endpoint
        counts, and return the full current tally.
        """
        if not self.log_path.exists():
            return dict(self._counts)

        with self.log_path.open("r", errors="replace") as f:
            f.seek(self._offset)
            new_lines = f.readlines()
            self._offset = f.tell()

        for line in new_lines:
            endpoint = _extract_endpoint(line)
            if endpoint is not None:
                self._counts[endpoint] += 1

        return dict(self._counts)

    def status(self, endpoint: str | None = None) -> dict:
        """Return the current breach tally plus which endpoints have crossed
        config.BREACH_THRESHOLD. If `endpoint` is given, restrict the result
        to just that one endpoint.
        """
        counts = self.poll()
        if endpoint is not None:
            counts = {endpoint: counts.get(endpoint, 0)}

        tripped = [ep for ep, count in counts.items() if count >= config.BREACH_THRESHOLD]
        return {
            "counts": counts,
            "threshold": config.BREACH_THRESHOLD,
            "tripped_endpoints": tripped,
            "checked_at": time.time(),
        }
