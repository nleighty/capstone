"""Correlates fired requests with the WAF error log by `_wave_marker` value.

Harness-layer: knows about the log file and about "waiting for a match,"
neither of which core.fire needs to know about.

Caveat (see docs/debug-notes-sprint2-log-granularity.md): under the current
CRS anomaly-scoring config, `matched_rule_id` will almost always be the
generic aggregate rule `949110`, not a payload-specific signature ID.
"""

import re
import time
from pathlib import Path

import config

_RULE_ID_RE = re.compile(r'\[id "(\d+)"\]')


class LogReader:
    """Tracks a byte offset into the WAF error log so repeated lookups only
    scan lines appended since the last call, instead of rescanning the whole
    (ever-growing) file per request.
    """

    def __init__(self, log_path: str | None = None):
        # Start at end-of-file: only lines written *after* this reader exists
        # are ever considered, so a wave marker can't accidentally match a
        # stale line from a previous run.
        self.log_path = Path(log_path or config.WAF_ERROR_LOG)
        self._offset = self.log_path.stat().st_size if self.log_path.exists() else 0

    def find_matched_rule(
        self, correlation_id: str, wait_seconds: float = 1.0, poll_interval: float = 0.1
    ) -> str | None:
        """Poll for up to `wait_seconds` for a log line containing
        `correlation_id`, returning its matched ModSecurity rule ID. ModSecurity
        writes the log line asynchronously relative to the HTTP response
        reaching the client, so a single unpolled read can race the write —
        hence the short poll loop rather than one-shot scan.
        """
        deadline = time.monotonic() + wait_seconds
        while True:
            match = self._scan_new_lines(correlation_id)
            if match is not None:
                return match
            if time.monotonic() >= deadline:
                return None
            time.sleep(poll_interval)

    def _scan_new_lines(self, correlation_id: str) -> str | None:
        """Read only the bytes appended since the last call and advance the
        offset regardless of whether a match was found, so lines are never
        scanned twice."""
        if not self.log_path.exists():
            return None

        with self.log_path.open("r", errors="replace") as f:
            f.seek(self._offset)
            new_lines = f.readlines()
            self._offset = f.tell()

        for line in new_lines:
            if correlation_id in line:
                rule_match = _RULE_ID_RE.search(line)
                if rule_match:
                    return rule_match.group(1)
        return None
