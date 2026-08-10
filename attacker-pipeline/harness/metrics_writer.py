"""Sole owner of the metrics CSV schema and file.

Harness-layer: core/fire.py and core/mutate.py never import this module or
touch a CSV directly — keeps metric-gathering decoupled from the attack code
per docs/design-notes.md's layer split.
"""

import csv
import os
from datetime import datetime

import config

FIELDNAMES = [
    "wave_id",
    "payload_id",
    "attack_type",
    "seed_payload",
    "mutated_payload",
    "endpoint",
    "status_code",
    "blocked",
    "matched_rule_id",
    "timestamp",
]


class MetricsWriter:
    """One CSV per run (`run_<timestamp>.csv`), not one perpetually-appended
    file — keeps separate baseline-capture attempts from silently mixing
    together when a later sprint analyzes the data.

    `label`, if given, prefixes the filename (`run_<label>_<timestamp>.csv`)
    — e.g. "demo" for a rehearsal/advisor-demo run — so it's visually and
    filterably distinct from unlabeled runs, which are the real baseline
    captures meant to feed the thesis's metrics.
    """

    def __init__(self, run_id: str | None = None, label: str | None = None):
        os.makedirs(config.METRICS_DIR, exist_ok=True)
        if run_id is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_id = f"{label}_{timestamp}" if label else timestamp
        self.path = os.path.join(config.METRICS_DIR, f"run_{run_id}.csv")
        self._file = open(self.path, "w", newline="")
        self._writer = csv.DictWriter(self._file, fieldnames=FIELDNAMES)
        self._writer.writeheader()

    def append_row(
        self,
        wave_id: int,
        payload_id: str,
        attack_type: str,
        seed_payload: str,
        mutated_payload: str,
        endpoint: str,
        status_code: int,
        matched_rule_id: str | None,
        timestamp: str,
    ) -> None:
        """Write one fired-payload result as a CSV row. `blocked` is derived
        from `status_code` here (not passed in) so it's always consistent
        with the raw code — the caller can't drift the two apart.
        """
        self._writer.writerow(
            {
                "wave_id": wave_id,
                "payload_id": payload_id,
                "attack_type": attack_type,
                "seed_payload": seed_payload,
                "mutated_payload": mutated_payload,
                "endpoint": endpoint,
                "status_code": status_code,
                "blocked": status_code == 403,
                "matched_rule_id": matched_rule_id or "",
                "timestamp": timestamp,
            }
        )
        # Flush per row (not just at close()) so a mid-run crash or Ctrl-C
        # during a long baseline capture still leaves a readable partial CSV.
        self._file.flush()

    def close(self) -> None:
        self._file.close()
