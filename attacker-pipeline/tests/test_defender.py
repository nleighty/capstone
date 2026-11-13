"""Offline tests for harness/defender.run_agent's records. The agent
subprocess is stubbed, so no MCP server/API key is needed. Run from
attacker-pipeline/:  python -m unittest discover -s tests -t .
"""

import json
import unittest
from unittest import mock

from harness import defender


def fake_agent(summary):
    """A subprocess.run stand-in that writes `summary` where agent.py would."""
    def run(cmd, **kwargs):
        with open(cmd[cmd.index("--summary-json") + 1], "w") as f:
            json.dump(summary, f)
    return run


class RunAgent(unittest.TestCase):
    def _run(self, summary):
        with mock.patch.object(defender.time, "sleep"), \
             mock.patch.object(defender.subprocess, "run", side_effect=fake_agent(summary)):
            return defender.run_agent(2, wave_ended_at=100.0)

    def test_nothing_tripped_still_writes_a_row(self):
        records = self._run([])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["verdict"], "nothing tripped")
        self.assertEqual(records[0]["wave_id"], 2)

    def test_mttm_measured_from_wave_end(self):
        records = self._run([{"endpoint": "/rest/user/login", "rule_id": 1000000, "verdict": "PASS",
                              "verify_attempts": 1, "started_at": 103.0, "finished_at": 150.5}])
        self.assertEqual(records[0]["mttm_seconds"], 50.5)


if __name__ == "__main__":
    unittest.main()
