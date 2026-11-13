"""Auto-trigger for the defensive agent: the harness-driven option (c) from
docs/sprint-4.6-direction.md #5, built 2026-11-13.

Between waves, the orchestrator calls run_agent(). That starts
defensive-agent/agent.py as a separate process, waits for it to finish, and
reads back its per-endpoint summary. This is what turns a multi-wave run into
a closed loop: wave N fires -> any endpoint past the breach threshold gets a
rule written and verified -> wave N+1 fires against the patched WAF.

Why a subprocess instead of importing the agent:
- The two subprojects deliberately share no code (attacker = test harness,
  defender = the system under test; docs/design-notes.md), and they run in
  separate virtualenvs with different dependencies (Ollama vs. LangChain).
- The harness only sees what the agent reports in its summary file, which keeps
  the measurement independent of the defender's internals.

The harness deliberately does NOT decide which endpoints to fix. agent.py asks
the MCP server (get_breach_status) itself, so the decision lives in the
defensive system, the same way it would if the agent ran on its own schedule.
The MCP server must already be running; this module does not start it.

Timing: each record carries the wave's end time plus the agent's start/finish
time per endpoint, so mttm_seconds = finished_at - wave_ended_at measures
"attack wave over -> rule live and verified". That includes a short log-settle
pause and agent startup, which is fine to state as part of the definition.
"""

import csv
import json
import os
import subprocess
import tempfile
import time

import config

FIELDNAMES = [
    "wave_id",
    "endpoint",
    "rule_id",
    "verdict",
    "verify_attempts",
    "wave_ended_at",
    "started_at",
    "finished_at",
    "mttm_seconds",
]


def run_agent(wave_id: int, wave_ended_at: float) -> list[dict]:
    """Run one defensive pass and return one record per endpoint it handled
    (an empty list if nothing was tripped). Never raises: a crashed or
    timed-out agent is reported as a single error record, so a defender
    failure is visible in the results but doesn't kill the attack run.
    """
    # Give nginx/ModSecurity a moment to flush the wave's last access/audit
    # lines, so the breach check sees the whole wave.
    time.sleep(config.LOG_SETTLE_SECONDS)

    fd, summary_path = tempfile.mkstemp(suffix=".json", prefix="agent_summary_")
    os.close(fd)
    try:
        print(f"--- wave {wave_id}: running defensive agent ---")
        subprocess.run(
            [config.DEFENSIVE_AGENT_PYTHON, "agent.py", "--summary-json", summary_path],
            cwd=config.DEFENSIVE_AGENT_DIR,
            timeout=config.AGENT_TIMEOUT_SECONDS,
            check=True,
        )
        with open(summary_path) as f:
            runs = json.load(f)
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as exc:
        print(f"--- wave {wave_id}: defensive agent failed: {exc} ---")
        now = time.time()
        runs = [{"endpoint": "(agent run)", "rule_id": None, "verdict": f"error: {exc}",
                 "verify_attempts": None, "started_at": now, "finished_at": now}]
    finally:
        os.remove(summary_path)

    records = []
    for run in runs:
        records.append({
            "wave_id": wave_id,
            "endpoint": run.get("endpoint"),
            "rule_id": run.get("rule_id"),
            "verdict": run.get("verdict"),
            "verify_attempts": run.get("verify_attempts"),
            "wave_ended_at": wave_ended_at,
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
            "mttm_seconds": round(run["finished_at"] - wave_ended_at, 1) if run.get("finished_at") else None,
        })
    if not records:
        # Still write a row: "the agent checked and nothing had tripped" is a
        # result too, and without it a wave the agent ran after would leave
        # no trace in the CSV, indistinguishable from the agent never running.
        print(f"--- wave {wave_id}: no endpoint tripped, nothing to defend ---")
        records.append({
            "wave_id": wave_id, "endpoint": "(none tripped)", "rule_id": None,
            "verdict": "nothing tripped", "verify_attempts": 0, "wave_ended_at": wave_ended_at,
            "started_at": None, "finished_at": None, "mttm_seconds": None,
        })
    return records


class AgentRunWriter:
    """CSV of agent runs, written next to the wave metrics CSV
    (run_<id>.csv -> run_<id>_agent.csv) so the two always pair up."""

    def __init__(self, metrics_path: str):
        self.path = metrics_path.removesuffix(".csv") + "_agent.csv"
        self._file = open(self.path, "w", newline="")
        self._writer = csv.DictWriter(self._file, fieldnames=FIELDNAMES)
        self._writer.writeheader()

    def append(self, records: list[dict]) -> None:
        self._writer.writerows(records)
        self._file.flush()

    def close(self) -> None:
        self._file.close()
