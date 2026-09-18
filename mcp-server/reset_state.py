"""Operator-only reset for wiping WAF state between test runs (e.g. after
manual poking around, or between an early test round and an official metrics
run). Deliberately NOT an MCP tool: the tools in server.py represent what the
Sprint 4 defensive agent is allowed to do, and letting the agent erase its
own prior rules would undermine Sprint 5's RGI metric, which depends on old
rules staying in place and generalizing across attack waves. This script is
something a human runs by hand between runs.

Also deletes BreachTracker's persisted state file (config.BREACH_STATE_FILE),
which holds get_breach_status()'s per-endpoint tallies and each log's read
offset - clearing the logs without also clearing this would leave a stale
offset pointing past the now-empty file's end (harmless - BreachTracker
clamps it back to 0, see core/log_parser.py) but also stale, no-longer-true
tallies sitting alongside a freshly emptied log, which is exactly the kind
of drift this script exists to prevent. Deleting it here means logs and
tallies always move together. Still restart the server after running this:
its in-memory copy of the (now-deleted) state won't reload on its own until
the process restarts.

Usage: python reset_state.py
(will prompt for your sudo password - see the note below on why)
"""

import subprocess
from pathlib import Path

import config


def reset() -> None:
    rules_path = Path(config.RULES_FILE)
    rules_path.write_text("")
    print(f"Cleared {rules_path}")

    # The log files are written by the WAF container as root, so they're not
    # writable by this user directly (see waf-defense/docs and the existing
    # manual `sudo truncate` command in docs/common-commands.md). Using
    # `truncate` in place (not delete-and-recreate) matters: nginx holds the
    # file open, so replacing the file rather than truncating it in place
    # would leave nginx writing to the old, now-unlinked file forever.
    for log_path in (Path(config.WAF_ACCESS_LOG), Path(config.WAF_ERROR_LOG)):
        subprocess.run(["sudo", "truncate", "-s", "0", str(log_path)], check=True)
        print(f"Truncated {log_path}")

    state_path = Path(config.BREACH_STATE_FILE)
    if state_path.exists():
        state_path.unlink()
        print(f"Deleted {state_path}")


if __name__ == "__main__":
    reset()
