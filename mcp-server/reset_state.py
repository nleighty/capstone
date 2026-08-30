"""Operator-only reset for wiping WAF state between test runs (e.g. after
manual poking around, or between an early test round and an official metrics
run). Deliberately NOT an MCP tool: the tools in server.py represent what the
Sprint 4 defensive agent is allowed to do, and letting the agent erase its
own prior rules would undermine Sprint 5's RGI metric, which depends on old
rules staying in place and generalizing across attack waves. This script is
something a human runs by hand between runs.

Does not touch the MCP server's in-memory breach tally (get_breach_status())
- that already resets for free the moment the server process restarts, so
just restart the server after running this if a clean tally is also needed.

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


if __name__ == "__main__":
    reset()
