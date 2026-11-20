"""CLI entrypoint. Overrides exist mainly for smoke-testing (e.g.
`--waves 1 --wave-size 5 --pause 0`) without touching config.py's defaults,
which are the real baseline-capture settings.
"""

import argparse

from harness.orchestrator import run

# Potential future: include a `--help` flag that prints the config.py defaults, so a user can see what the baseline-capture settings are without opening the file.

def main():
    parser = argparse.ArgumentParser(description="Fire attack waves at the WAF and record baseline metrics.")
    parser.add_argument("--waves", type=int, default=None, help="Number of waves (default: config.NUM_WAVES)")
    parser.add_argument("--wave-size", type=int, default=None, help="Payloads per wave (default: config.WAVE_SIZE)")
    parser.add_argument("--pause", type=int, default=None, help="Seconds between waves (default: config.WAVE_PAUSE_SECONDS)")
    parser.add_argument("--label", type=str, default=None, help="Tag the output CSV filename (e.g. --label demo) so it's clearly not a baseline-capture run")
    parser.add_argument("--defend", action="store_true",
                        help="Run the defensive agent after every wave (closed loop; MCP server must be running)")
    parser.add_argument("--adaptive", action="store_true",
                        help="Feed each wave's per-seed results (403 vs. not) back into the next "
                             "wave's mutation prompt. Black-box: status codes only, never the WAF's "
                             "rules or logs. Off by default, so the fixed attacker stays comparable")
    args = parser.parse_args()

    run(num_waves=args.waves, wave_size=args.wave_size, pause_seconds=args.pause, label=args.label,
        defend=args.defend, adaptive=args.adaptive)


if __name__ == "__main__":
    main()
