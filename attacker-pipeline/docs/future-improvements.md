# Future Improvements

Small, proposed-but-not-yet-built enhancements for `attacker-pipeline/` — not part of any current
sprint's scope, just tracked here so the ideas don't get lost. Contrast with
`docs/debug-notes-sprint2-log-granularity.md`, which is about *why past decisions were made*; this
file is about *ideas for later*.

## `run.py` CLI

Originally noted as inline comments in `run.py`; moved here so `docs/common-commands.md` can stay a
pure "how to run what already exists" reference rather than mixing in a backlog.

- **`--smoke-test` flag** — one flag that sets the smoke-test values (`--waves 1 --wave-size 5
  --pause 0`) instead of having to remember/retype the exact numbers every time.
- **Print `config.py`'s current defaults without opening the file** — e.g. folded into `--help`,
  so `python run.py --help` shows the actual `WAVE_SIZE`/`NUM_WAVES`/`WAVE_PAUSE_SECONDS` values
  currently in effect, not just the flag descriptions.

## Investigate the question: What causes bypasses/what are the trends/patterns in the payloads behind them?