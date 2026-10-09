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

## Degenerate mutations counted as "bypasses"

Found 2026-10-09 while verifying Sprint 4.5's body capture: some Llama-3 "variants" are not
attacks at all - e.g. an XSS seed mutated down to the single character `[` (seen as
`/rest/products/search?q=[` and a `/api/Feedbacks` body `{"comment": "["}`). The WAF correctly
lets these through, but `BreachTracker` counts any non-403 wave-marked request as a bypass, so
they inflate bypass counts, can trip the threshold, and hand the defensive agent "evidence" that
would only be matched by a rule that breaks benign traffic. Likely also depresses measured
WAF efficacy and skews alpha (bypass decay) in Sprint 5.

Idea: a validity filter in `core/mutate.py` (or a post-parse step) that drops variants failing a
cheap sanity check - e.g. still contains a SQL keyword / tag / event-handler token, minimum
length, or round-trips through a known-malicious oracle such as a one-off request to an
unprotected Juice Shop. Log how many variants were rejected so mutation quality is measurable.
