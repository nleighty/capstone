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

## ✅ Investigate: what causes bypasses / what are the trends in the payloads behind them? — ADDRESSED (Sprint 4.6, 2026-10-15)

Built `analyze.py` + `harness/bypass_analysis.py`: offline analysis over the metrics CSVs that
reports per-family/endpoint bypass rate and, per obfuscation technique, how much more common it
is among bypasses than blocks ("lift"). Tests in `tests/test_bypass_analysis.py`.

Headline finding on the baseline CSV (250 payloads, 33.6% bypass): bypasses are concentrated in
SQLi tautologies against the login JSON body (60% bypass) while encoded XSS in the query string is
almost fully blocked (1.5%). Counterintuitively, "sophisticated" encodings (mixed-case, HTML
entity, hex/unicode) correlate with being *blocked* (negative lift) - CRS handles them well - while
short, simple tautologies with inline comments slip through. So "stronger attacks" (the Sprint 4.6
#1 goal) means smarter *logic-level* evasion, not more encoding. See
`../../docs/sprint-4.6-direction.md` §1 for the full write-up.

## ✅ Degenerate mutations counted as "bypasses" — DONE (Sprint 4.5, 2026-10-11)

Found 2026-10-09 while verifying Sprint 4.5's body capture: some Llama-3 "variants" are not
attacks at all - e.g. an XSS seed mutated down to the single character `[` (seen as
`/rest/products/search?q=[` and a `/api/Feedbacks` body `{"comment": "["}`). The WAF correctly
lets these through, but `BreachTracker` counts any non-403 wave-marked request as a bypass, so
they inflate bypass counts, can trip the threshold, and hand the defensive agent "evidence" that
would only be matched by a rule that breaks benign traffic. Likely also depresses measured
WAF efficacy and skews alpha (bypass decay) in Sprint 5.

**Fixed:** `core/mutate.py` now runs a validity filter (`_is_valid_variant`) as a post-parse,
post-dedup step in `generate_variants`. A variant is dropped if it is shorter than
`config.MIN_VARIANT_LENGTH` (default 4) or carries no attack signal for its family (broad
literal-or-encoded token lists, so URL/hex-encoded mutations still pass). Rejected variants are
counted and printed per seed so mutation quality stays observable. Verified against the existing
metrics CSVs: drops the 15 true-junk rows (lone `[`/`]`) and keeps every genuinely obfuscated
variant. The deliberately-broad lists reject *non-attacks*, they do not grade attack quality.
Regression tests in `attacker-pipeline/tests/test_mutate_filter.py`. The "oracle round-trip"
idea from the original note was not needed — a token/length check was enough and adds no network
dependency to the wave loop.
