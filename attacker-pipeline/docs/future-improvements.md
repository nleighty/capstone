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

## Balanced seed coverage + guaranteed wave size (planned fix, found 2026-11-12, Step 3 review)

Nic wants this fixed before the Sprint 5 evaluation runs, to cut down on variables.

**Problem 1: uneven seed coverage.** `harness/orchestrator.py:build_wave` asks for
`ceil(WAVE_SIZE / len(SEEDS))` variants per seed, flattens them **in seed order**, and keeps the
first `WAVE_SIZE`. Two things make the last seeds lose out: the list has all 8 SQLi seeds first, and
`generate_variants` often returns *more* than requested (it never trims back down to `n`; the
baseline has indexes up to 7 when 4 were asked for). Result in `run_baseline_20260809_140007.csv`:
the 8 SQLi seeds got 15–26 rows each, `xss-05` got 2, and `xss-06`/`07`/`08` got **0**. Only one
XSS seed (`xss-04`) ever reached `/api/Feedbacks`. The `build_wave` docstring's "roughly even
coverage" claim is wrong for the same reason.

**Problem 2: wave size isn't guaranteed.** `generate_variants` can also return *fewer* than `n`
(the junk filter drops output, there's only one retry, and a timeout returns nothing). If too many seeds
come up short, the wave has fewer than `WAVE_SIZE` payloads, and the docstring's "never short"
claim doesn't hold. Every baseline wave happened to be 50, but α compares waves, so the size should be fixed.

**Proposed fix (not built):**
- Trim each seed's variants to `variants_per_seed` and take them **round-robin across seeds**
  (seed 1 variant 1, seed 2 variant 1, ...), so cutting to `WAVE_SIZE` drops evenly instead of
  dropping whole seeds at the end of the list. Shuffling the seed order each wave also works.
- **Top-up loop:** after the first pass, while the wave is short, ask Ollama for more variants from
  the seeds that came up short, so junk is *replaced* instead of just dropped. This needs a
  hard cap on extra calls, since a broken model must not hang the run. If it's still short after the cap,
  log it and record the actual size, rather than failing silently.
- Rewrite the `build_wave` docstring to match.

## Attacker doesn't learn from results (found 2026-11-12, Step 3 review)

The attacker is open-loop. Every wave sends the same 16 seeds and the same prompt to Llama, and
nothing about which variants got through or were blocked goes back in. Variation between waves is just
sampling noise. The advisor's "you get better, I get better" direction (`docs/meeting-notes.md`,
2026-10-30) needs a feedback path, e.g.:
- Seed the next wave's prompt with the previous wave's bypasses ("make more like these").
- Weight seeds toward the families/endpoints that are currently bypassing.
- Feed `analyze.py`'s lift results back in (techniques with positive lift get used more).

This changes what α measures: a learning attacker against a learning defender, instead of a fixed
attacker distribution against a learning defender. So it's a design decision to make with the advisor,
not just a code change.

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
