# Debug Notes — Sprint 3

## `core/mutate.py`'s Ollama call could hang indefinitely with no timeout or token cap

**Symptom:** a `run.py --waves 2 --wave-size 24 --pause 5` run (during MCP server integration
testing, not baseline capture) appeared stuck — no wave completed, no error, and `journalctl -u
ollama -f` showed nothing but steady `slot print_timing` lines that didn't look obviously wrong at
a glance.

**Root cause:** `generate_variants()`'s call to `_client.generate(...)` had no `options={"num_predict":
...}` cap and the `ollama.Client` had no request timeout. `llama-server` was also started with
`--context-shift`, so a generation that fails to emit an end-of-sequence token doesn't stop at the
model's context limit — it just keeps shifting the window and generating forever. Diagnosed by
checking `ps aux` (one `llama-server` process pinned at ~680% CPU) and `journalctl -u ollama`,
which showed a single task ID (`task 521`) still active ~24 minutes after being launched, with
`n_gen` past 9,000 tokens — for what should be a JSON array of ~24 short obfuscated strings (a few
hundred tokens at most). It was the very first `generate()` call of the run; the whole run had been
blocked on it from the start.

**Fix:** `mutate.py` now sets `options={"num_predict": 1024}` on every `generate()` call and
constructs `ollama.Client(..., timeout=90)`. A `httpx.TimeoutException` is caught and treated the
same as any other uncooperative model response (empty string, feeding into the existing
retry-once-then-accept-fewer-than-n logic) rather than propagating and crashing the wave loop —
consistent with `generate_variants()`'s existing contract that callers can't assume an exact count
back.

**Why 90s / 1024 tokens specifically:** generous enough to comfortably cover a normal response on
this hardware (RTX 3050 Laptop GPU, ~6.6 tok/s under load) while still turning a runaway generation
into a fast, bounded failure instead of an unbounded hang. Not tuned further than "clearly safe
margin over observed normal-case behavior" since this is a defensive bound, not a performance knob.
