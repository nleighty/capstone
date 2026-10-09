# Sprint 4.5 — Inserted Clean-up Sprint (before Sprint 5)

Inserted between Sprint 4 (agent integration) and Sprint 5 (automated multi-wave
testing) to settle loose ends first. Tasks are worked one at a time, in order.

| # | Task | Status |
|---|------|--------|
| 1 | Prompt caching not showing in the Claude Console | ✅ Fixed, verified live + end-to-end |
| 2 | VS Code linting errors | ⏳ |
| 3 | Does the agent verify that a rule actually blocks what it was written for? | ✅ Done - verified live incl. FAIL->revise->PASS (see "Second agent run"). Fit check only, by design |
| 4 | (If time) Auto-trigger the agent after a wave? | ⏳ |

---

## 1. Prompt caching

**Symptom:** Console showed no cache activity, though caching was believed configured.

**Root cause:** It was never configured. `core/graph.py` built a bare
`ChatAnthropic(model=...)` with a plain-string system prompt and no `cache_control`
anywhere. Anthropic's prompt caching is opt-in — nothing is cached unless a request
carries a `cache_control` marker. (Sprint 4 only mentions "cached" in the sense of
bypass-sample caching, unrelated.)

**Fix (`core/graph.py`, `build_agent`):**
- Explicit `cache_control` on the system prompt block. Render order is
  tools → system → messages, so this one breakpoint caches the 5 tool definitions *and*
  the system prompt (~1,050 tokens; the minimum cacheable prefix on Opus 5 is 512).
- Top-level automatic `cache_control` via `ChatAnthropic(model_kwargs=...)`, which moves a
  breakpoint to the end of the conversation each turn so the read → write → test → reload
  loop re-reads its own history.
- Default 5-minute TTL: turns are seconds apart, and endpoints in a dry run minutes apart.
  A 1-hour TTL (2× write cost) only pays off for gaps of 5–60 min.
- `run_for_endpoint` now prints a per-endpoint token/cache summary
  (`_print_cache_usage`), so cache effectiveness is visible in the transcript without the
  Console.

**Verified live** (two identical calls, real system prompt): call 1 wrote 1,054 tokens to
the 5m cache; call 2 read 1,054 of 1,056 input tokens from cache.

**Verified end-to-end** (2026-10-08, full `agent.py` pass against live MCP server + WAF,
`/rest/user/login`, extending existing rule 1000000): 6 model calls, input=95,234 tokens of
which cache_read=71,612 (75%), cache_write=23,610, uncached=12; output=4,426. At Opus 5
list prices (cache read 0.1x, write 1.25x) that is roughly $0.30 vs ~$0.59 uncached, about
half. Every call after the first read the growing prefix from cache; large `read_waf_logs`
results are the bulk of the written tokens.

**Side finding for task 3:** the agent's run exposed that `test_waf_configuration` only checks
nginx config syntax ("OK"), and the bypass samples it was given contained only the
`_wave_marker` tag, not the real payload (POST body not logged). The agent said so itself and
wrote the rule from inference. Nothing in the loop confirms the rule blocks anything.

**Gotchas worth remembering:**
- `langchain-anthropic` 1.7.2 reports cache *writes* under
  `input_token_details.ephemeral_5m_input_tokens` and leaves `cache_creation` at 0. Code
  reading only `cache_creation` will wrongly conclude nothing was written.
- `input_tokens` in langchain's `usage_metadata` is the *total* prompt; cache reads/writes
  are subsets of it (uncached = input − read − write).
- Realistic savings are modest: the agent runs only on breach events, and a cold dry run
  still pays the write premium (1.25×) on first contact. The win is on the multi-turn loop
  within an endpoint and on back-to-back endpoints/runs inside 5 minutes. This matters more
  in Sprint 5 when multi-wave loops invoke the agent repeatedly.
- Caches are per-workspace; if the Console's workspace filter differs from the API key's
  workspace, activity can appear missing.

---

## 3. Does the agent test its rules?

**Answer (before this work): no.** Two gaps, found by tracing a real run:

1. `test_waf_configuration` is `nginx -t` - syntax only. Nothing replays an attack to see
   whether the new rule blocks it.
2. For POST endpoints the agent never saw the payloads. nginx's access log has no body field,
   the error log's `[data ""]` is empty for body attacks, and the ModSecurity JSON audit log
   (`modsec_audit.log`) omitted the request body because the image's default
   `SecAuditLogParts` (`ABIJDEFHZ`) lacks part **C** (in libmodsecurity3, C is the request
   body). A payload that evades every CRS rule also has no `messages[]`, so no "Matched Data"
   either - evasion itself was what hid it. E.g. every `/rest/user/login` sample was a bare
   `/rest/user/login?_wave_marker=...`; the agent wrote its rule by analogy from GET
   payloads on `/rest/products/search` (query string visible in the access log).

### Step A - capture request bodies (done)
- `waf-defense/docker-compose.yml`: `MODSEC_AUDIT_LOG_PARTS: "ABCDEFHIJZ"` (adds C). Verified
  with a real POST: the audit JSON now has `request.body`. Testbed-only caveat: this logs
  credentials from login bodies; production would redact or scope to flagged requests.
- `mcp-server/core/log_parser.py`: audit samples now include `body: <raw body>` (capped at
  `config.BYPASS_BODY_MAX_CHARS`, default 500, since samples go to the LLM verbatim).
- Dedupe by `_wave_marker`: the access log and audit log both describe the same request, and
  with a 5-slot buffer a useless bare-URI access line was occupying a slot the body-bearing
  audit sample needed. `BreachTracker._add_sample` keeps one sample per request; an audit
  sample replaces an access-log one, never the reverse. Marker compared exactly (not by
  substring - `...-02-3` is a substring of `...-02-30`).
- Tested offline against temp logs (counts unchanged, 403s ignored, body cap, dedupe in both
  arrival orders).
- **Verified end-to-end (2026-10-09)** via demo_client after restart + fresh wave: every
  `/rest/user/login` sample now reads like
  `...?_wave_marker=w1-sqli-08-1 - body: {"email": " or 1=1;--", "password": "x"}`.

**Findings from that verification output:**
- *Degenerate mutations count as bypasses.* An XSS variant mutated to the single character `[`
  appears as a "bypass" on `/rest/products/search` and `/api/Feedbacks`. Not an attack, so
  any rule written to block it would hit benign traffic. Logged in
  `attacker-pipeline/docs/future-improvements.md`; it also constrains Step B (a replay check
  must not push the agent toward blocking `[`, so it needs a benign-traffic guard too).
- *Low sample diversity.* The 5 login samples are all from seed `sqli-08` (a rolling
  last-5 buffer), so a rule is written from one mutation family while others may exist.
- Login payloads like `" or 1=1;--"` have no leading quote - exactly what the previous
  rule's quote-anchored tautology branch missed.

### Step B0 - sample diversity (done; prerequisite for B)
Question raised after the step A output: is a last-5 rolling buffer OK? No - it showed the
agent 5 samples from one seed (`sqli-08`) out of 17 login bypasses, and across Sprint 5's
multi-wave runs later waves would evict every earlier one. Changes:
- `mcp-server/config.py`: `BYPASS_SAMPLE_LIMIT` 5 -> 20 (per endpoint+family bucket), new
  `BYPASS_SAMPLES_PER_SEED` = 2. 20 samples is a few thousand prompt tokens, negligible next
  to `read_waf_logs` output and mostly cache-read.
- `mcp-server/core/log_parser.py`: samples are now structured records
  (`text, marker, seed, method, uri, body, content_type`); agent-facing `sample_bypasses`
  is unchanged (list of text). Seed read off the marker (`w1-sqli-08-3` -> `sqli-08`), like
  family, never off payload content. `_add_sample`: max 2 per seed (newest kept); past the
  bucket limit, evict the oldest sample of whichever seed currently has the most. Full body
  stored for replay (the `text` copy is still capped at 500 chars - a truncated JSON body
  would replay as a different request). Old state files with bare-string samples still load.
- `defensive-agent/core/graph.py` + `agent.py`: the task prompt now states "N bypasses
  recorded; the M below are a representative subset ... generalize", so the model knows the
  samples are partial.
- Tested offline (flooding seed capped at 2 with rare seeds kept; 30 seeds -> 20 samples from
  20 distinct seeds; POST access-line upgraded by audit body; legacy state loads). Not yet
  run live - needs a server restart + fresh wave.

**B0 verified live (2026-10-09):** 11 login bypasses -> 7 samples across seeds 01/02/03/08 and
both waves (previously 5 from one seed).

### Step B - replay verification (built; agent run pending)
New MCP tool `verify_rule(endpoint)` (`mcp-server/core/rule_verifier.py`), called after
`reload_waf`. It sends two things through the live WAF and returns a structured report with a
PASS/FAIL verdict:
1. **Attack replay** - the structured bypass samples recorded for that endpoint
   (`BreachTracker.samples_for`), re-sent with method, URI, full body and content-type.
   `still_bypassing` lists gaps.
2. **Benign guard** - a small fixed per-endpoint set of ordinary requests that superficially
   resemble attacks (apostrophe in an email, "select"/"or" as plain English, a lone `[`).
   `falsely_blocked` lists over-blocking. Needed because "block everything that bypassed" would
   have the agent blocking the degenerate `[` mutation.

Design decisions:
- **Not a generic send-request tool**: the agent supplies only an endpoint; it can't make the
  server fire arbitrary traffic. Replays come solely from what the server itself logged.
- **Replays carry `_replay=1` and have `_wave_marker` stripped**, so neither BreachTracker nor
  the attacker harness's LogReader (both correlate on the marker) counts them as new attacks.
  The error log has no marker check (it counts every "Access denied"), so
  `_extract_blocked_endpoint` now skips lines containing `_replay=1`.
- **2s settle after reload** (`VERIFY_SETTLE_SECONDS`): `nginx -s reload` returns once signalled;
  new workers load rules asynchronously, so an immediate replay can hit an old worker.
- **Neutral User-Agent** and stdlib `urllib` (no new dependency; `httpx` isn't in the server
  venv).
- **A fit check, not a generalization check**: replayed requests are the same ones the agent
  saw, so PASS means "covers its evidence". Unseen-variant generality is what the harness's
  RGI measures in Sprint 5, and the harness's own 50-100-request RFPR set (design-notes.md)
  stays separate from this 9-request defender-side set so the final metric isn't graded by the
  set the agent iterated against.
- Agent prompt: new steps 7-8 - revise on FAIL up to 3 verify attempts; favor not blocking
  benign traffic when attack/benign conflict; don't write rules to block non-attacks; report
  the final verdict honestly.

Tested standalone against the live WAF with the real saved samples and an empty rules file:
all 7 login bypasses reproduced their original outcomes (401s, one 500) -> `FAIL: 7 recorded
bypass(es) still get through`; a synthetic CRS-blocked payload counted as `now_blocked`; all 9
benign requests (3 endpoints) passed. **Not yet exercised through the agent.**

Observation: 6 of those 7 replayed bypasses return 401 (login failed), not a SQL error - the
WAF missed them but the injection didn't actually work against Juice Shop. "Bypass" means "the
WAF didn't block it" by design (docs/design-notes.md), so this is expected, but worth keeping in
mind when interpreting alpha in Sprint 5.
A tool that replays the logged bypass requests through the WAF after a rule is written and
reports which still get through, so the agent can revise. Depends on A for POST endpoints.

### First agent run with `verify_rule` (2026-10-09) and what it exposed
Transcript: read_current_rule -> read_waf_logs -> write -> test -> reload -> `verify_rule` ->
**PASS on the first attempt** (7/7 recorded login bypasses now blocked, 3/3 benign ok; the same
7 were all `still_bypassing` against an empty rules file earlier, so the rule - not CRS - is
what changed the outcome). Usage: 6 calls, input=117,643 (cache_read=93,907 = 80%),
output=3,558. The agent's summary correctly stated that PASS covers its evidence only.

**But the PASS was incomplete - a real false-positive bug the guard missed.** The generated
`SecRule` matches `REQUEST_COOKIES|ARGS` with *no URL condition*, so a rule written for
`/rest/user/login` is live on every endpoint. `verify_rule` only sent the tripped endpoint's
benign requests. Probing the live rule by hand showed it (`[id "1000000"]` in the error log)
returning 403 for ordinary `/api/Feedbacks` comments like `Fast delivery, great 'service';
would buy again` and `Loved the 'juice' #1 shop`, and search `q='apple'; juice`: its
"quote followed by `;`/`#`/`--`" branch fires on normal prose punctuation.
Fixes made:
- `rule_verifier.verify` now sends the benign set for **all** endpoints regardless of which
  one tripped, and the corpus gained quote-then-punctuation cases for feedback and search
  (12 benign requests total). Re-checked against the same live rule: now
  `FAIL: 3 benign request(s) are now blocked`, as it should be.
- `read_waf_logs` now filters out `_replay=1` lines (before taking the last N). Observed in
  this run: the agent's log read included a line from a manual test replay, i.e. it would
  otherwise read its own verification traffic back as attack evidence.

**Open decision (not yet made): rule scoping.** Rules are global, but the agent prompt and
rule-ID scheme treat them as per-endpoint ("a single rule_id covers the whole endpoint"). Options:
(a) keep global and rely on the all-endpoint benign guard (current); (b) scope each rule to
its endpoint with a chained `REQUEST_URI` condition - needs `write_idempotent_rule` to take an
endpoint and `rule_writer`'s one-line-per-rule overwrite to handle chains. (b) limits blast
radius but would stop a login rule from protecting search against the same SQLi; interacts
with RGI in Sprint 5.

**Not yet exercised:** the agent's behaviour on a FAIL verdict (revise loop). Re-running the
agent now is a natural test: rule 1000000 exists, `verify_rule` will fail it on the benign
guard.

**Cost note:** `read_waf_logs` returned 50 raw CRS lines (~29k chars, ~8k tokens) of near-identical
boilerplate (`Inbound Anomaly Score Exceeded`, empty `[data ""]`). Correction to an earlier
estimate: `input_tokens` is summed over all 6 calls (each resends the history), so the logs were
not "20k of 117k" - they are written to cache once (~8k at 1.25x) and re-read on later turns
(~0.1x), roughly 20% of the run's ~$0.28.

### Decisions (2026-10-09)
1. **Rule scoping: keep rules global**, backed by the all-endpoint benign guard. Revisit in
   Sprint 5 if RGI results suggest per-endpoint scoping would be cleaner.
2. **Trim `read_waf_logs`**: default output is now one compact line per block (time, status,
   rule id, msg, matched data if any, request line) via `log_parser.compact_error_line`
   - ~24% of the raw size on the real log. `raw=True` returns the unabridged lines (demo
   client / debugging). Non-ModSecurity lines pass through unchanged. The tracker reads the
   log files directly and is unaffected.

### To re-test after these changes
Restart `server.py` (picks up: all-endpoint benign guard, `_replay=1` log filter, compact
logs), then `python3 agent.py` against the existing rule 1000000. Expected: `verify_rule`
FAILs on the 3 benign false positives, the agent narrows the quote-adjacency branches, and a
second verify passes. Watch for: does it revise rather than declare victory; does it stay
within 3 verify attempts; does the final rule still block the 7 recorded bypasses.

### Second agent run (2026-10-09): FAIL -> revise -> PASS
Existing rule 1000000 (from the first run) + the all-endpoint benign guard + compact logs:
1. Agent read the rule and compact log (40 lines), wrote a broadened rule (added `AND`,
   quoted-string tautology, more encodings) that kept every old branch.
2. `test_waf_configuration` **FAILED** (config parse error) - see msg bug below. Agent shortened the
   description and retried: OK -> reload.
3. `verify_rule`: 7/7 attacks blocked but **FAIL: 3 benign blocked** (exactly the three predicted
   false positives). Agent narrowed the quote-adjacent branch (quote + `;` only when followed by
   a comment or SQL keyword; bare `#` only at end of value), re-wrote, re-tested, reloaded.
4. `verify_rule`: **PASS** (7/7 blocked, 0/12 benign). Final summary stated the trade-off
   (coverage slightly reduced vs the original blanket branch, favoring benign traffic) and the
   fit-not-generalization caveat.
Usage: 12 model calls, input=159,475 (cache_read=142,432 = 89%, write 17,019), output=7,229,
about $0.36. The revise loop works and stayed inside the 3-attempt limit.

**Bug found and fixed: `%` in a rule's `msg` breaks the whole config.** The agent guessed
"punctuation"; bisecting against the live `nginx -t` (rules file backed up and restored) showed
only `%` fails (ModSecurity expands `%...` macros in `msg`): `%20`, `%2F`, even "100%". Commas,
parens, `#`, `--`, `;` are fine. An agent describing URL-encoding evasions will write `%27`
constantly, so this was a latent landmine that it happened to recover from. `rule_writer.write_rule`
now rewrites `%` as `percent-` and collapses whitespace/newlines (a newline would break the
one-line-per-rule format). Verified with `nginx -t` on three previously-fatal descriptions.

**Caveats on what the PASS means:**
- *Unseen-variant check is uninformative so far.* 12 standard SQLi forms not in the samples were
  all blocked, but 11 of 12 by CRS rule 949110, not rule 1000000. Custom rules load from
  `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf`, i.e. after CRS's blocking evaluation, so a
  request CRS already denies never reaches the custom rule: "blocked by CRS" says nothing about
  whether 1000000 would also have caught it. Textbook SQLi was never the problem; real
  generalization (RGI) needs unseen *polymorphic* variants that evade CRS - Sprint 5's job.
- *The benign set is no longer independent for 3 cases.* The quote-then-punctuation cases were
  added after seeing the first rule fail them, and the agent then iterated against them. Fine
  as a safety net; Sprint 5's RFPR must use a fresh, harness-owned set.
- Replays do not leak into the tracker (blocked/bypass counts identical before/after).
