# Sprint 4.5 — Inserted Clean-up Sprint (before Sprint 5)

Inserted between Sprint 4 (agent integration) and Sprint 5 (automated multi-wave
testing) to settle loose ends first. Tasks are worked one at a time, in order.

| # | Task | Status |
|---|------|--------|
| 1 | Prompt caching not showing in the Claude Console | ✅ Fixed, verified live + end-to-end |
| 2 | VS Code linting errors | ⏳ |
| 3 | Does the agent verify that a rule actually blocks what it was written for? | 🔄 In progress: A (body capture) done + verified e2e, B (replay verification) next |
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

### Step B - replay verification (next)
A tool that replays the logged bypass requests through the WAF after a rule is written and
reports which still get through, so the agent can revise. Depends on A for POST endpoints.
