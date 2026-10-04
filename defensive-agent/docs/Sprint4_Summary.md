# Sprint 4 Summary — Agent Integration & Dry Runs

**Project:** An Adaptive Defense Framework Against GenAI-Driven Web Payload Polymorphism Using MCP
**Sprint Dates:** work completed 2026-09-17, live Docker verification completed 2026-09-18,
POST-body payload visibility gap closed 2026-10-02, `read_current_rule` tool added 2026-10-02
**Student:** Nic Leighty

## Objective

Per the project timeline, Sprint 4's goal was to wire a LangGraph agent to the Sprint 3 MCP tools as
the defensive "brain": decide when `get_breach_status()` indicates a tripped endpoint and what
`write_idempotent_rule()` call to make in response, with structured JSON tool outputs and static
rule IDs for idempotency.

Earlier in this sprint, the defensive side's LLM was changed from the proposal's default
(Ollama/Llama-3, same as the offensive side) to Claude via the Anthropic API — a decision reviewed
with the advisor, recorded in `docs/meeting-notes.md`'s 2026-09-17 entry and `CLAUDE.md`. Rationale:
genuine independence between attacker and defender models (rather than both driven by the same
LLM), and the guardrail concern that ruled out cloud LLMs for the *offensive* side (refusing to
generate exploit payloads) doesn't apply to the *defensive* side (writing WAF rules is ordinary
defensive work). MCP's model/tool decoupling (`docs/design-notes.md`, "Swapping LLMs") meant this
swap required no changes to `mcp-server/`.

## What Was Built

### A small but real extension to `mcp-server/` (Sprint 3 tool surface)

Integrating the agent surfaced a genuine gap: `get_breach_status()` returned bypass *counts* only,
and the only log tool, `read_waf_logs()`, tails the *error* log (requests ModSecurity already
caught) — there was no way to see what actually bypassed, since that lives in the access log, which
no tool exposed. Without this, the agent couldn't do what `CLAUDE.md` says it should ("identifies
the mutation pattern") — it would only ever see requests the WAF already handles.

Fixed by extending `get_breach_status()` to return `sample_bypasses`: a small rolling sample of raw
bypassing request lines, bucketed by **(endpoint, attack family)** — not just endpoint. The
family-bucketing matters because a single wave can bypass one endpoint with more than one attack
family at once (confirmed against real seed data: `/rest/products/search` is targeted by both
`sqli` and `xss` seeds in `attacker-pipeline/payloads/seeds.py`), and a flat per-endpoint cap would
let whichever family bypasses later in the wave silently evict every example of the other family.
The family is read directly off `_wave_marker`'s own value
(`w<wave_id>-<family>-<seed>-<idx>`, e.g. `w3-sqli-05-2`) rather than by inspecting payload content —
deliberately, since this project's premise is that the offensive LLM generates obfuscated,
polymorphic mutations specifically to evade keyword/signature matching, so a content-based
classifier would be exactly the naive detection this project exists to defeat.

Changed: `mcp-server/core/log_parser.py` (`_extract_family`, `_bypass_samples` restructured to
`dict[endpoint][family] -> deque`, persisted the same atomic way as counts/offsets),
`mcp-server/config.py` (`BYPASS_SAMPLE_LIMIT`, default 5, per (endpoint, family) bucket),
`mcp-server/server.py` (docstring update). See `mcp-server/docs/Sprint3_Summary.md`'s Sprint 4
correction note for the pointer back.

### New subproject: `defensive-agent/`

- **`agent.py`** — entrypoint. A single dry-run pass: connect to the MCP server, call
  `get_breach_status()` once, and for each tripped endpoint, look up its stable `rule_id` and hand
  off to the ReAct agent. Exits when done. Deliberately single-pass, not a polling loop — the
  sprint's own name is "Dry Runs" (a human triggers it and watches the transcript); a real poller
  belongs to Sprint 5 alongside the metrics-collection loop it'll need anyway.
- **`core/rule_registry.py`** — `RuleRegistry`, the code-owned source of truth for "static rule
  IDs." `get_or_assign(endpoint)` returns a stable, persisted ID per endpoint, assigned once and
  reused forever. This is what actually makes idempotency real rather than hoped-for: the LLM is
  told the ID as a fixed fact, never asked to invent or remember one across separate runs.
- **`core/graph.py`** — builds a `langgraph.prebuilt.create_react_agent` (Claude, bound to
  `read_current_rule`, `read_waf_logs`, `write_idempotent_rule`, `test_waf_configuration`,
  `reload_waf` — deliberately *not* `get_breach_status`, which stays a deterministic pre-step in
  `agent.py`) and drives one invocation per tripped endpoint, streaming each tool call/result to the
  console.
- **`config.py`** — same `os.environ.get(...)` pattern as the other two subprojects; loads
  `.env` via `python-dotenv` for `ANTHROPIC_API_KEY`.

## Design decisions made this sprint

- **Plain Python loop + `create_react_agent`, not a hand-built outer `StateGraph`.** A dry run's
  control flow is a straight line with one bounded loop (check status once → act on each tripped
  endpoint → exit) — no branching or cycles. A custom `StateGraph` would define a state schema and
  edges purely to express what a `for` loop already expresses, against this project's own
  "no premature abstraction" convention. `create_react_agent` is itself a compiled `StateGraph`, so
  "a LangGraph agent" is satisfied without hand-rolling a tool-calling loop. If Sprint 5 needs real
  polling/scheduling/retry logic, that's the point an outer graph would earn its keep.
- **The rule-ID registry lives entirely in `defensive-agent/`, not `mcp-server/`.** The two
  subprojects deliberately don't share code or state (core/test-harness separation principle,
  `docs/design-notes.md`) — `CUSTOM_RULE_ID_MIN`/`MAX` are duplicated as constants in
  `defensive-agent/config.py` with a comment pointing at `mcp-server/config.py` as the source of
  truth for the range itself.
- **Model: `claude-opus-5`, not Sonnet.** The agent only fires on breach events, not per-request, so
  the cost difference vs. Sonnet is negligible in absolute terms — not worth trading away judgment
  quality (log interpretation, regex design) for it.
- **"Structured JSON outputs" is satisfied by Claude's native tool-use, not a bespoke layer.**
  `write_idempotent_rule`'s MCP schema (`rule_id: int, attack_pattern: str, description: str`) is
  already validated JSON when Claude calls it. The Sprint 4-specific piece is that `rule_id` arrives
  pre-decided from `RuleRegistry` and is stated as a fixed fact in the task prompt — no separate
  parsing/validation step needed.
- **`get_breach_status` is excluded from the ReAct agent's tool set on purpose.** Breach detection
  and rule-ID assignment are deterministic, code-owned steps that run before the LLM is invoked at
  all — keeping them out of the LLM's hands is what makes them reproducible.
- **No shared checkpointer/memory across endpoints or runs.** Each endpoint gets a fresh
  conversation. A dry run has no need for multi-turn memory across endpoints.

## Issues Encountered & Resolved

- **The bypass-visibility gap** (see "What Was Built" above) — found during integration, not
  planned for; fixed in `mcp-server/` as part of this sprint rather than worked around.
- **`langchain_mcp_adapters.client.MultiServerMCPClient` wraps a dict-returning MCP tool's result as
  a list of content blocks** (`[{"type": "text", "text": "<json string>"}]`), not a bare dict or a
  bare JSON string — confirmed by testing against the live server rather than assumed. `agent.py`'s
  `_parse_tool_result()` handles this.
- **Tool names surface through the adapter unprefixed** (`read_waf_logs`, not e.g.
  `waf-defense__read_waf_logs`) — confirmed via `MultiServerMCPClient`'s `tool_name_prefix=False`
  default, matched against the live server's actual tool list.
- **`create_react_agent`'s system-prompt kwarg is `prompt=`** (accepts a plain string), confirmed via
  `inspect.signature` against the installed `langgraph` 1.2.11 rather than assumed from a possibly
  stale recollection of the API.
- **Docker wasn't reachable from the development session used to build this** (WSL 2 distro without
  Docker Desktop's WSL integration active for that session) — this blocked two of the five MCP tools
  end-to-end (`test_waf_configuration`, `reload_waf`, both `docker exec waf ...`) and blocked firing
  a real `attacker-pipeline` wave against a live WAF on port 8080. Resolved 2026-09-18 in a session
  with real Docker access — see "Validation" below.
- **`BreachTracker` silently skipped an entire real wave** (found 2026-09-18): a fresh wave was fired
  before `server.py` was (re)started, and a fresh tracker with no checkpoint starts at *end-of-file*
  by design (so a restart doesn't retroactively count old traffic) — meaning it started scanning
  from the very end of a file that already contained the whole wave, and silently counted nothing.
  Not a code bug - correct by-design behavior for its intended case, but the symptom (`get_breach_status()`
  reporting all-zero) was indistinguishable from "nothing tripped" without digging into file mtimes
  and process start times. Fixed by adding a startup print in `_initial_offset()` (`core/log_parser.py`)
  that names the log's starting offset and current size, with an explicit warning when a fresh start
  lands on a non-empty file. Also restructured `docs/common-commands.md` so the MCP server section
  comes before the attacker-pipeline section (it previously read as license to fire a wave first).
- **For POST-body attacks specifically, neither log tool exposes the actual injected payload** (found
  2026-09-18, live testing against `/rest/user/login`'s sqli seeds): `sample_bypasses` reads the
  access log, which only logs the request line (`_wave_marker` is a query param, visible even on a
  POST) - the actual injected value lives in the JSON body, which nginx's access log never records.
  The error log's `[data ""]` field was also empty for these blocked attempts. This is real for POST
  targets (`/rest/user/login`) but not GET targets (`/rest/products/search`'s sqli/xss ride in the
  query string, which *is* logged).
  - **Fixed 2026-10-02.** ModSecurity's own JSON audit log already captures the actual matched
    request data (e.g. `"Matched Data: ... found within ARGS:json.email: ' OR 1=1--"`) via its
    normal signature matching - it just wasn't being written anywhere readable (defaulted to
    `/dev/stdout`). Redirected it into the existing log bind mount via `MODSEC_AUDIT_LOG` in
    `waf-defense/docker-compose.yml`, switched `MODSEC_AUDIT_ENGINE` to `On` (the default
    `RelevantOnly` only logs 4xx/5xx, which would miss a genuinely successful 200-status bypass),
    and added `_extract_audit_sample()` (`mcp-server/core/log_parser.py`) to fold matched-data
    evidence into the same per-(endpoint, family) `sample_bypasses` buckets - purely additive,
    `bypass_counts` stays sourced from the access log alone. Verified two ways: live, firing a real
    attacker-pipeline wave and confirming a full-CRS-evasion bypass correctly fell back to the bare
    URI (no rule matched, nothing to enrich with); and directly, feeding `_extract_audit_sample()` a
    synthetic entry matching the real confirmed schema with a non-blocked status and real matched
    data, which correctly parsed out `(endpoint, family, sample)` with the actual injected value
    intact. The one combination not yet seen occurring naturally in a wave - a bypass that *also*
    trips a CRS signature below the blocking threshold - is mechanically identical to both verified
    paths, so this is considered proven rather than still-open.
  - **Found alongside this fix**: `reset_state.py` only truncated the access/error logs, never this
    new audit log - so it grew unbounded across resets (15MB within an hour of light testing under
    `MODSEC_AUDIT_ENGINE: On`). Fixed by adding `config.WAF_AUDIT_LOG` to `reset_state.py`'s
    truncation loop.
- **The idempotency mechanism had a blind-overwrite gap** (found 2026-10-02, via a user question
  after a real 2-wave test): `RuleRegistry` guarantees the *same* `rule_id` is reused for a given
  endpoint, and `write_idempotent_rule()` always overwrites that id's line - but nothing let the
  agent see what that line *currently said* before overwriting it. A re-trip on an already-ruled
  endpoint hands the agent only the current `sample_bypasses` window (capped), so a rewrite based
  solely on that evidence could silently narrow an existing rule - dropping coverage for a pattern
  that isn't bypassing *right now* but was previously handled. Fixed by adding a 6th MCP tool,
  `read_current_rule(rule_id)` (`mcp-server/core/rule_writer.py`'s `read_rule()` +
  `mcp-server/server.py`), and updating the agent's system prompt (`core/graph.py`) to call it first
  and treat any existing rule's coverage as a floor to extend, not a draft to discard.

  **Verified live with a controlled canary test (2026-10-02).** Unit-testing `read_rule()` only
  proves the tool returns the right text - it doesn't prove the agent actually *acts* on it rather
  than calling it and discarding the result ("malicious compliance" with step 1 of the prompt). To
  test the real behavior: planted a distinctive, unrealistic pattern (`ZZCANARYZZ`) as the *entire*
  rule content for `/rest/user/login`'s `rule_id`, confirmed it alone blocked (`403`) a request
  carrying it, then re-ran `agent.py` against that endpoint's already-tripped state (evidence
  entirely unrelated to the canary). The agent called `read_current_rule` first, explicitly reasoned
  about whether to keep or drop the canary ("today's capped sample isn't evidence that a pattern is
  safe to stop blocking"), and chose to preserve it - confirmed not just by its own narration but by
  reading the rewritten rule directly: `ZZCANARYZZ` was literally present as the first alternative in
  the new regex, and the `msg` field even self-documented `retains legacy ZZCANARYZZ coverage`.
  Re-fired three checks after the rewrite: the canary still blocked (`403`), the newly-inferred real
  SQLi coverage also blocked (`403`), and a benign login was unaffected (`401`). All three passed.
  Cleaned up afterward by writing the same rule body with just the canary alternative removed,
  re-verified the canary now passes through normally (`401`) while real coverage and benign traffic
  are both unaffected.

## Validation

**What was verified end-to-end, against the real running `mcp-server` and a real Claude API call:**

- `mcp-server`'s family-bucketing extension: unit-tested directly against `BreachTracker` with
  synthetic mixed-family access-log lines, including a restart-persistence check (samples and counts
  both survive a simulated server restart intact).
- Live-server confirmation: started the real `server.py`, pointed at writable scratch log files
  (since the real `waf-defense/logs/` files are container-owned and unwritable without Docker in
  that session) with `RULES_FILE` left pointed at the real
  `waf-defense/modsec-rules/ai_generated_rules.conf`. Injected realistic mixed sqli+xss bypass
  traffic (matching real seed payloads and the real `_wave_marker` format) for
  `/rest/products/search`.
- Ran `defensive-agent/agent.py` for real: it correctly identified the tripped endpoint, received
  both `sqli` and `xss` sample buckets, called `read_waf_logs` for supplementary context, and wrote
  **one rule with a single regex covering both families** using exactly the `rule_id` assigned by
  `RuleRegistry` (never invented its own) — confirmed by reading `ai_generated_rules.conf` directly.
- `test_waf_configuration` failed (no `docker` binary in that session) — the agent correctly
  **refused to call `reload_waf`** after the failed test, retried the test once, then stopped and
  clearly explained why in its final summary, matching the system prompt's ordering rule exactly.
- **Idempotency check**: re-tripped the same endpoint and ran `agent.py` again. `RuleRegistry`
  returned the same `rule_id` (1000000); `ai_generated_rules.conf` still had exactly one line for
  that ID afterward (`grep -c` → 1) — overwritten, not duplicated. This is this sprint's explicitly
  stated deliverable, and it holds.

**Completed 2026-09-18, with real Docker access, a real `attacker-pipeline` wave, and a real WAF:**

- Fired a real wave; `/rest/user/login` (sqli) and `/rest/products/search` (sqli+xss, below
  threshold) both registered correctly in `get_breach_status()` once the offset issue above was
  fixed.
- Ran `agent.py` for real against `/rest/user/login`. It wrote a rule, called
  `test_waf_configuration` (real `docker exec waf nginx -t`, succeeded), and called `reload_waf`
  (real `nginx -s reload`) - all end-to-end, no synthetic substitution.
- Confirmed the rule is genuinely live by firing real requests, not by inspecting config dumps
  (`nginx -T` doesn't reflect ModSecurity's own `Include` chain - a dead end, not a real check):
  a benign wrong-password login still returned `401` (no false positive), and both a generic
  `' OR 1=1--` tautology and the literal `sqli-08` seed payload returned `403`.

**Not yet re-verified end-to-end this round**: the `/rest/products/search` mixed-family case
specifically (below threshold on this run, so it didn't fire) - the mechanism was already proven
against synthetic mixed-family data on 2026-09-17 and there's no reason to expect it behaves
differently live, but it hasn't been watched happen against a real wave yet.

## Status: Sprint 4 Complete

| Deliverable | Status |
|---|---|
| LangGraph agent wired to the 6 MCP tools | ✅ Done, verified live end-to-end |
| Idempotent updates preserve prior rule coverage (`read_current_rule`) | ✅ Added and verified live 2026-10-02 via controlled canary test |
| Structured JSON tool outputs | ✅ Done — native Claude tool-use, no bespoke layer needed |
| Static rule IDs for idempotency | ✅ Done, verified live — same ID reused, no duplicate rule lines |
| Bypass-visibility gap in `get_breach_status()` | ✅ Found and fixed |
| Family-aware bypass sampling | ✅ Done, unit- and live-tested |
| `test_waf_configuration()` / `reload_waf()` against a real WAF container | ✅ Verified live 2026-09-18 |
| Real `attacker-pipeline` wave as the traffic source | ✅ Verified live 2026-09-18 |
| Rule confirmed actually blocking, benign traffic unaffected | ✅ Verified live via direct curl tests |
| POST-body payload visibility for `sample_bypasses` | ✅ Found and fixed 2026-10-02 - see Issues Encountered |

## Next Up (Sprint 5)

Per the timeline: Automated Testing — multi-wave attack loops, MTTM/α/RGI/RFPR metrics collection.
Also worth addressing at that point:
- Whether an outer `StateGraph` is now warranted (this sprint deliberately deferred that).
- Code-enforced test→reload ordering as a backstop, rather than relying solely on the system
  prompt's instructions — fine for a human-watched dry run, a real gap for unattended automation.
- The audit log's disk growth under sustained multi-wave runs (now reset between runs via
  `reset_state.py`, but worth watching once waves run back-to-back for hours rather than minutes).
- The canary test used a single, obvious, distinctive pattern - worth a follow-up with a more
  realistic "competing evidence" scenario (e.g. two genuinely similar but distinct attack variants
  where the merge decision is less clear-cut) to see how the agent's judgment holds up under more
  ambiguity than "an unmistakably synthetic marker vs. real evidence."
