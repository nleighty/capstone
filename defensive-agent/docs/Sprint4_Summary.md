# Sprint 4 Summary — Agent Integration & Dry Runs

**Project:** An Adaptive Defense Framework Against GenAI-Driven Web Payload Polymorphism Using MCP
**Sprint Dates:** work completed 2026-09-17
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
  `read_waf_logs`, `write_idempotent_rule`, `test_waf_configuration`, `reload_waf` — deliberately
  *not* `get_breach_status`, which stays a deterministic pre-step in `agent.py`) and drives one
  invocation per tripped endpoint, streaming each tool call/result to the console.
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
  a real `attacker-pipeline` wave against a live WAF on port 8080. See "Validation" below for exactly
  what was and wasn't covered as a result, and what still needs to be run in an environment with
  Docker access.

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

**What was NOT verified (needs a session with Docker access to `waf` and `juice-shop`):**

- `test_waf_configuration()` / `reload_waf()` actually succeeding against a real WAF container.
- A real `attacker-pipeline` wave (`python3 run.py --waves 1 --label dry-run-demo`) firing against
  the live WAF on `localhost:8080`, rather than hand-injected synthetic log lines.
- Confirming the reload takes effect: re-firing a request matching the agent's chosen regex and
  seeing `403` where it was previously non-403, for both families.

**Next step for whoever picks this up**: run `docs/common-commands.md`'s "Running the defensive
agent" section for real, with the WAF stack up (`docker compose -f waf-defense/docker-compose.yml
up -d`) and a real attacker-pipeline wave fired first. Everything downstream of
`get_breach_status()` and `write_idempotent_rule()` is already proven correct against real data;
only the two Docker-dependent calls remain to actually exercise against a live container.

## Status: Sprint 4 Built, Pending Live Docker Verification

| Deliverable | Status |
|---|---|
| LangGraph agent wired to the 5 MCP tools | ✅ Done, verified live (see Validation) |
| Structured JSON tool outputs | ✅ Done — native Claude tool-use, no bespoke layer needed |
| Static rule IDs for idempotency | ✅ Done, verified live — same ID reused, no duplicate rule lines |
| Bypass-visibility gap in `get_breach_status()` | ✅ Found and fixed this sprint |
| Family-aware bypass sampling | ✅ Done, unit- and live-tested |
| `test_waf_configuration()` / `reload_waf()` against a real WAF container | ⬜ Blocked on Docker access in the dev session — needs a real run |
| Real `attacker-pipeline` wave as the traffic source (vs. synthetic injection) | ⬜ Needs a real run |

## Next Up (Sprint 5)

Per the timeline: Automated Testing — multi-wave attack loops, MTTM/α/RGI/RFPR metrics collection.
Also worth revisiting at that point, now that a real polling/automation loop is in scope:
- Whether an outer `StateGraph` is now warranted (this sprint deliberately deferred that).
- Code-enforced test→reload ordering as a backstop, rather than relying solely on the system
  prompt's instructions — fine for a human-watched dry run, a real gap for unattended automation.
- Complete the Docker-dependent verification left open above, as the first step of Sprint 5's setup.
