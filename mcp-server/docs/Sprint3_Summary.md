# Sprint 3 Summary — MCP Server & Defenses

**Project:** An Adaptive Defense Framework Against GenAI-Driven Web Payload Polymorphism Using MCP
**Sprint Dates:** work completed 2026-08-30
**Student:** Nic Leighty

## Objective

Per the project timeline, Sprint 3's goal was to build the production-side MCP server the future
Sprint 4 defensive agent will call: expose `read_waf_logs()`, `test_waf_configuration()`,
`write_idempotent_rule()`, `reload_waf()` as MCP tools, plus per-endpoint breach-threshold
tracking. This sprint builds the mechanism only — nothing here decides *when* to write a rule or
*what* it should say; that's Sprint 4's job.

## What Was Built

A new sibling subproject, `mcp-server/`, built with the official `mcp` Python SDK (`pip install
mcp`, resolved to v2.1.1 — note its `FastMCP` class was renamed to `MCPServer` in the v2 API;
`docs/design-notes.md`'s sketch used the older v1 name):

- **`server.py`** — the `MCPServer` app and five `@app.tool()`-decorated functions, run over
  streamable-HTTP (`localhost:8000/mcp`) rather than stdio, so the server exists as a standalone
  always-on local service (matching the WAF/Ollama pattern already used elsewhere in the project)
  testable on its own, independent of any agent.
  - `read_waf_logs(lines)` — tails the raw error log.
  - `get_breach_status(endpoint=None)` — the new "tripwire" tool: per-endpoint breach counts
    (query string stripped) plus which endpoints have crossed `config.BREACH_THRESHOLD` (default
    5). Not one of the proposal's original four named tools, but called out separately in the
    Sprint 3 timeline bullet ("threshold tracking") as its own deliverable.
  - `test_waf_configuration()` / `reload_waf()` — `docker exec waf nginx -t` / `nginx -s reload`.
  - `write_idempotent_rule(rule_id, attack_pattern, description)` — the Scoped Inclusion pattern
    from `docs/design-notes.md`: overwrites the line for an existing `rule_id`, appends if new.
- **`core/log_parser.py`** — `BreachTracker`, using the same incremental-offset log-scanning
  technique as `attacker-pipeline/harness/log_reader.py`'s `LogReader` (reimplemented rather than
  imported, since this is core/production code and that module is the test-harness layer).
- **`core/rule_writer.py`** — builds and idempotently writes the `SecRule` line; validates
  `rule_id` falls in the reserved 900000-999999 custom range.
- **`core/waf_control.py`** — thin `docker exec` wrappers, confirmed against the real container
  before being wired in.
- **`reset_state.py`** — operator-only script (deliberately *not* an MCP tool - see "Design
  decisions" below) that clears `ai_generated_rules.conf` and truncates the WAF log files, for
  resetting between test runs.

## Design decisions made this sprint

- **MCP framework:** official `mcp` SDK (`MCPServer`/`FastMCP`-style decorators), not the
  third-party `fastapi-mcp` package that wraps an existing REST app — there's no separate REST
  layer here, matching `docs/design-notes.md`'s sketch almost exactly (module rename aside).
- **Transport:** streamable-HTTP, standalone service. Reasoning and the option to revisit for
  Sprint 4 if a stdio-launched-subprocess model turns out to fit the LangGraph agent better is
  recorded in this sprint's plan discussion; not expected to require touching the tool logic
  either way.
- **Threshold tracking is per-endpoint**, not the design-notes' global-count MVP fallback — grouped
  by URL path with the query string stripped, per `docs/design-notes.md`'s own suggested approach.
- **Reset is a separate script, not a 6th MCP tool.** The MCP toolset represents what the Sprint 4
  defensive agent is allowed to do; giving the agent a tool that can erase its own prior rules
  would undermine Sprint 5's RGI metric, which depends on old rules staying in place and
  generalizing across attack waves. Resetting between test runs is an operator action.

## Issues Encountered & Resolved

- **`docs/design-notes.md`'s rule template referenced a ModSecurity variable that doesn't exist**
  (`REQUEST_PARAMETERS` instead of `ARGS`) — caught immediately by `test_waf_configuration()`
  rejecting the generated rule, confirmed against the real CRS ruleset shipped in the container,
  and fixed in `core/rule_writer.py`. See `docs/debug-notes-sprint3-rule-syntax.md`.
- **`nginx -s reload` has a brief (sub-second) propagation delay** before new rules actually take
  effect — not a bug, but worth knowing for Sprint 4/5's verification and MTTM timing. See the same
  debug notes file.
- **Log files are container-written (owned by the container's user, not the host user)** — same
  constraint `docs/common-commands.md`'s existing manual truncate command already works around via
  `sudo`; `reset_state.py` shells out to the same `sudo truncate` rather than trying to
  delete-and-recreate the files (which would silently break logging, since nginx holds the old
  file open and a replaced file wouldn't receive further writes).

## Validation

- Confirmed `docker exec waf nginx -t` / `nginx -s reload` work directly against the real
  container before wiring them into `waf_control.py`.
- Started the server, confirmed it listens on `127.0.0.1:8000/mcp`.
- Fired known-blocked payloads against two different endpoints (`/rest/products/search`,
  `/rest/user/login`) and used a small MCP client script to call all five tools, confirming:
  - `read_waf_logs()` returns the fresh lines.
  - `get_breach_status()` correctly grouped counts per endpoint (1 each) with no double-counting
    across repeated calls.
  - `write_idempotent_rule()` on a fresh `rule_id` appended; calling it again with the same
    `rule_id` overwrote the line in place (checked directly in `ai_generated_rules.conf`) rather
    than duplicating it; an out-of-range `rule_id` was correctly rejected.
  - `test_waf_configuration()` correctly reported the `REQUEST_PARAMETERS` bug as a failure before
    the fix, and reported success after.
  - `reload_waf()` took effect end-to-end: a rule blocking `test-pattern-beta` really returned
    `403` on a matching request after reload, and returned to `200` once the rule was cleared and
    the WAF reloaded again.
- Ran `reset_state.py`; confirmed `ai_generated_rules.conf` returns to empty. Log truncation
  (the `sudo truncate` step) requires an interactive terminal for the password prompt - confirmed
  the script fails cleanly with a clear sudo error in a non-interactive shell, same limitation the
  pre-existing manual command in `docs/common-commands.md` already has; not a script bug, just
  something to run from a real terminal.

## Status: Sprint 3 Complete

| Deliverable | Status |
|---|---|
| MCP server exposing `read_waf_logs`, `test_waf_configuration`, `write_idempotent_rule`, `reload_waf` | ✅ Done |
| Endpoint parsing + per-endpoint breach-threshold tracking (`get_breach_status`) | ✅ Done |
| Operator reset flow for clean test runs | ✅ Done |

## Next Up (Sprint 4)

Per the timeline: Agent Integration & Dry Runs — wire a LangGraph agent to these MCP tools as its
"brain," deciding when `get_breach_status()` indicates a tripped endpoint and what
`write_idempotent_rule()` call to make in response. Revisit the streamable-HTTP vs. stdio transport
choice at that point if the agent framework's MCP client makes one meaningfully easier to wire up
than the other.
