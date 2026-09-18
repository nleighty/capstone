# Capstone Project

**Title:** An Adaptive Defense Framework Against GenAI-Driven Web Payload Polymorphism Using MCP
**Student:** Nic Leighty | **Advisor:** Jiazhen Zhou | **Semester:** Fall 2026 | **Credits:** 6
Full proposal: `docs/proposal/Proposal_20260703.pdf` (architecture diagram also at
`docs/proposal/diagram_20260609.png`).

## What this is
A self-healing WAF defense framework, orchestrated over MCP, that closes the loop between an
AI-driven attacker and an AI-driven defender:

- **Offensive side**: a local LLM (Ollama/Llama-3) obfuscates standard SQLi/XSS payloads into
  polymorphic variants and fires them at the target through the WAF.
- **Target + WAF**: OWASP Juice Shop behind an Nginx/ModSecurity (OWASP CRS) reverse proxy.
- **Defensive side**: a LangGraph agent, powered by Claude via the Anthropic API, that once a
  breach threshold is crossed reads WAF logs, identifies the mutation pattern, and writes a new
  idempotent WAF rule — via a custom Python MCP server (built on the official `mcp` SDK,
  `mcp-server/`) exposing: `read_waf_logs()`, `get_breach_status()`, `test_waf_configuration()`,
  `write_idempotent_rule()`, `reload_waf()`. Using Claude here (vs. the proposal's default of
  Ollama/Llama-3 for both sides) is a Sprint 4 decision made with the advisor — see
  `docs/meeting-notes.md`, 2026-09-17 entry — that gives real independence between attacker and
  defender models; the offensive side stays on local Ollama/Llama-3 unchanged.
- **Evaluation**: an independent test harness scores each cycle on Mean Time to Mitigation (MTTM),
  Bypass Decay Rate (α, across attack waves of 50 payloads), Rule Generality Index (RGI — does a
  rule generalize to unseen variants, not just the one it was written for), and Regressive False
  Positive Rate (RFPR, target 0% — patches must not break benign traffic).

Everything runs local/containerized (WSL2 host), zero budget, LLM-agnostic by design (defensive
side could swap to a different LLM via MCP; offensive side is intentionally hardcoded to the local
LLM since cloud LLMs guardrail against generating exploits).

## Timeline (see proposal for full detail/dates)
1. Environment Setup — Docker for WAF + Juice Shop, logging, rule-injection target ✅ **Sprint 1 done**
2. Attacker Pipeline & Test Harness — Ollama payload mutation, test orchestrator ✅ **Sprint 2 done**
3. MCP Server & Defenses — expose logs/rule-writing as MCP tools, threshold tracking ✅ **Sprint 3 done**
4. Agent Integration & Dry Runs — LangGraph agent wired to MCP tools, idempotent rule IDs
   🔶 **built, pending a live Docker/WAF dry run** — see `defensive-agent/docs/Sprint4_Summary.md`
5. Automated Testing — multi-wave attack loops, collect MTTM/α/RGI/RFPR
6. Report finalization, then presentation prep

Timeline is agile/subject to change per the proposal — treat sprint summaries as the source of truth
over this list.

## Repo layout
- `docs/` — project-wide material: the proposal, diagram, overall milestones, anything that spans
  subprojects.
  - `docs/design-notes.md` — pre-proposal architecture reasoning (threshold tracking approach,
    the Scoped Inclusion idempotency pattern, per-metric implementation notes, an early/superseded
    MCP server sketch, LLM-swapping approach). Read this before implementing the MCP server or the
    metrics/test-harness pieces — it's the "why" behind several proposal decisions.
  - `docs/meeting-notes.md` — advisor meeting log (scope decisions, meeting cadence, open questions
    raised by the advisor).
  - `docs/demo-walkthrough.md` — rehearsable, self-run script for demoing the offensive pipeline
    concept of operations to the advisor (or anyone else) without relying on an AI executing it live.
  - `docs/demo-walkthrough-mcp.md` — same pattern, for the Sprint 3 defensive MCP server. Written to
    run standalone (no attacker-pipeline dependency) or combined with a wave fired from the other
    walkthrough — see that doc for which to use.
  - `docs/common-commands.md` — day-to-day operation quick reference (Docker, Ollama, running the
    attacker pipeline, running the MCP server, running the defensive agent) spanning `waf-defense/`,
    `attacker-pipeline/`, `mcp-server/`, and `defensive-agent/`.
- `waf-defense/` — Docker environment (target app + ModSecurity WAF), logging, and the
  rule-injection target the defensive agent will write to.
  - `waf-defense/docs/` — sprint summaries and debug notes specific to this subproject.
- `attacker-pipeline/` — the offensive pipeline: local Ollama payload mutation (`core/mutate.py`),
  attack firing against the WAF (`core/fire.py`), and the test orchestrator/harness that runs
  attack waves and writes baseline metrics (`harness/`). Seed payloads live in `payloads/seeds.py`;
  metrics land in `attacker-pipeline/metrics/` (gitignored CSVs).
  - `attacker-pipeline/docs/` — sprint summaries, debug notes, and `future-improvements.md`
    (proposed-but-not-yet-built enhancements) specific to this subproject.
- `mcp-server/` — the defensive MCP server: exposes `read_waf_logs()`, `get_breach_status()`,
  `test_waf_configuration()`, `write_idempotent_rule()`, `reload_waf()` as MCP tools over
  streamable-HTTP, plus per-endpoint breach-threshold tracking (`core/log_parser.py`) and an
  operator-only `reset_state.py` for clearing rules/logs between test runs. This is the future
  Sprint 4 defensive agent's tool layer, not the agent itself.
  - `mcp-server/docs/` — sprint summaries and debug notes specific to this subproject.
- `defensive-agent/` — the Sprint 4 defensive "brain": a LangGraph ReAct agent (Claude via
  `langchain-anthropic`) that connects to `mcp-server`'s tools over MCP (`langchain-mcp-adapters`),
  deterministically checks `get_breach_status()` and assigns each newly-seen endpoint a stable
  `rule_id` (`core/rule_registry.py` — code-owned, never left to the LLM, since that's what actually
  makes "static rule IDs" idempotent rather than hoped-for), then hands the LLM the evidence
  (`get_breach_status()`'s `sample_bypasses`, bucketed by attack family) to design and write a rule
  via `write_idempotent_rule` → `test_waf_configuration` → `reload_waf`. Runs as a single "dry run"
  pass (`agent.py`), not a polling loop — see `defensive-agent/docs/Sprint4_Summary.md`.
  - `defensive-agent/docs/` — sprint summaries and debug notes specific to this subproject.
- Future subprojects (automated multi-wave testing / metrics, Sprint 5) will likely land as sibling
  directories here, each with their own `docs/` if needed.

## Where to look for current status
Don't treat this file as the status tracker — check the most recent sprint summary in the relevant
subproject's `docs/` folder (e.g. `waf-defense/docs/Sprint1_Summary.md`) for what's actually done
and what's next.

## Conventions
- Sprint summaries live in `<subproject>/docs/Sprint<N>_Summary.md`.
- Non-obvious implementation gotchas get their own debug-notes file rather than bloating the sprint
  summary (see `waf-defense/docs/debug-notes-sprint1-paths.md` for the pattern).
- Proposed-but-not-yet-built enhancements (not in scope for any current sprint) go in
  `<subproject>/docs/future-improvements.md`, not in a code comment alone or in an operational
  reference doc like `docs/common-commands.md` — keep "what to run" and "ideas for later" separate.
- **Code comments — moderate, not zero, not exhaustive.** This is a capstone project an advisor and
  graders will read, not a fast-moving production codebase, so lean toward more explanation than
  you would elsewhere: a short module-level docstring explaining what the file is/why it exists,
  docstrings on non-trivial functions/classes explaining intent (not just restating the signature),
  and inline comments wherever the *why* isn't obvious from the code alone (a design tradeoff, a
  workaround, a non-obvious ordering requirement). Skip comments that just restate what a
  well-named line already says. See `attacker-pipeline/core/mutate.py` or
  `attacker-pipeline/harness/orchestrator.py` for the target density.

## Organizing documentation — full latitude, no need to ask
I have standing permission to create new doc files/folders, rename or move existing ones, and split
or merge docs whenever the current structure stops fitting a growing project — no need to check
first. This is how `docs/design-notes.md`, `docs/meeting-notes.md`, and `docs/proposal/` came to
exist: raw/freeform notes in, organized structure and naming out, without being told exact
filenames or layout.

Guardrails while exercising that latitude:
- Creating, renaming, splitting, and merging docs needs no permission. Deleting content is
  different: if something looks stale, inaccurate, or superseded, flag it and ask which the user
  wants — annotate it in place (see the ⚠️ *superseded* notes in `docs/meeting-notes.md` for the
  pattern) or delete it outright. Don't decide that unilaterally either way.
- Whenever a doc is added, renamed, or moved, update the "Repo layout" section above in the same
  edit, so it never drifts out of sync with what's actually on disk.
- Say what changed and why in the same turn. Full latitude means not needing permission first, not
  operating silently — the user should always be able to see what got reorganized.

## Capture context automatically — don't wait to be asked
This project spans many chats, and only what's written to a file survives between them. So: when a
sprint wraps, a design decision gets made, an implementation deviates from the proposal, or a
non-trivial bug gets root-caused, write it down before the session ends — proactively, without
waiting for an explicit instruction to do so.
- Subproject-specific outcomes (a sprint finishing, an implementation choice scoped to one
  subproject, a debugging war story) → that subproject's `docs/` (a `Sprint<N>_Summary.md` update
  or a new debug-notes file).
- Project-wide decisions (scope changes, architecture pivots, a new subproject being added) →
  update this file directly.
Keep entries factual and concise — capture *what changed and why*, not a transcript of the
conversation. If unsure whether something's worth recording, err toward recording it: cheap to
ignore later, expensive to have lost.
