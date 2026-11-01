# Advisor Meeting Notes

## 2026-07-03 — Initial / groundbreaking meeting

> **Note:** this was the very first planning meeting, before the proposal was written — some items
> below were superseded once the proposal (`docs/proposal/Proposal_20260703.pdf`) locked in the
> actual architecture. Superseded points are marked inline; treat the proposal as authoritative
> wherever the two disagree.

**Scope & phasing**
- Use AI to conduct payload investigation (offensive side generates + investigates payloads).
- **Summer**: build the basic framework — at minimum, the offensive/attacking side.
- **Fall semester**: MCP integration (Claude or otherwise, if not already done by then) and
  refining the defensive side.
  - ⚠️ *Superseded*: the proposal settled this — **both** offensive and defensive sides default to
    the local Ollama/Llama-3 model, not Claude. Claude (or another cloud model) is scoped as an
    optional later swap for the defensive side only, made easy by MCP decoupling model from tools
    (see `docs/design-notes.md`, "Swapping LLMs") — not a baseline Fall requirement.

**Testing considerations raised**
- False positive rate: consider generating *alerts* rather than outright blocking, to some degree,
  to avoid over-securing and hurting availability. (Ties into the RFPR metric in the proposal.)
- Investigate performance / response time impact of the defense pipeline.
- Open question: does every request/decision have to go through Claude (or another cloud LLM)? Need
  to monitor traffic and response times for practicality — an LLM call in the hot path may not
  scale.
  - ⚠️ *Largely superseded*: the proposal's default architecture uses the local Ollama/Llama-3
    model for both sides, which sidesteps per-request cloud calls by default. Still worth
    monitoring local-inference latency, but the "sending everything to Claude" version of this
    concern doesn't apply to the baseline design.
- Related idea: leverage some form of local knowledge/caching instead of hitting the LLM for every
  decision.
  - Still an open question — not addressed by the proposal. Worth revisiting if local-inference
    latency turns out to be a bottleneck during Sprint 2/3 testing.

## 2026-09-17 — Defensive-side LLM: Claude instead of Ollama/Llama-3

- **Decision** (reviewed with advisor): the defensive LangGraph agent will use Claude via the
  Anthropic API, not the local Ollama/Llama-3 model the proposal defaulted to. The offensive side
  stays on local Ollama/Llama-3 unchanged. This updates the "both sides default to Ollama" note
  from 2026-07-03 above — Claude is no longer just an optional later swap, it's the Sprint 4 plan.
  - **Why**: gives genuine independence between attacker and defender (not both driven by the same
    model), and the guardrail problem that ruled out cloud LLMs for the *offensive* side (refusing
    to generate exploit payloads) doesn't apply to the *defensive* side (writing WAF rules is
    ordinary defensive work). MCP already decouples model choice from the tool layer per the
    proposal's design (`docs/design-notes.md`, "Swapping LLMs"), so this swap doesn't require
    touching `mcp-server/`.
  - **Practical implications**: the defensive agent now needs its own Anthropic API key (metered,
    separate from any claude.ai/Claude Code subscription — a subscription does not grant API
    access). Call volume stays low since the agent only fires after `get_breach_status()` trips a
    breach threshold, not per-request, so expected cost is minor. Resolves the 2026-07-03 "does
    every request have to go through Claude" latency concern the same way: it doesn't, by design.
  - API key setup: dedicated Console workspace + spend limit, key stored in a project-scoped
    `.env` (see `defensive-agent/.env.example`) rather than a machine-wide shell export, so it
    can't leak into unrelated work and is easy to rotate/revoke independently. (Originally staged
    at repo root before `defensive-agent/` existed; moved once the subproject was scaffolded.)

**Logistics**
- 6 credits of capstone total; effectively split so summer work counts toward part of that, with
  1 course formally taken in the Fall.
- Meet with advisor every 2 weeks; give a progress update each time.
- Write weekly progress notes in OneNote.

## 2026-10-30 — Post-4.6: how much evaluation is expected?

Question asked (queued in `docs/code-review/README.md`): the proposal promises MTTM/α/RGI/RFPR
across attack waves, but only the Sprint 2 baseline and the `verify_rule` runs exist — how much
evaluation is expected? No direct answer on scope; Nic's notes from the meeting, verbatim:

> Basic functionality vs. performance tests
> Attacks vs functionality--> demonstrate it
> How to use llama to generate effective attacks? How can we use Claude/MCP to effectively defend
> the firewall?
> Performance
> Direction: model of attacks and changing potential parameters on the llama side and see what
> happens, predictability of offensive side, knowing each side better-->"you get better, I get better"
> Iterative

Reading of the notes (an interpretation, not the advisor's words):
- **Two levels of evaluation:** *basic functionality* (demonstrate that attacks land and the defense
  responds) first, *performance* second.
- **Two framing questions for the report:** how to get effective attacks out of Llama, and how to use
  Claude/MCP to defend effectively.
- **Suggested direction:** treat it as an iterative attacker-vs-defender process ("you get better, I
  get better"). Vary parameters on the Llama/attack side, watch how the defense responds, and get a
  sense of how predictable the offensive side is.
- The full four-metric multi-wave suite wasn't explicitly required or ruled out. What to build next
  (if anything) is still Nic's decision during the code-review sprint, but the automation of the MCP client/agent is the important building block to do.
