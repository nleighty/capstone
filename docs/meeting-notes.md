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

**Logistics**
- 6 credits of capstone total; effectively split so summer work counts toward part of that, with
  1 course formally taken in the Fall.
- Meet with advisor every 2 weeks; give a progress update each time.
- Write weekly progress notes in OneNote.
- Next meeting: Friday, 2026-07-17.
