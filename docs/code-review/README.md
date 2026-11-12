# Code Review / Understanding Sprint

Started 2026-10-29, after the end-of-Sprint-4.6 advisor meeting. Goal: Nic understands the
whole system — concept down to individual lines — well enough to explain it, defend its design
choices, and answer detailed technical questions in the final report and presentation. No new
feature work happens during this phase unless Nic decides on it.

**Roles:** Nic leads. He decides what to look at, in what order, and what happens next. Claude
acts as a tutor: it explains, answers questions, checks understanding with quiz questions, and
writes up each step's notes. It does not change code or choose next steps on its own.

## How this is organized

- **One chat per step.** Each step below runs in its own Claude Code chat to keep context
  focused. A new chat does *not* see earlier chats, so **this folder is the shared memory**: start
  each step's chat by pointing Claude at this README and the previous step's notes file.
- **One notes file per step** (`stepN-<topic>.md`), written during/at the end of that step's chat.
  Each one should read as a walkthrough someone could learn from without the chat: what the
  piece does, how data moves through it, the key design decisions and *why*, gotchas, and
  "questions I should be able to answer". `step1-architecture.md` is the template.
  - **Quiz format (Nic's call, 2026-10-31):** list each quiz question followed by a short
    synthesis: **Got right** (what Nic had), then **Added** / **Corrected** (what Claude filled in
    or fixed). If Nic didn't know one, put **Didn't know this one** and the answer. Don't put
    Nic's verbatim answer and Claude's feedback side by side; that made the file too long.
  - **Voice:** write in Nic's style: plain, direct, first person where it fits ("I start it by
    hand"), not tutor-speak. The notes are his study material.
- **The original planning chat** (2026-10-29) stays the "base" chat for process-level decisions.
  Even so, anything decided there gets written here, because a chat isn't a reliable record.

## Rapid mode (from Step 3, decided 2026-11-11)

Time is short (advisor meeting Fri 2026-11-13; final report + presentation early–mid December), so
from Step 3 on the review is expedited. Nic accepts handing more of the thinking to Claude, at the
cost of some detailed understanding, and the presentation will cover only what he can explain.
Each step is **one session** and targets understanding tiers:

- **Tier A, explain cold:** what the component does, how data flows through it, the key design
  decisions and why, its limitations. *Must* be covered.
- **Tier B, explain at the level of what each function does:** each file/function's job in one or
  two sentences. Covered quickly.
- **Tier C, details to look up:** regex internals, offset bookkeeping, framework plumbing. Skipped,
  unless it's needed to understand A or B. For anything here that could come up in Q&A, the
  notes give a **boundary answer**: the what and why in Nic's words, plus where the detail lives.

Plan after the review (proposed, to confirm with the advisor Friday): Step 6 folds into report
writing → build the harness-driven agent auto-trigger (`docs/sprint-4.6-direction.md` #5c) →
multi-wave runs, which are both the evaluation (α, RFPR, MTTM) and the coverage-loss test below →
fix coverage only if the data shows loss → report/presentation from ~Nov 20.

## The steps (follow data flow, not file order)

| # | Step | Main material | Status |
|---|------|---------------|--------|
| 1 | Concept & architecture | `docs/proposal/Proposal_20261004.pdf` + `diagram_20261004.png` (the current versions; the July files are history only), `docs/design-notes.md`, repo layout in `CLAUDE.md` | ✅ 2026-10-31 — `step1-architecture.md` |
| 2 | Target + WAF | `waf-defense/docker-compose.yml`, ModSecurity/OWASP CRS basics, SecRule syntax, `waf-defense/modsec-rules/` | ✅ 2026-11-06 — `step2-waf.md` |
| 3 | Attacker pipeline | `attacker-pipeline/`: `payloads/seeds.py` → `core/mutate.py` → `core/fire.py` → `harness/orchestrator.py` → metrics; then `analyze.py` | ✅ 2026-11-12 — `step3-attacker.md` |
| 4 | MCP server | `mcp-server/server.py`, `core/log_parser.py` (dense; likely several sessions), `rule_writer.py`, `rule_verifier.py`, `waf_control.py`, `reset_state.py` | ⏳ next |
| 5 | Defensive agent | `defensive-agent/agent.py`, `core/rule_registry.py`, `core/graph.py` (LangGraph ReAct) | ◻ |
| 6 | Cross-cutting | `SECURITY.md`, prompt-injection/MCP-value argument, the four metrics (MTTM, α, RGI, RFPR), what's measured vs. not yet | ◻ |

## Doc map — what to read, when

The repo has ~2,800 lines of docs, about as much as the code, and most were written as a running
record, not as teaching material. **Don't read them up front.** Each doc is read in the step
where its code comes up, and Claude explains any point that isn't clear. Priority:

- **Core** — read during the step, because it explains *why* the code is the way it is.
- **Skim** — glance for context; read closely only if a question comes up.
- **Reference** — not review material; open it only when needed.

| Doc | Step | Priority |
|-----|------|----------|
| `docs/proposal/Proposal_20261004.pdf` + `diagram_20261004.png` | 1 | Core (ignore the older July files) |
| `docs/design-notes.md` | 1, 4 | Core (its early MCP sketch is superseded; skim that part) |
| `docs/meeting-notes.md` | 1 | Skim |
| `waf-defense/docs/Sprint1_Summary.md` | 2 | Core |
| `waf-defense/docs/debug-notes-sprint1-paths.md` | 2 | Skim |
| `attacker-pipeline/docs/Sprint2_Summary.md` | 3 | Core |
| `attacker-pipeline/docs/debug-notes-sprint2-log-granularity.md` | 3 | Skim |
| `attacker-pipeline/docs/debug-notes-sprint3-ollama-hang.md` | 3 | Skim |
| `mcp-server/docs/Sprint3_Summary.md` | 4 | Core |
| `mcp-server/docs/debug-notes-sprint3-*.md` (rule syntax, restart offset) | 4 | Skim |
| `defensive-agent/docs/Sprint4_Summary.md` | 5 | Core |
| `defensive-agent/docs/Sprint4.5_Cleanup.md` | 5 | Skim |
| `defensive-agent/docs/transcripts/sprint4.5-fail-revise-pass.txt` | 5 | Core (shows the loop actually running) |
| `SECURITY.md` | 6 | Core |
| `docs/sprint-4.6-direction.md` | 6 (§2 also in Step 4) | Core for §3 (injection/MCP value), skim the rest |
| `docs/common-commands.md`, `docs/demo-walkthrough*.md` | — | Reference (operating/demo scripts) |
| `*/docs/future-improvements.md` | 6 | Reference (ideas, not built) |
| `CLAUDE.md` | — | Reference (instructions for Claude + repo layout) |

Suggested effort level: **medium** for most steps; **high** for Step 4's `log_parser.py`, regex-
heavy WAF rules (Step 2), and the LangGraph flow (Step 5).

## To work out after the review

- **Rule rewrites can lose old coverage without anything noticing** (found in Step 2; Nic wants this
  treated as a priority). Details and options: `mcp-server/docs/future-improvements.md`.
- **Uneven seed coverage and wave size not guaranteed** (found in Step 3; Nic wants this fixed before Sprint 5
  runs). `xss-06`/`07`/`08` never fired in the baseline. Plan: `attacker-pipeline/docs/future-improvements.md`.
- **Rerun the baseline** in the Sprint 5 runs. The recorded 33.6% includes 13 junk rows (30.0% without them).

## Open items to take to the advisor

- **How much evaluation is expected?** *Asked 2026-10-30. No direct answer on scope.* The advisor
  stressed demonstrating basic functionality (attacks vs. defense) first and performance second,
  with an iterative attacker-vs-defender direction: vary parameters on the Llama side and watch how
  the defense responds ("you get better, I get better"). Nic's takeaway: automating the MCP
  client/agent is the key building block. Full notes and interpretation are in
  `docs/meeting-notes.md` (2026-10-30). Background: the proposal promises MTTM/α/RGI/RFPR; what
  exists is the Sprint 2 baseline (33.6% bypass), the bypass-analyzer findings, and the Sprint 4.5
  `verify_rule` runs. There are no multi-wave results yet. Whether and when to build the
  auto-trigger is Nic's decision, but the intent is to do so as long as time permits.
