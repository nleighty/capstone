# Advisor Meeting Playbook — 2026-11-13

A run-sheet for walking the advisor through the work since the end of Sprint 4.6. **Show
captured results; don't run anything live** unless there's spare time (a 3-wave run takes several
minutes). Total ~25 min. Full detail behind every point: `docs/post-review-fixes.md`.

**Open in tabs before the meeting:**
1. `docs/code-review/README.md` (the steps table)
2. `docs/post-review-fixes.md`
3. `attacker-pipeline/metrics/run_smoke_20261113_104756_agent.csv`
4. `attacker-pipeline/metrics/run_smoke_20261113_104756.csv`
5. `waf-defense/modsec-rules/ai_generated_rules.conf` (the rule the agent wrote in that run)

---

## The one-sentence story

> "I reviewed the whole codebase, the review found five real problems, I fixed them, and the system
> now runs as a closed loop. Attack, defend, attack again, with no manual steps in between. A first
> live run shows bypasses dropping from 6 to 1 per wave after the agent's rule went in."

## 1. Code review (3 min) — tab 1

- Steps 1–5 are done, each with its own notes file: architecture, WAF, attacker, MCP server, agent.
  Step 6 (cross-cutting) gets folded into report writing.
- Rapid mode from Step 3 on: I aimed to be able to explain every component's job, its data flow, and
  its design decisions, not every line.
- **The point to make:** reviewing the code didn't just teach me the system. It found real bugs.
  That's section 2.

## 2. What the review found → what I changed (8 min) — tab 2

| Found during | Problem (plain words) | Fix |
|---|---|---|
| Step 2 | When the agent rewrites a rule, it can silently drop protection the old version had (the one we discussed last meeting) | **Protected list.** Every attack a passing rule blocked gets re-tested on every later rewrite; losing one fails verification |
| Step 3 | 3 of the 16 seeds never fired (all XSS), and waves could come up short | Seeds take turns; short seeds get topped up; short waves are flagged |
| Step 4 | The breach threshold never reset, so every agent pass would redo every endpoint that ever tripped | An endpoint re-trips only on **new** bypasses after its last verified rule |
| Step 5 | "Use this rule ID" was only a request in the prompt, so the model could overwrite another endpoint's rule | The code fills in the rule ID, and the model's tools don't even have that parameter |
| (parked since 4.6) | The agent only ran by hand | **`run.py --defend`**: the agent runs automatically between waves |

Point to make on row 1: **the fix is also the measurement.** Every time verification catches a
rewrite dropping coverage, that's a data point for the report.

Point to make on row 4: this hardens the prompt-injection argument. Even if log text manipulated the
model, it has no way to target a different rule.

## 3. Live evidence (6 min) — tabs 3–5

The smoke run was 3 waves of 20 payloads, with `--defend`:

| Wave | Bypassed | What the agent did |
|---|---|---|
| 1 | **6/20** (all login SQLi) | Wrote rule 1000000. **First version FAILED** (it blocked a benign feedback comment, `Loved the 'juice' #1 shop`), so it revised and then PASSED. 2 verify attempts. **MTTM 104.6 s** |
| 2 | **1/20** (a search request, not login) | Nothing new tripped, so it left login alone. Under the old cumulative threshold, login's 6 bypasses would have re-tripped it |
| 3 | **1/20** | — |

- The FAIL→revise→PASS is the best moment to point at: the verifier's benign check caught a false
  positive, and the agent fixed it **without a human**.
- Tab 3 is the `_agent.csv` row (verdict, attempts, `mttm_seconds`). Tab 5 is the rule it wrote.
- **Be upfront:** this is a smoke test (60 payloads, one endpoint), not an evaluation. It shows the
  loop works; it doesn't prove performance yet.

## 4. Two findings worth discussing (4 min)

**a. Adjustment: RGI is now defined as the AI rules' *added value over CRS*.** The original plan
counted any later-wave attack blocked by the AI rule. But when CRS and the AI rule both match, CRS's
blocking check (`949110`) runs first, because of the order the rule files load, so the AI rule's ID
only appears in the log when it catches something CRS **missed**. Rather than work around that, I'm
redefining RGI to measure exactly that: the share of new, unseen later-wave variants blocked by an
AI rule (ID ≥ 1000000) that CRS let through. It's the more honest question for this project anyway:
does the AI add anything on top of CRS? The smoke run already shows it: rule 1000000, written from
wave 1, caught **3** wave 2 attacks and **1** wave 3 attack that CRS missed.

**b. Rules apply site-wide.** The login rule also blocked a search request. That's by design (the
template matches every endpoint's arguments), and the benign check already tests every endpoint for
this reason. Just attribute results by rule ID, not by endpoint.

## 5. Next steps + decisions for the advisor (4 min)

My plan:
1. **A runner script/CLI.** One command to bring the system up, reset it, run waves (with or
   without the agent), and summarize the results. It prints every command it runs, so a user can see
   what's happening. Today it's ~6 manual commands across 3 terminals. Hence, runner CLI app should entail:
   - bring up Docker
   - check that Ollama is running
   - start the MCP server
   - reset state
   - run the waves
summarize the results
2. **Evaluation runs:** a baseline (CRS only) vs. `--defend`, multi-wave, giving the convergence
   curve (bypass rate per wave), MTTM, RFPR, and coverage regressions.
3. **Report + presentation**, early–mid December.

Questions to ask:
- **Scope of evaluation:** how many runs, how many waves? Is "basic functionality first, performance
  second" still the priority?
- **The attacker learning from results** ("you get better, I get better"): in scope before
  December, or future work? (I'd lean future work.)

---

## Likely questions — short answers

- **"How do you know the rule works and isn't just blocking everything?"** `verify_rule` replays the
  recorded attacks *and* a benign set covering every endpoint. PASS needs both: every attack blocked,
  no benign request blocked. The smoke run's first FAIL was exactly that check catching a too-broad
  rule.
- **"What stops the AI from breaking the WAF?"** The config is tested (`nginx -t`) before every reload,
  and the agent can only touch its own rule, in a reserved ID range CRS never uses. The rule ID is
  set by code, not by the model.
- **"Why did bypasses drop to 1 and not 0?"** It's one bypass on a small wave, and the threshold is 5
  new bypasses, so nothing re-tripped. The evaluation runs will show whether it trends to zero.
- **"Is MTTM 104 seconds good?"** It's one data point: the time from the end of the wave to a
  verified, live rule. That includes a failed first attempt. The evaluation runs will give a
  distribution.
- **Anything about implementation detail I can't answer:** "That part was built with AI assistance.
  What it does is X, and it's verified by Y; the detail is in [file]. I can follow up."
