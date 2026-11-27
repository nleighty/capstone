# Evaluation plan (objective 4)

The source of truth for *what* gets run in the evaluation and *why*. It adapts the grant
application's test plan (`docs/proposal/Graduate_Research_Grant_Application_Project_Description.pdf`,
which also holds the $150 API budget) to the system as it actually stands on 2026-11-27, after the
code review, the post-review fixes, the adaptive attacker, and the runner CLI. Results get recorded
at the bottom of this file as the runs complete.

## What the grant committed to, and what changed

| Grant plan | Now | Why |
|---|---|---|
| Control = the August baseline (84/250 through, 34%) | **Rerun the control (arm A)** on the current attacker | The attacker changed since August (balanced waves, junk-variant filter), so the old 34% isn't a fair control anymore. CRS-only runs cost $0 in API. |
| Main experiment: 15 independent five-wave trials, 50 payloads/wave, means with spread | **Unchanged (arm B, `--defend`)** | This is the core result. |
| — | **Added: arm C, `--defend --adaptive`** | Advisor's "game theory" suggestion (2026-11-13), built 2026-11-19. Not in the grant; no extra line item, absorbed by the dry-run and contingency lines. |
| RGI = % of unseen variants blocked by earlier rules | **RGI = AI rules' added value over CRS** | Redefined 2026-11-13 (CRS's 949110 masks AI-rule matches); see `docs/design-notes.md`. |
| RFPR = benign requests blocked out of 100 sent after every WAF reload | **Unchanged, but not built yet** | Needs a 100-request benign set in the harness, kept *separate* from `verify_rule`'s small set so the metric isn't graded by what the agent iterated against. |
| Sensitivity study: per-endpoint vs. global breach threshold, 5 trials | **Second tier; needs code** | Only per-endpoint thresholds exist today. A global mode is a small mcp-server change. Run only if time allows before 12-09; otherwise report as future work. |
| Cross-model study: lower-cost Claude model, 10 trials | **Second tier; no code needed** | `ANTHROPIC_MODEL` env var in `defensive-agent/config.py` already swaps the model. |
| Timeline: trials Oct 28–Nov 10, report Nov 24 | **Trials 2026-11-27 → 12-03** | The code-review sprint (from 2026-10-29) and post-review fixes came first. Deck draft due 12-04, presentation 12-09. |

## Arms and trial counts

Every trial is 5 waves × 50 payloads, starting from a clean state (`runner reset`) with the MCP
server restarted.

| Arm | Command (per trial) | Trials | Claude cost (grant basis, ~$0.50/agent run) | Tier |
|---|---|---|---|---|
| A — fixed attacker, CRS only | `run --waves 5 --wave-size 50` | 5 | $0 | 1 |
| B — fixed attacker, CRS + agent | `run ... --defend` | 15 | ~$60 | 1 |
| C — adaptive attacker, CRS + agent | `run ... --defend --adaptive` | 5–10 | ~$20–40 | 1 |
| Cross-model (B with a cheaper model) | `ANTHROPIC_MODEL=<cheaper> run ... --defend` | 10 | ~$12 | 2 |
| Threshold sensitivity (B with a global threshold) | needs the global-threshold mode first | 5 | ~$20 | 2 |

Tier 1 is what the 12-04 deck draft needs. Tier 2 runs if there's time before 12-09.

**Time estimate:** the August baseline (250 payloads) took about 16 minutes. One agent run takes
about 1 minute, with up to 3 endpoints per wave. So one defended trial is roughly 20–30 minutes, and
Tier 1 comes to about 10–12 hours of unattended run time. Batches should run unattended (overnight).

**Keep the defender model fixed** for arms B and C (`claude-opus-5`, the model the $0.50/run figure
was measured on). Changing it mid-experiment would break the comparison.

## What has to be built before (or while) the runs go

1. **RFPR benign set:** 100 ordinary requests across the three endpoints, sent by the harness
   after every agent run (i.e. after every reload). Recorded per wave.
2. **`runner metrics`:** computes MTTM, α, RGI and RFPR from a run's CSVs, prints a table, saves a
   per-run summary, and can compare runs or arms (mean ± spread across trials).
3. **`runner trials`:** a batch loop that runs N trials of one arm, resetting state and restarting
   the server between trials, so an arm can run overnight.

## Results

*(filled in as arms complete)*
