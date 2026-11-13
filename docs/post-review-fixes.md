# Post-Review Fixes (2026-11-13, branch `post-review-fixes`)

Fixes for the four "to work out after the review" items in `code-review/README.md`, plus the
auto-trigger that was parked in Sprint 4.6 (#5c). Built and unit-tested offline first (Docker wasn't
reachable from WSL at the time), then **live-checked the same day with a 3-wave smoke run, which passed**.
See "Live check" at the bottom. That's a smoke test, not an evaluation run.

**Next planned step (2026-11-13): a single runner script/CLI** for the whole system: bring up Docker,
check Ollama, start the MCP server, reset state, run waves with or without `--defend`, and summarize the
CSVs. It prints each underlying command before running it, so a user can see what it's doing, but
doesn't have to type the commands by hand. It would replace the `--smoke-test`-flag idea in
`attacker-pipeline/docs/future-improvements.md`.

---

## 1. Auto-trigger: the closed loop (`run.py --defend`)

**Before:** the agent only ran when started by hand, and the pause between waves did nothing.
**Now:** `python run.py --defend` runs the defensive agent after every wave, the last one
included, so each later wave hits the patched WAF and no wave's breaches go unanswered. The last
wave's response still gets an MTTM, but there's no later wave to measure its effect on bypasses.
(Until 2026-11-13 the last wave was skipped. The smoke run below predates that change.)

- `attacker-pipeline/harness/defender.py` starts `defensive-agent/agent.py` as a **separate
  process**, using the agent's own venv. The two subprojects still share no code.
- The harness doesn't choose what to fix. The agent asks the MCP server (`get_breach_status`)
  itself, just as it would if it ran on its own.
- Results go to `run_<id>_agent.csv` next to the wave metrics: one row per endpoint handled, with
  verdict, number of `verify_rule` attempts, and **`mttm_seconds`** (wave over → rule live and
  verified).
- The MCP server must already be running. The harness doesn't start it.
- A crashed or timed-out agent becomes an error row; the attack run continues.
- A pass where nothing tripped still writes a row (`endpoint` = `(none tripped)`, `verdict` =
  `nothing tripped`), so every agent run is visible in the CSV. Added after the smoke run, whose
  wave 2 "nothing tripped" pass left no row.

## 2. Threshold resets per endpoint after a verified rule

**Before:** `tripped_endpoints` counted all bypasses ever, so once login tripped, every later pass
re-worked login from the same old samples, even with zero new bypasses.
**Now:** `BreachTracker` remembers each endpoint's bypass count at its last **PASS**
(`handled_counts`). An endpoint trips again only on `threshold` **new** bypasses after that.
`get_breach_status` also returns `bypasses_since_rule`; `bypass_counts` stays the all-time total.

- Only `verify_rule` reporting PASS closes a breach (server-side, in `server.py`). The agent can't
  declare itself done.
- A rule that ends on FAIL leaves the endpoint tripped, so the next pass tries again with new
  evidence.

## 3. Coverage loss: the protected replay list

**Decision:** built without first running the live "does coverage get lost?" test, because the test
needs the live stack. Reasons it was worth building anyway: the gap is confirmed in the code, there's
one observed instance (`mcp-server/docs/future-improvements.md`), the auto-trigger makes rewrites
much more frequent, and the fix also **measures** the problem (see below).

- At every PASS, the requests that rule was confirmed to block are added to that endpoint's
  **protected list**. It's uncapped and persisted, and `reset_state.py` clears it along with
  everything else.
- Every later `verify_rule` call also replays **all endpoints'** protected requests. All of them,
  because rules aren't scoped to a URL. Any that get through now are reported as
  `coverage_check.regressions`, and the verdict is FAIL.
- Harmless "bypasses" can't get stuck in the list: only requests that a passing rule actually
  blocked are added.
- **This is also the test.** In a multi-wave `--defend` run, any FAIL that lists regressions is a
  rewrite that tried to drop coverage, and the agent had to put it back. Count those for the report.

## 4. Rule ID (and endpoint) enforced in code

**Before:** the prompt said "use exactly this rule_id", but the model could pass any ID in range to
`write_idempotent_rule` and overwrite another endpoint's rule. Prompt injection through log text
could cause that too.
**Now:** `defensive-agent/core/graph.py` (`_bound_tools`) gives the model versions of
`read_current_rule`, `write_idempotent_rule`, and `verify_rule` that **have no `rule_id` or
`endpoint` parameter**. The code fills them in. The model has nothing to get wrong. This makes
`docs/sprint-4.6-direction.md` §3's "injection can't hijack rule identity" true at the agent layer.
The MCP server itself still accepts any in-range ID from any local client (see `SECURITY.md`).

Also added: a hard cap on agent steps (`AGENT_MAX_STEPS`, default 60). The 3-attempt limit was
prompt-only, and once runs are unattended a runaway loop costs money.

## 5. Even seed coverage and fixed wave size

**Before:** `build_wave` cut a seed-ordered list, so `xss-06/07/08` never fired, and a wave could
come up short silently.
**Now** (`attacker-pipeline/harness/orchestrator.py`):
- Each seed is trimmed to its share, and the wave takes variants **one seed at a time in rotation**.
  The seeds that get the one extra variant change every wave. Over 8 waves of 50, every seed fires
  exactly 25 times.
- Seeds that came up short are **topped up** with up to `WAVE_TOPUP_ROUNDS` (2) extra model calls.
- A wave that's still short is fired anyway with a printed WARNING. The CSV row count shows the
  real size.

---

## Tests (all offline)

| Subproject | Run from it | New tests |
|---|---|---|
| `mcp-server` | `python -m unittest discover -s tests -t .` | trip-since-rule, protected list persistence, regression → FAIL, no double replay (29 total) |
| `defensive-agent` | same | first test suite: model can't pass rule_id/endpoint, code fills them in, verdict summary (5) |
| `attacker-pipeline` | same | every seed fires, exact size, extra rotates evenly, top-up, broken model doesn't hang (21 total) |

## Live check

Docker Desktop → Settings → Resources → WSL integration must be on for this distro. Then:
1. `python reset_state.py` (mcp-server) for a clean start, then start the MCP server.
2. A short closed loop: `python run.py --waves 3 --wave-size 20 --defend --label smoke`.
3. Check: wave 1 trips something → the agent PASSes → wave 2's bypass rate on that endpoint drops →
   the `_agent.csv` has rows with `mttm_seconds`; a later pass with no new bypasses leaves that
   endpoint alone.

### Result — 2026-11-13 smoke run (`run_smoke_20261113_104756*.csv`)
An earlier attempt the same morning (`run_smoke_20261113_104125*.csv`, header-only) crashed with
`ConnectionRefused` on :8080 because both containers had exited (code 255) at 10:06, before the run.
The rerun after `docker compose up -d` passed every check:
- Wave 1: 6/20 bypassed (all `/rest/user/login`, 401s). Agent wrote `1000000`, FAIL→revise→PASS
  (2 `verify_rule` attempts; the first version blocked benign `Loved the 'juice' #1 shop`),
  `mttm_seconds` = 104.6.
- Wave 2: 1/20 bypassed; agent pass found nothing tripped and left the endpoint alone. Wave 3: 1/20.
- `matched_rule_id` is filled for **every** 403 row in a `--defend` run (no blanks). `verify_rule`'s
  own replay traffic lands in the same error.log but doesn't confuse correlation: those lines don't
  carry wave markers.

**Finding that matters for RGI:** when a request matches both CRS and an AI rule, the log shows
**`949110`**, never the AI rule's ID. Cause: AI rules load from `RESPONSE-999-…AFTER-CRS.conf`,
which sorts after `REQUEST-949-BLOCKING-EVALUATION.conf`. Both rules run in phase 2, so 949110 denies
first and the AI rule never runs. Confirmed with direct probes: the audit log lists 942100/942190/
942270/949110 and no 1000000, even though the rule's regex matches the payload. So
`matched_rule_id == 1000000` means "the AI rule caught something CRS missed" (its *marginal*
coverage). It does not measure the rule's full coverage, so RGI can't be computed from that column
alone. Also seen: rule 1000000 (written for `/rest/user/login`) blocked one
`/rest/products/search` request, because the template matches `ARGS` on every endpoint. Attribute by
rule ID, not by endpoint.

Not built (still open): `not_replayable` doesn't fail PASS (`mcp-server/docs/future-improvements.md`),
degenerate POST still nudges the count, the attacker doesn't learn from results.
