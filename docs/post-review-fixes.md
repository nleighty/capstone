# Post-Review Fixes (2026-11-13, branch `post-review-fixes`)

Fixes for the four "to work out after the review" items in `code-review/README.md`, plus the
auto-trigger that was parked in Sprint 4.6 (#5c). Built and unit-tested offline first (Docker wasn't
reachable from WSL at the time), then **live-checked the same day with a 3-wave smoke run, which passed**.
See "Live check" at the bottom. That's a smoke test, not an evaluation run.

**Plan to the baseline rerun (agreed 2026-11-19), in order:**
1. ✅ **Live re-check** of the two post-smoke-run changes (agent after the last wave; `nothing tripped`
   rows), with the console output saved to `defensive-agent/docs/transcripts/`. Passed 2026-11-19,
   see "Result — 2026-11-19 re-check" at the bottom.
2. ✅ **Adaptive attacker (`run.py --adaptive`)**, the advisor's "game theory" suggestion (2026-11-13).
   Each wave's per-seed results (got through vs. 403) are fed back into the next wave's mutation prompt
   ("more like these, avoid those"), with a few examples per seed. The attacker learns **only from status
   codes** it sees on its own requests, never from `matched_rule_id`, logs, or rules, which keeps it a
   black-box attacker. Off by default, so the fixed attacker stays available for comparison. Offline tests
   with a fake model, then a short live check. Prompt-injection as an attacker strategy is *not* included.
   **That live check also covered §6** (uncapped replay set, built 2026-11-19): restart `server.py`
   first, then confirm each `verify_rule` result's `attack_replay.replayed` equals the endpoint's
   `bypasses_since_rule` (minus `not_replayable`). Built and live-checked 2026-11-19, both passed — see
   "Adaptive attacker" below.
3. ✅ **Runner CLI** for the whole system: bring up Docker, check Ollama, start the MCP server, reset
   state, run waves with or without `--defend`, and summarize the CSVs. It prints each underlying command
   before running it, so a user can see what it's doing without typing the commands by hand. It
   includes a **`test` command** that runs all three subprojects' unit tests the same way. It replaces
   the `--smoke-test`-flag idea in `attacker-pipeline/docs/future-improvements.md`. Built and
   live-checked 2026-11-20 (`runner/runner.py`), see "Runner CLI" at the bottom.
4. **Test coverage:** add `coverage.py` to each venv, measure, and test every function's logic, with
   Docker/Ollama/Claude/HTTP replaced by stand-ins. Report the coverage number per subproject. A
   literal 100% isn't the goal; the live runs cover the real services.
5. **Comment pass**, one subproject per chat, after the tests exist: comment every line that isn't
   self-explanatory to someone newer to Python (regexes, library calls, idioms, magic numbers, order
   dependencies). Not every line: comments that just repeat the code go stale. Update the comment
   convention in `CLAUDE.md` when this starts. First thing to cut if time runs short.
6. Evaluation runs: A = fixed attacker vs. CRS only (the baseline rerun), B = fixed attacker vs. CRS +
   agent (`--defend`), C = adaptive attacker vs. CRS + agent (`--defend --adaptive`, the "you get better, I
   get better" comparison). Then the RGI script. **Superseded 2026-11-27 by `docs/evaluation-plan.md`**
   (the grant's test plan adapted to the current system; the RGI script became `runner metrics`).

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

## 6. `verify_rule` replays every bypass, not the capped sample (2026-11-19)

**Before:** `verify_rule` replayed the endpoint's evidence bucket, which keeps at most 2 bypasses per
seed. A bypass the cap dropped was never replayed and never added to the protected list. Seen live in
the 2026-11-19 re-check: 8 login bypasses, 7 replayed.
**Now:** `BreachTracker` also keeps **`open_bypasses`**: every bypass per endpoint since its last
PASS, uncapped, one entry per request (the same marker dedupe as the buckets, now shared through
`_upsert_by_marker`). `verify_rule` replays that list (`replay_set_for`). At PASS, `mark_mitigated`
adds those requests to the protected list and removes them from `open_bypasses`, so the list stays in
step with `handled_counts`.

- The agent's view doesn't change: `sample_bypasses` is still the capped, diversity-chosen bucket.
  `still_bypassing` can now list a request the agent wasn't shown; its full text is in the result.
- The list is saved in the state file. `reset_state.py` deletes that file, so it needs no change. A
  stale (truncated-log) restart clears the list along with the counts.
- PASS removes only the requests it replayed. A bypass that arrives after the replay stays open.
- Tests: 4 new in `mcp-server/tests/test_log_parser.py` (`ReplaySetUncapped`). They rebuild the
  2026-11-19 case (8 bypasses, 7 shown, 8 replayed) and cover the access+audit merge, PASS → protected
  surviving a restart, and the late arrival. 33 total, all passing.
- ✅ **Live-checked 2026-11-19**, folded into the adaptive attacker's live check (plan item 2): restarted
  `server.py` first; the one rule written had `attack_replay.replayed` = 5, `not_replayable` = 0, and
  `bypasses_since_rule` = 5, so `replayed == bypasses_since_rule − not_replayable` held. Caveat: no single
  seed exceeded the per-seed cap in that wave (5 bypasses, one per seed), so it confirms the condition
  without re-staging the 8-vs-7 gap the pre-fix re-check hit — see "Adaptive attacker" below.

---

## Tests (all offline)

| Subproject | Run from it | New tests |
|---|---|---|
| `mcp-server` | `python -m unittest discover -s tests -t .` | trip-since-rule, protected list persistence, regression → FAIL, no double replay; uncapped replay set (§6) (33 total) |
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

### Result — 2026-11-19 re-check (`run_recheck_20261119_100200*.csv`)
Re-check of the two changes made after the smoke run (agent also runs after the last wave; a pass with
nothing tripped writes a row). Same command shape: `reset_state.py` → `server.py` →
`PYTHONUNBUFFERED=1 python3 run.py --waves 3 --wave-size 20 --defend --label recheck 2>&1 | tee …`.
Full console output: `defensive-agent/docs/transcripts/recheck-20261119_100159.txt`. All three checks
passed. Each was read from the files, not from the console.

| Wave | Bypassed | Agent pass (`_agent.csv`) |
|---|---|---|
| 1 | 5/20 (4 `/rest/user/login`: two 401, two 500; 1 `/rest/products/search`: 500) | `(none tripped)`, `nothing tripped`. Login at 4 < threshold 5 |
| 2 | 4/20 (all `/rest/user/login`, 401) | login tripped (8 total) → rule `1000000`, FAIL→revise→PASS, 2 `verify_rule` attempts, `mttm_seconds` = 93.5 |
| 3 | **0/20** (3 of the 20 403s attributed to `1000000`) | `(none tripped)`, `nothing tripped`. **This last-wave row is the new behavior** |

1. **`_agent.csv` has a row for every wave, including the last.** Waves 1 and 3 are `nothing tripped`
   rows. Before the change, wave 1 would have left no row and wave 3 would not have run at all.
2. **Prompt caching works.** There is exactly one token-usage line, because only wave 2's pass called
   the model. A `nothing tripped` pass exits before any model call (`agent.py`, "No tripped endpoints"),
   so it prints no usage line. The one line: 10 calls, input=106687, **cache_read=93266**,
   cache_write=13401, uncached=20, output=5575.
3. **The verify FAIL reason is in the transcript.** The full `verify_rule` JSON is printed. The first
   attempt blocked 7/7 replayed attacks but returned `FAIL: 1 benign request(s) are now blocked`, with
   `falsely_blocked`: `POST /api/Feedbacks {"comment": "Loved the 'juice' #1 shop", …}`. This is the
   same benign case as the first attempt in the 11-13 smoke run (the quote-then-`#` terminator
   alternative). The revision passed with 0 false positives and `coverage_check.regressions` empty
   (`protected_replayed` = 0, since this was the first PASS of the run, so there was nothing to
   regress yet).

Also seen:
- No 403 row has an empty `matched_rule_id`.
- The model's `generate()` timed out once (90s) in wave 2's mutation. The top-up still delivered a
  full 20-payload wave.
- The server's startup warning `modsec_audit.log … already has N bytes` after a reset comes from the
  WAF container's Docker healthcheck (`/healthz` every 30s) and is harmless. This is now noted in
  `docs/common-commands.md`.
- **`verify_rule` replayed 7 requests, but login's tally was 8. This is the per-seed sample cap, not
  a bug.** `verify_rule` replays the sample bucket, not every bypass, and `BYPASS_SAMPLES_PER_SEED` = 2
  (`mcp-server/config.py`, applied in `BreachTracker._add_sample`). Seed `sqli-02` bypassed 3 times
  (`w1-sqli-02-1`, `w1-sqli-02-2`, `w2-sqli-02-1`), so the oldest one (`w1-sqli-02-1`, body below)
  was dropped. The other seeds (`01` ×2, `03` ×1, `08` ×2) fit under the cap: 2+2+1+2 = 7. What follows
  from this: (a) `verify_rule` checks the rule against its samples, not against every bypass. That's
  already stated in `rule_verifier.py`'s docstring; this is a concrete case of it. (b) The
  **protected list is filled from the same samples**, so a dropped bypass is never re-checked by the
  coverage check on later rewrites. (c) Eviction is oldest-first and ignores the status code, and the
  dropped request was a **500**: it likely reached the database, which is worse than a 401. **No harm
  in this run, confirmed live after the run:** re-sending the exact wave-1 body
  (`{"email": " OR 1=1 /* '1'='1 */", "password": "x"}`, copied from the audit log, no wave marker)
  gives a 403, and the audit entry lists **only `1000000`**, with no CRS score. So the AI rule covers
  it, and CRS alone still doesn't. That only shows this case was covered; the gap still exists. Fixed
  the same day (§6): `verify_rule` now replays every bypass since the last PASS.

---

## Adaptive attacker (`run.py --adaptive`, 2026-11-19) — plan item 2

The attacker was open-loop: every wave sent the same seeds and the same prompt, so variation between
waves was only sampling noise (Step 3 review, `attacker-pipeline/docs/future-improvements.md`).
`--adaptive` closes the attacker-side loop, the offensive half of the advisor's "you get better, I get
better" direction (`docs/meeting-notes.md`, 2026-11-13).

**What it does.** After each wave, each seed's fired variants are bucketed by the status code the WAF
returned — 403 is a block, anything else is a bypass — and a few of each (`config.ADAPTIVE_EXAMPLES_PER_SEED`,
default 3) are fed into that seed's *next* mutation prompt: "these got through, make more like them;
these were blocked, avoid them." Wave 1 is open-loop (nothing fired yet). Off by default, so the fixed
attacker stays available for the A/B eval runs.

**Black-box, by construction.** The feedback is only mutated-payload strings bucketed by status code.
The collector (`harness/orchestrator._feedback_from_results`) takes `(seed_id, mutated, status_code)`
tuples — there is literally no slot for `matched_rule_id`, a log line, or rule text — so nothing about
the WAF's internals can reach the attacker. It sees what a real attacker sees: the responses to its own
requests. Prompt injection as an attacker *strategy* is deliberately out of scope.

**Where the pieces live (all in `attacker-pipeline/`, nothing in `mcp-server/` or `defensive-agent/`):**
- `core/mutate.py` — `SeedFeedback` dataclass (`bypassed`/`blocked` lists), `_feedback_block` prompt
  renderer (each half shown only when non-empty), and a `feedback=None` arg on `generate_variants`
  (None ⇒ byte-for-byte the old prompt).
- `harness/orchestrator.py` — the pure `_feedback_from_results` collector; `feedback` threaded through
  `build_wave` (forwarded per seed, including top-up calls) and `run(..., adaptive=False)`.
- `run.py` — the `--adaptive` flag. `config.py` — `ADAPTIVE_EXAMPLES_PER_SEED`, and `ADAPTIVE_DEBUG`
  (opt-in env flag: prints one `[mutate] adaptive: …` line per seed when a prompt carries feedback, the
  only way to observe it since the prompt isn't otherwise logged).
- Tests: `tests/test_adaptive.py` (12: collector bucketing/capping/per-seed, build_wave forwarding,
  prompt rendering); existing `tests/test_build_wave.py` fakes updated for the new kwarg. 35 attacker
  tests total, all passing offline.

### Live check — 2026-11-19 (`run_adaptive_20261119_124532*.csv`)
`reset_state.py` → restarted `server.py` → `ADAPTIVE_DEBUG=1 PYTHONUNBUFFERED=1 python3 run.py --waves 3
--wave-size 20 --defend --adaptive --label adaptive`. Full console:
`defensive-agent/docs/transcripts/adaptive-20261119_124532.txt`. All checks read from the files.

| Wave | Bypassed | Adaptive feedback | Agent pass |
|---|---|---|---|
| 1 | 6/20 | none (open-loop) | `/rest/user/login` tripped (5 bypasses) → rule `1000000`, PASS first try, `mttm` 58.9s |
| 2 | 2/20 | 16 `[mutate] adaptive:` lines, one per seed | `(none tripped)` |
| 3 | 2/20 | 16 `[mutate] adaptive:` lines, one per seed | `(none tripped)` |

1. **Feedback reached waves 2–3.** 32 `[mutate] adaptive:` lines (16 seeds × 2 waves); wave 1 has none.
   Each line names the seed and how many bypassed/blocked examples its prompt carried. Confirmed in the
   transcript, not just the console.
2. **Llama didn't refuse or degrade.** No refusal strings; it kept emitting variants. One malformed
   variant (`"DROP\u20 tabletS;--"`) hit the line-split fallback — ordinary model noise the junk
   filter/parser absorb, not feedback-induced collapse.
3. **§6 held live.** The one `verify_rule` (wave 1) replayed all 5 recorded login bypasses
   (`attack_replay.replayed` = 5, `not_replayable` = 0, `bypasses_since_rule` = 5). Caveat: those 5 were
   one per seed, so no seed exceeded the per-seed cap; this confirms `replayed == bypasses_since_rule`
   without re-staging the 8-vs-7 gap the pre-fix re-check hit.

**On the dynamic:** bypasses fell 6 → 2 → 2, but that's the *defender* — rule `1000000` closed the login
SQLi avenue after wave 1, and the adaptive attacker couldn't reopen it in two short waves. Expected for a
3-wave smoke run; the real "learning vs. learning" picture comes from the longer eval run C (plan item 6).
Balanced waves also held: 60 rows, all 16 seeds every wave. This is a smoke check, not an evaluation run.

---

## Runner CLI (`runner/runner.py`, 2026-11-20) — plan item 3

One command-line front end for everything `docs/common-commands.md` does by hand. Every subcommand
prints the exact shell command(s) as copy-pasteable `$ …` lines before running them, so a viewer can
follow along without knowing the commands. `--dry-run` (before or after the subcommand) prints them
and runs nothing, for slides and demos. `--help` works on the runner and on every subcommand.

```
python3 runner/runner.py <command> [--dry-run]
  up / down                     docker compose up -d / down (images kept)
  check                         Docker containers, Ollama + llama3, MCP server, Anthropic key (set/not set, never the value)
  server start|stop|restart|status|log   MCP server as a background process
  reset [--restart-server]      reset_state.py (sudo prompts normally) + nginx reload
  run [--waves --wave-size --pause --label --defend --adaptive --adaptive-debug --tee [PATH]]
  summary [CSV]                 per-wave bypass table, _agent.csv rows (MTTM), then analyze.py
  test                          all three subprojects' unit tests (own venvs) + the runner's, PASS/FAIL each
```

**Design decisions:**
- **Standard library only**, so it runs with the system `python3` (3.10). It never imports a
  subproject; it calls each subproject's own `.venv/bin/python`, the same pattern as
  `harness/defender.py`. No subproject's behaviour changed (one bug fix, below).
- **Build vs. run are separate.** `*_steps()` functions return `Step` objects (argv + cwd + env + the
  display line, built together so they can't drift apart); only `execute()` touches the system.
  `runner/tests/test_runner.py` (26 tests) checks the commands offline and asserts that `--dry-run`
  never calls `subprocess`.
- **`server` runs in the background, not in a separate terminal.** Detached (`start_new_session`),
  PID and log in `runner/state/` (gitignored). `start` waits for the port, then prints the server's
  startup lines, so the "file already has N bytes" offset warning stays visible. Chosen because the
  runner can then manage the whole lifecycle (stop/restart, the `--defend` preflight); a new terminal
  window isn't reliable to open from WSL. `server log` follows the output live when needed.
- **`run --defend` preflights the MCP server** and refuses to fire if it isn't answering.
  `PYTHONUNBUFFERED=1` is always set so progress (and the agent subprocess's output) streams live.
  `--tee` replaces the manual `2>&1 | tee …`; with no path it writes
  `runner/state/transcripts/<label>-<timestamp>.txt` (copy a keeper into
  `defensive-agent/docs/transcripts/`).
- **`reset` warns if the server is running** (it only reads its state file at startup).
  `--restart-server` stops it, resets, and starts it again, but only for a runner-started server. If
  the server was started in another terminal, the reset refuses and changes nothing.
- **`summary`'s "403s by AI rule"** column counts `matched_rule_id >= 1000000`, i.e. only what CRS
  missed (the 949110 masking finding above), and is labeled that way in the output.

**Bug fixed along the way:** `attacker-pipeline/analyze.py` with no argument picked the "newest" CSV
by *filename*, which sorts by label rather than time and could land on an `_agent.csv` (different
schema). It now picks by modification time and skips `_agent.csv`. The runner passes an explicit
CSV regardless.

**Live check, 2026-11-20:** `check` → all four OK (MCP server was already running from a separate
terminal). `test` → PASS for all four suites (mcp-server 33, defensive-agent 5, attacker-pipeline 35,
runner 26). Tiny run: `run --waves 1 --wave-size 5 --pause 0 --label runnertest --tee` → 2/5
bypassed, CSV `run_runnertest_20261120_132631.csv`, transcript saved. One of its 403s was attributed
to `1000000`: the rule from the 11-19 runs was still loaded (no reset beforehand, because `reset`
needs the operator's sudo password). `summary` on it and on `run_adaptive_20261119_124532.csv`
reproduced the documented numbers (6→2→2 bypassed, MTTM 58.9 s).

**Full-lifecycle check, same day (run by the student):** `reset` → `server start` → `run --waves 2
--wave-size 10 --defend --label runnercheck --tee` → `summary` → `server stop`
(`run_runnercheck_20261120_133850*.csv`). All passed: wave 1 had 0 AI-rule 403s (reset cleared the
old rule); the server log showed only the harmless healthcheck `already has 830 bytes` warning;
wave 1 = 4/10 bypassed (under threshold → `nothing tripped` row), wave 2 = 1/10 with login tripped
at 5 → `1000000` FAIL (benign `'juice' #1` feedback blocked, the known case) → revise → PASS, 2
attempts, MTTM 83.4 s; `replayed` 5 = `bypasses_since_rule` 5 (§6 held); `regressions` empty;
`cache_read` 74792; `server stop` left it DOWN with the PID file removed. Gap found and fixed the
same day: the `--tee` transcript held `run.py`'s output only, not the command that produced it. It
now starts with a `# <timestamp>` line and the full `$ …` command line (test:
`TeeTranscript`, 27 runner tests).
