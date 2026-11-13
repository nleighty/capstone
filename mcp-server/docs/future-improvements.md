# Future Improvements

Small, proposed-but-not-yet-built enhancements for `mcp-server/` — not part of any current
sprint's scope, just tracked so the ideas don't get lost.

## Degenerate POST bodies still nudge the bypass *count* (Sprint 4.6)

The Sprint 4.6 defender-side degeneracy guard (`core/log_parser.py`,
`_is_degenerate_payload`) drops junk "variants" (the lone-`[` class) so they don't trip the
breach threshold or become agent evidence. It fully covers GET query payloads (visible on the
access line, where counts are sourced) and keeps junk POST *bodies* out of the agent's evidence
and `verify_rule` replay.

Residual: a degenerate **POST** still increments `bypass_counts`, because the body isn't visible
on the access line where counts are sourced — only in the audit log, which arrives separately.
The proper fix is to source POST bypass counts from the audit log rather than the access log, but
Sprint 4.5 deliberately kept counting on the access log alone (the behavior already proven
correct), so this is a larger change than it looks. The practical harm is small (a slight count
inflation from junk POSTs; the dangerous part — junk reaching the agent/verifier — is already
closed). Revisit only if Sprint 5's α (bypass decay) turns out to be sensitive to it.

## `verify_rule` can PASS without re-testing POST attacks (`not_replayable`)

*Found during the Step 4 code review, 2026-11-12.*

`verify_rule` skips any sample it can't rebuild (a non-GET with no body) and counts it in
`attack_replay.not_replayable`, but that count doesn't affect the verdict. A POST sample only gets a body
when its audit-log entry enriches it. That doesn't happen when (1) the body was junk (the degeneracy guard
skips it, correctly), (2) the audit log is missing or disabled (e.g. a `docker-compose.yml` without
`MODSEC_AUDIT_LOG`), so *every* POST sample is skipped, or (3) the sample was loaded from a state file
saved before samples were structured. Case 2 is the risk: the verdict says PASS while the login and
Feedbacks attacks were never replayed.

Options (undecided): fail or warn when `not_replayable` is above zero (excluding junk-body skips, which
would need tagging so they can be told apart); or check on startup that the audit log exists and is being
written, and refuse to verify if not. Low priority while the current compose file has the audit log on.

## ✅ Rule rewrites can lose old coverage without anything noticing — BUILT (2026-11-13, not yet live-tested)

Built as the "permanent replay list" option (`BreachTracker` protected list + `coverage_check` in `verify_rule`). The live test below wasn't run first, because Docker was unavailable; the reasons for building it anyway are in `../../docs/post-review-fixes.md` §3. Multi-wave `--defend` runs now measure the problem: each FAIL listing `regressions` is a rewrite that tried to drop coverage. The original write-up is kept below.

*Found during the Step 2 code review, 2026-11-06. **Priority to work out after the review**; it
matters most once multi-wave runs start rewriting the same rule repeatedly.*

**The problem.** `write_idempotent_rule` overwrites a rule by ID, so each agent run replaces the
whole regex. If the new regex drops something the old one covered, that protection is gone.
`verify_rule` only notices if the affected request is still in `BreachTracker`'s sample list, and
that list is capped (`BYPASS_SAMPLES_PER_SEED`, `BYPASS_SAMPLE_LIMIT`) and wiped by
`reset_state.py`. A request the old rule blocks also returns 403, so it isn't recorded as a new
bypass.

**Evidence.** The rule 1000000 revised in the Sprint 4.5 transcript blocks `admin'#`,
`admin@juice-sh.op&#x27--`, and ` OR '1''='1 `. The version committed in `3638a3a` (2026-10-12)
replaced it and blocks none of them, and neither does rule 1000001 (tested with Python's `re`, not
on the live WAF). The system prompt already told Claude to treat the existing rule as "a floor"
(`defensive-agent/core/graph.py`, step 1), so a warning alone may not be enough. It isn't known
whether the rule file was reset before that run.

**The hard part.** Working out everything a long regex was meant to block, from the regex alone, is
a difficult inference for the LLM, so the fix may need to give it more than the raw regex.

**How real it is.** The gap in the design is confirmed from the code: nothing enforces that coverage
is kept. How often the LLM actually narrows a rule when an existing rule is in front of it hasn't
been measured. If the file was reset before the 2026-10-12 run, Claude never saw the old rule, so
that run says nothing about whether the prompt warning works.

**Test before building anything.** Run several waves without resetting state between them. Save
every rule version and the full list of bypasses, then re-test each new regex against all earlier
bypasses. If coverage holds, a fix may not be needed; if it drops, that also gives data for the
report.

**Options to weigh if the test shows loss (undecided):**
- **Stronger prompt warning.** Cheapest, but it still relies on the LLM.
- **Keep a record for the LLM (Claude's memory, or a file the code writes).** Store what each part of
  a rule was added for, so the agent has that context on the next rewrite. This helps the LLM reason
  about the rule, but doesn't guarantee it keeps the coverage.
- **A permanent replay list for `verify_rule`.** Keep every recorded bypass in a separate, uncapped
  list, and leave the capped list for the agent's evidence. Lost coverage then fails verification,
  enforced by code. Open questions: replay time as the list grows, and how to exclude harmless
  entries that shouldn't block a PASS.
- **Add rules instead of replacing them.** Give new patterns new IDs, so old rules stay untouched.
  This changes the one-rule-per-endpoint design and lets the rule file grow.
