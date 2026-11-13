# Step 4 — MCP server

Code-review sprint, Step 4, rapid mode. Chat held 2026-11-12, one session.

**Source material:** everything in `mcp-server/` (~1,450 lines): `server.py`, `config.py`, `core/log_parser.py`,
`core/rule_writer.py`, `core/rule_verifier.py`, `core/waf_control.py`, `reset_state.py`. Main supporting doc:
`docs/Sprint3_Summary.md`. Also `docs/future-improvements.md` (the rule-coverage issue).

**How this file is laid out:** big picture, then each file (Tier A = explain cold, Tier B = one line per function,
Tier C = boundary answers), then `verify_rule` and the coverage issue in depth (advisor meeting 2026-11-13), the quiz,
grader questions, and repo changes.

---

## Big picture

```
access.log ─┐                                      ┌─► get_breach_status() ─► agent reads counts + samples
error.log  ─┼─► BreachTracker.poll() ─► tallies ───┤
audit.log  ─┘     (log_parser.py)       + samples ─┴─► verify_rule() ─► replays samples + benign set ─► WAF :8080

agent ─► read_current_rule / write_idempotent_rule (rule_writer) ─► ai_generated_rules.conf
      ─► test_waf_configuration / reload_waf (waf_control) ─► docker exec waf nginx -t / -s reload
```

The MCP server gives the agent **eyes** (logs, breach status), **hands** (write a rule, reload), and a **check** (verify).
It decides nothing. The agent decides; the server does what it's asked, within limits.

---

## 1. `server.py`: what an MCP server is

**MCP (Model Context Protocol)** is a standard way for an LLM app (the *client*, my LangGraph agent) to discover and call
tools on a separate program (the *server*). The client asks what tools exist and gets each one's name, argument schema, and
description. The LLM picks a tool and arguments, and the client sends the call.

- **`@app.tool()`** turns a Python function into a tool. Type hints become the schema, and **the docstring is the description the
  LLM reads**. So the docstrings in `server.py` are really prompt text, which is why they read like instructions ("call this
  AFTER reload_waf()").
- **Transport:** streamable-HTTP on `127.0.0.1:8000/mcp`, a standalone always-on service like the WAF and Ollama. Loopback only,
  no auth (lab choice; `SECURITY.md`, Step 6).
- **Why MCP instead of importing functions:** the agent never sees Docker, file paths, or log formats, only 7 tools. I could swap
  the LLM or the agent framework without touching the server. That's the "LLM-agnostic" claim.

| Tool | What it does | Why it exists |
|---|---|---|
| `read_waf_logs(lines, raw)` | Last N error-log lines, compacted; hides `_replay=1` | What's being **blocked**. Compacted because 50 raw lines were ~20k tokens |
| `get_breach_status(endpoint)` | Per-endpoint bypass/block counts, tripped endpoints, `sample_bypasses` | **Tripwire + evidence.** Samples added in Sprint 4, since counts don't say what to block |
| `read_current_rule(rule_id)` | The current rule line for that ID | Sprint 4, so an overwrite isn't blind. The only coverage guard today |
| `write_idempotent_rule(id, pattern, desc)` | Write or overwrite one SecRule by ID | Scoped Inclusion: same ID = same line, file never grows |
| `test_waf_configuration()` | `nginx -t` in the container | Catch a broken rule before it takes the WAF down |
| `reload_waf()` | `nginx -s reload` | Make the rule live |
| `verify_rule(endpoint)` | Replay recorded bypasses + benign set → PASS/FAIL | Sprint 4.5. Before it, "parses" looked the same as "works" |

**Not a tool, on purpose:** `reset_state.py`. If the agent could wipe its own rules and logs, RGI would be meaningless, and that's
a destructive capability I don't want exposed to an LLM.

---

## 2. `core/log_parser.py`: what it guarantees (Tier A)

### Three logs, three jobs

| Log | Has | Used for |
|---|---|---|
| `access.log` | Every request line + status, **no body** | **Bypass counts** (only source) + samples for GETs |
| `error.log` | Only ModSecurity denials | Blocked counts (telemetry, never trips anything) |
| `modsec_audit.log` | JSON per request, **with body** + matched data | Upgrades samples so POSTs are visible and replayable. Never counts |

### What counts as a bypass
An access-log line that has `_wave_marker` (attacker traffic, the lab assumption from Step 3), a status **other than 403**
(401/500 count: the WAF let it through), and, for GETs, a decoded query payload of at least 4 characters. Replays never count:
the marker is stripped, and the error-log path skips `_replay=1`.

### Breach threshold
- Per endpoint (path, query string stripped). **Tripped at `bypass_counts >= 5`.** Blocks never trip it; they're already handled.
- **Cumulative:** survives restarts, never decays, only `reset_state.py` clears it. "Tripped" means "has ever had 5+ bypasses",
  not "is being bypassed now". Fine for a single dry run; worth thinking about for multi-wave Sprint 5.

### Degenerate-payload guard (length, not keywords)
- Under 4 characters of injected content = junk. For a JSON body it measures the **longest string value**, so `{"comment": "["}`
  is 1 character, not 15.
- **Why length:** the project's premise is that the attacker mutates payloads to dodge keyword matching. A defender filter like
  "drop anything without `<script>` or a quote" *is* keyword matching, and it would throw away the most obfuscated payloads,
  the ones that matter most. Length doesn't look at content: 1 character is noise in any family.
- **Why the attacker side can check tokens:** `mutate.py` is grading its own output before firing. The defender can't assume a
  cooperative attacker, so it uses the content-free test.
- **Known gap:** a junk **POST** still adds 1 to `bypass_counts`. Counts come from the access log, where the body isn't visible, so the
  guard can't run there. The audit-log guard keeps it out of the *evidence* (where it would do real harm), but doesn't take the count
  back (`mcp-server/docs/future-improvements.md` §1).

### What evidence the agent gets
`sample_bypasses = {endpoint: {family: [text, ...]}}`
- **By family**, read off the marker (`w3-sqli-05-2` → `sqli`), never off payload content. `/rest/products/search` gets both SQLi and
  XSS, and a flat bucket would let one push the other out.
- **Diverse, not most recent:** at most **2 per seed**, **20 per family**. Over the limit, the oldest sample of the most-represented
  seed is evicted. The old "last 5" once showed the agent 5 samples from one seed while 12 other bypasses were invisible.
- **One sample per request:** access and audit lines for the same marker merge; the audit version (with the body) wins.
- **The agent sees only `text`** (URI, body cut to 500 chars, matched data). The full record (method, URI, **full body**, content type)
  stays on the server for `verify_rule`.

## `log_parser.py`: how it works (Tier C, boundary answers)

- **"How do you avoid double-counting?"** Each log is read from a saved byte offset, so each poll only reads what's new. Same technique
  as Step 3's `LogReader`, reimplemented so production code doesn't import the test harness. → `_OffsetLog`.
- **"What if the server restarts mid-run?"** Offsets and tallies are saved to `state/breach_tracker_state.json` after every poll with new
  lines (temp file + rename, so a crash can't corrupt it). It resumes from there. No checkpoint → start at end of file, with a warning. A
  log smaller than its checkpoint (truncated by hand) → all tallies thrown out, since they no longer match the disk. →
  `BreachTracker.__init__`, `_initial_offset`, `_save_state`; the bug it fixed is in `debug-notes-sprint3-restart-offset.md`.
- **"How do you parse the lines?"** One regex per log format plus marker regexes for family and seed; the audit log is JSON, one request
  per line, and a half-written line just gets skipped. → module-level `_*_RE` and the `_extract_*` functions.

**Functions (B):** `compact_error_line` shrinks an error line to its useful fields. `_extract_blocked_endpoint` / `_extract_bypassed_endpoint`
/ `_extract_audit_sample` apply the rules above to one line each. `_meaningful_len` + `_is_degenerate_payload` are the junk guard.
`_add_sample` merges by marker and enforces the per-seed / per-family caps. `poll` reads all three logs, updates everything, and saves.
`status` is what `get_breach_status` returns. `samples_for` gives `verify_rule` the full records.

---

## 3. `core/rule_writer.py`

- **Template:** `SecRule REQUEST_COOKIES|ARGS "@rx <pattern>" "id:<id>,phase:2,deny,status:403,msg:'<desc>'"`.
  **`ARGS` with no URL condition means every rule is live on every endpoint.** That's why `verify_rule`'s benign set covers all three.
- **IDs 1000000–1999999** (7 digits), so they can never collide with CRS's 900000–999999 (e.g. 949110).
- **Idempotent:** find the line with `id:<id>,` (the comma stops `1000001` matching `10000010`), replace it, or append if new.
- **Sanitizing:** `"` in the pattern escaped; in the description `%` → `percent-` (ModSecurity treats `%` as a macro and `nginx -t` fails),
  newlines collapsed (one rule per line is what makes find-by-ID work).
- **Functions (B):** `read_rule` returns the line or "no existing rule". `write_rule` validates, sanitizes, overwrites or appends.

## 4. `core/waf_control.py`
`_run` = `docker exec waf nginx <args>`, returns (success, output). `test_configuration` = `-t`, `reload` = `-s reload`. Reload returns when
the signal is sent and workers pick up the rules a moment later, which is why `verify_rule` waits 2s first.

## 5. `reset_state.py`
Operator-only. Empties the rules file, `sudo truncate`s the 3 logs **in place** (nginx holds them open; delete-and-recreate would leave it
writing to a deleted file), and deletes the breach state file. Restart the server after. Not an MCP tool (section 1).

---

## 6. `verify_rule` in depth

**Question it answers:** does the rule that's live now actually work? Before Sprint 4.5 the only check was `nginx -t` (syntax).

1. **Wait 2s** for the reload to take effect.
2. **Attack replay.** For each sample from `samples_for(endpoint)`:
   - Skip it if it can't be replayed (a POST with no body, never enriched from the audit log) → `not_replayable`.
   - Strip `_wave_marker`, add `_replay=1`, so it isn't counted as new attacker traffic by BreachTracker or the attacker harness. The other
     query params go out **byte-for-byte**, since re-encoding could change the obfuscation that made it bypass.
   - 403 → `now_blocked`; anything else → `still_bypassing`.
3. **Benign guard.** 12 fixed requests across **all three endpoints**, picked to *look* like attacks (`o'brien@`, "salt and pepper or sugar,
   select one", `q=[`, `'juice' #1`). Any 403 → `falsely_blocked`. The first version only tested the tripped endpoint and passed a login
   rule that was blocking normal feedback comments.
4. **Verdict:** PASS only if both lists are empty; otherwise FAIL, and the agent revises (Step 5 transcript).

**Safety:** the agent can't supply a request, only an endpoint name. The server replays what it logged itself plus its own fixed set, so the
tool can't be used to send arbitrary traffic.

**What PASS doesn't prove:**
- **Generalization.** It replays the evidence the rule was written from, so it's a fit check. RGI (Sprint 5) covers unseen variants.
- **False-positive rate.** 12 requests is a sanity check. RFPR uses a separate, larger set so the agent isn't graded on what it iterated against.
- **Untested samples.** `not_replayable` is reported but doesn't fail the verdict.
- **Earlier coverage.** Next section.

### The coverage issue (for the advisor)

**One line:** `write_idempotent_rule` replaces the whole regex, and **nothing re-tests what the previous version of the rule was blocking.**

Why `verify_rule` misses it:
1. **Its replay set *is* the sample list**, which is capped (2 per seed / 20 per family, older ones evicted as new waves bypass), wiped by
   `reset_state.py`, and only fed by bypasses.
2. **A request the old rule blocks gets a 403, so it's never recorded again.** Once v1 works, the attacks it stops stop producing evidence.
3. So v2 can **drop some of v1's coverage and still PASS**, because the check only asks "does v2 cover the *current* evidence?"

| Check | Tests | Misses |
|---|---|---|
| `verify_rule` | current recorded bypasses + 12 benign | anything evicted or reset; earlier coverage |
| RGI (harness, Sprint 5) | unseen new variants | old payloads; new waves are fresh mutations |
| `read_current_rule` + "treat it as a floor" prompt | nothing, it relies on the LLM | enforcement |

→ **Nothing checks for regressions against earlier coverage.**

**Evidence:** rule 1000000 in the Sprint 4.5 transcript blocks `admin'#`, `admin@juice-sh.op&#x27--`, and ` OR '1''='1 `. The version committed
in `3638a3a` blocks none of them (tested offline with Python `re`). **Caveat:** I don't know whether the rule file was reset before that run.
If it was, Claude never saw the old rule. So the gap is confirmed in the design, but how often it happens isn't measured.

**Plan:** test first. Multi-wave run, no reset, save every rule version, re-test each new regex against *all* earlier bypasses. Fix only if
coverage drops. The most natural fix: a **permanent, uncapped replay list for `verify_rule`** (the agent's evidence stays capped for prompt
size), so lost coverage becomes a code-enforced FAIL instead of something I hope the LLM avoids. Open questions: replay time as it grows,
excluding harmless entries. Alternatives: stronger prompt, a per-rule "why each part exists" record, or new IDs instead of overwriting.

---

## Quiz

**Q1. A wave-marked `POST /rest/user/login` with body `{"email": "["}` gets a 401. What happens in each log path? Does it count toward the
threshold? Does the agent see it? Can `verify_rule` replay it?**
- **Corrected:** it **does** count. The access line has the marker and isn't a 403, so it's a bypass, and it's a POST, so there's no query payload
  to length-check. `bypass_counts` goes up by 1. That's the known gap.
- **Corrected:** the 401 is *why* it's a bypass (anything but 403), not why it can't be replayed.
- **Added:** the agent sees the bare access-log line (URI with marker, no payload). The audit entry has the body `"["`, the guard catches it
  (1 char), so the sample is never upgraded. `verify_rule` skips it as `not_replayable` because it's a POST with no body.

**Q2. Why does the defender's guard use length when the attacker's filter checks for attack tokens?**
- **Got right:** the attacker is checking its own output, so a token check is fine there.
- **Corrected:** the guard doesn't look at payload mechanics. It's deliberately content-blind (length only). The reason: a token check on the
  defender side would be signature matching, and it would drop the heavily obfuscated payloads the project exists to study. Analyzing what the
  payload does is the LLM's job, not the guard's.

**Q3. Why does `verify_rule` send benign requests to all three endpoints, and what line in `rule_writer.py` forces it?**
- **Got right:** to make sure the rule didn't break normal traffic anywhere, not just on login.
- **Didn't know the line:** `_RULE_TEMPLATE`, `SecRule REQUEST_COOKIES|ARGS ...`. It matches arguments on every request with no URL
  condition, so a "login" rule is live site-wide.

**Q4. Name two things PASS does not prove and what covers each.**
- **Got right:** earlier coverage (nothing yet; the permanent replay list would cover it) and generalization (RGI).
- **Added:** false-positive rate (12 requests is a sanity check; RFPR is the real metric) and `not_replayable` samples, which go untested
  without failing the verdict.

**Q5. Advisor rehearsal: why can a rewritten rule lose coverage and still pass, and what would you test first?**
- **Got right:** `verify_rule` only checks the current evidence, not what earlier versions of the rule covered.
- **Added the mechanism:** the replay list is capped, evicted, and reset, and a request the old rule blocks returns 403, so it never gets back into
  the list. **Added the plan:** multi-wave run with no reset, save every rule version, re-test each one against all earlier bypasses, and fix only
  if coverage drops.

---

## Questions I should be able to answer

1. **"What is MCP and why use it here?"** A standard client/server protocol for LLM tool calls. The agent sees 7 tools, not Docker or files, so the
   LLM or framework can be swapped without touching the server.
2. **"How does the LLM know what a tool does?"** The function's docstring and type hints become the tool description and schema.
3. **"What counts as a bypass?"** A wave-marked request that got anything but a 403, with at least 4 chars of real payload (GETs).
4. **"When does the agent get involved?"** When an endpoint reaches 5 cumulative bypasses. Blocks never count. The tally doesn't decay.
5. **"Why does the junk guard measure length?"** A keyword check would be signature matching and would drop the obfuscated payloads that matter most.
6. **"What does the agent actually see?"** Counts plus up to 20 samples per (endpoint, family), max 2 per seed, chosen for diversity, not recency.
7. **"Why can't the agent wipe its own rules?"** Reset is an operator script, not a tool. It would break RGI, and it's a destructive capability.
8. **"How is rule writing idempotent?"** One line per rule ID, overwritten in place. IDs are 7 digits so they can't hit CRS's range.
9. **"Why does a login rule affect the feedback endpoint?"** The template matches `ARGS` with no URL condition. Rules are site-wide.
10. **"What does `verify_rule` prove?"** That the live rule blocks the recorded bypasses and doesn't block 12 attack-looking benign requests.
    A fit check, not generalization (RGI) or a false-positive rate (RFPR).
11. **"Can `verify_rule` be abused to send traffic?"** No. The agent names an endpoint, and the server only replays its own logs plus a fixed set.
12. **"Can a rewritten rule lose protection?"** Yes, and nothing catches it yet. Confirmed in the design, frequency unmeasured, test planned before
    any fix.
13. **"What if the MCP server crashes mid-run?"** Offsets and tallies are checkpointed, so it resumes without double-counting or losing lines.

---

## What changed in the repo during this step
Docs and comments only; no behavior changed.

- `mcp-server/docs/Sprint3_Summary.md`: ⚠️ correction: 7 tools (`verify_rule` added in 4.5), `read_waf_logs` compacts by default and hides replays.
- `mcp-server/core/log_parser.py` (docstring only): threshold wording was ">5"; code is `>= 5`. Fixed to match.
- `mcp-server/server.py` (docstring only): no longer calls the agent "future"; transport note updated.
- `docs/code-review/README.md`: Step 4 marked done.

## Open items from this step
- **Coverage issue:** present to the advisor 2026-11-13 (section 6). Test before fixing; already on the post-review list.
- **Cumulative threshold → every pass re-reviews every endpoint that has ever tripped.** `agent.py` loops over all of `tripped_endpoints`,
  and an endpoint stays there until `reset_state.py`. So after wave 1 trips login and rule v1 fixes it, every later pass reworks login again
  using the same old samples (which v1 already blocks), even if wave N had zero login bypasses. Costs: wasted API calls, extra rewrites (each one
  another chance to lose coverage), and "tripped" can't mark when a breach started (MTTM). Harmless while the agent is run once by hand;
  matters once Sprint 5 auto-triggers it per wave. Options (undecided): trip on bypasses since the last rule for that endpoint; reset an
  endpoint's count after its rule passes `verify_rule`; have the harness compare counts before and after each wave. **Decided: fix before
  Sprint 5 runs, alongside the auto-trigger** (added to the README's post-review list).
- **`not_replayable` doesn't fail PASS.** A POST can only be replayed if the audit log added its body. That doesn't happen when (1) the body was
  junk (correctly skipped), (2) the audit log is missing or off, so *every* POST sample is skipped and only GETs get re-tested, or (3) the
  sample came from a state file saved before samples were structured. Case 2 is the one to watch: a PASS with a high `not_replayable` count
  means the login and Feedbacks attacks were never re-tested. **Decided: future improvement**, logged in
  `mcp-server/docs/future-improvements.md`.
