# Step 3 — Attacker pipeline

Code-review sprint, Step 3, the first in rapid mode. Chat held 2026-11-12.

**Source material:** everything in `attacker-pipeline/` (~1,200 lines), `docs/Sprint2_Summary.md`, the two debug
notes (skimmed), `docs/future-improvements.md`, and the baseline CSV `metrics/run_baseline_20260809_140007.csv`
(250 rows, Aug 9). I ran `analyze.py` and the current junk filter over it during the step.

**How this file is laid out:** the big picture, then each file in data-flow order (Tier A = explain cold, Tier B = one
line per function, Tier C = boundary answers), then problems found, the quiz, grader questions, and repo changes.

---

## Big picture

```
seeds.py ──(16 seeds)──► mutate.py ──(variants)──► orchestrator.build_wave ──(50 items)──►
fire.py ──(HTTP + _wave_marker)──► WAF :8080 ──► status code
   └── if 403: log_reader finds the marker in error.log → rule ID
metrics_writer ──► metrics/run_<ts>.csv ──► analyze.py → bypass_analysis.analyze()
```

- **Two layers.** `core/` (mutate, fire) is the attacker and doesn't know metrics exist. `harness/` does the measuring.
  `orchestrator.py` is the only file that imports both. I could swap the attacker without touching the measurement code, and the
  measurement can't change how the attack behaves.
- **The attacker doesn't learn.** Every wave sends the same 16 seeds and the same prompt to Llama. Nothing about what got
  through goes back in, so variation between waves is just sampling noise. Logged as a future improvement, since the advisor's
  "you get better, I get better" direction needs it.

---

## 1. `payloads/seeds.py`

Just data: 16 dicts, 8 SQLi and 8 XSS. Each seed has two halves:
- `type` and `payload` go to `mutate` (*what* to obfuscate).
- `method`, `endpoint`, `location`, `field`, `extra_fields` go to `fire` (*where* to put it).

| Target | Field | Families |
|---|---|---|
| `POST /rest/user/login` | JSON `email` | SQLi (login bypass) |
| `GET /rest/products/search?q=` | query `q` | SQLi, reflected XSS |
| `POST /api/Feedbacks` | JSON `comment` | stored XSS |

- `xss-01` (`<script>alert(1)</script>`) is a **known-answer control**. Sprint 1 proved by hand that it's blocked, so a bypass
  on it means something's wrong with the setup.
- The Feedbacks seeds send a fake captcha, so Juice Shop rejects them. That doesn't matter, because the WAF decides first.

**Boundary (C):** *Why these payloads?* They're textbook Juice Shop attacks on surfaces known to be vulnerable, so a bypass means something.

## 2. `core/mutate.py`

**Job:** one seed in, N variants out, from Llama-3 running locally on Ollama. It's local because cloud models refuse to write exploits.

**Flow:** prompt → `_safe_generate` → raw text → `_parse_variants` → dedup + junk filter → retry once if short → list.

Each design choice exists because the local 8B model actually did something wrong:

| Choice | Why |
|---|---|
| Three-tier parser: `json.loads` → pull out the first `[...]` and retry → split by lines | Llama often writes invalid JSON. Most of it is `\'`, which `_normalize_json_text` fixes. About 15% of baseline rows still went through line-split |
| 90s timeout + 1024-token cap | Llama sometimes looped for 25+ min / 9,000+ tokens. A timeout counts as an empty answer, so one bad call costs one attempt, not the run (Sprint 3 debug notes) |
| Junk filter (Sprint 4.5) | Line-split could leak a lone `[` or `]` as a "variant". See quiz Q3 for why that hurts the defender |
| One retry, not a loop | Ollama is the slowest part of the run |

**Line-split, plainly:** if both JSON attempts fail, it splits the raw text into lines, trims bullets/numbers/quotes, and treats
**each line as its own variant**. When the model puts `[` and `]` on their own lines, they become two "variants".

**Junk filter:** drops anything under 4 characters, or with no attack token for its family (quotes, comments, SQL keywords,
`<`, `on*=`, ... plain or encoded; also checked after URL-decoding). It's loose on purpose. It rejects non-attacks; it doesn't grade quality.

**It can return fewer *or more* than `n`.** It never trims down to `n`. That causes the seed-coverage problem in section 4.

**Functions (B):**
- `_is_valid_variant`: length check, then "has an attack token for this family".
- `_normalize_json_text`: strips markdown fences, turns `\'` into `'`.
- `_parse_variants`: the three-tier parser.
- `_safe_generate`: Ollama call with the token cap; timeout returns `""`.
- `generate_variants`: public entry point. Prompt, accept, retry once if short, print how many were rejected.

**Boundary (C):** *What exactly do the signal regexes match?* Lists of quote/comment/keyword/tag tokens in plain and encoded form,
in `_SQLI_SIGNALS` / `_XSS_SIGNALS`, tested in `tests/test_mutate_filter.py`.

## 3. `core/fire.py`

**Job:** send one request **through the WAF** (`localhost:8080`, never Juice Shop directly) and return the status code, send time, and
how long it took. Query seeds put the payload in a URL parameter; JSON seeds put it in the body, along with `extra_fields`.

**The marker always goes in the query string**, even on JSON POSTs. The access and error logs record the request line
(method, path, query string) but never the body. A marker in the body would never show up in the logs I count from.

**The defender depends on the marker.** The MCP server counts "marked request that didn't get a 403" as a bypass. So the defender
knows what's an attack because **the attacker labels it**. That's the lab's core simplifying assumption. A real attacker wouldn't
tag their requests, and production would need a real detection signal (`docs/sprint-4.6-direction.md` ~line 248).

**Functions (B):** `FireResult` is the return record. `send_payload` builds the URL, places the payload by `location`, and sends it
(10s timeout, one shared connection).

## 4. `harness/orchestrator.py`

**Per wave:**
1. Build the whole wave first (all the Ollama calls).
2. Fire the payloads one at a time.
3. A 403 counts as blocked, and only then ask `log_reader` for the rule ID.
4. Write one CSV row per payload.
5. Print the summary, then pause 60s.

The pause is there so a defender could patch between waves. Nothing runs in it today, because the agent isn't triggered
automatically (the parked auto-trigger, #5c).

**`build_wave`:** asks for `ceil(50/16) = 4` variants per seed, flattens **in seed order**, and keeps the first 50. Two problems:

| Seeds | Rows in baseline (5 waves) |
|---|---|
| sqli-01..08 | 15–26 each, 168 total |
| xss-01..04 | 16–24 each |
| xss-05 | **2** |
| xss-06, 07, 08 | **0, never fired** |

1. **Uneven coverage.** SQLi is first in the list, and Llama often returns more than 4 (indexes go up to 7), so the 50 slots are full
   before the last XSS seeds are reached. Only 13 seeds were ever fired, and only `xss-04` ever reached `/api/Feedbacks`.
2. **Wave size isn't guaranteed.** Llama can also return fewer than asked (junk dropped, one retry, timeout), so a wave could
   come up short. Every baseline wave happened to be 50.

**I'm fixing both before Sprint 5:** take variants round-robin across seeds (or shuffle the order), trim each seed to its share, and add
a capped top-up loop that asks for more when the wave is short, so junk gets *replaced* instead of just dropped. Fixing the wave size
removes one variable from α. Details: `attacker-pipeline/docs/future-improvements.md`.

**Functions (B):** `build_wave` turns seeds into 50 items with a `payload_id` like `w2-sqli-03-1`, which is also the marker. `run`
is the loop above, with `finally` closing the CSV even on a crash or Ctrl-C.

## 5. Metrics output: `harness/log_reader.py` + `harness/metrics_writer.py`

**`LogReader`:**
- Reads **`error.log`** only, which only has denied requests. That's why it's only called on 403s.
- Starts at the **end of the file**, so an old run can't produce a false match, and keeps a byte offset so it never rescans.
- Polls up to 1s, because ModSecurity writes the log line slightly after the response goes out.
- Every baseline block is `949110`, the CRS scoring rule (Step 2). A block by my own rule would show `1000000` instead. That's the RGI hook.

**CSV schema:** `wave_id, payload_id, attack_type, seed_payload, mutated_payload, endpoint, status_code, blocked, matched_rule_id, timestamp`
- `blocked` is **computed from** `status_code == 403` in the writer, so the two can't disagree.
- Each run gets its own file (`run_[label_]<timestamp>.csv`), so runs never mix. `--label demo` marks rehearsal runs.
- It flushes after every row, so a crash still leaves a readable partial CSV.

**Functions (B):**
- `find_matched_rule`: polling wrapper.
- `_scan_new_lines`: reads the new bytes, moves the offset forward, pulls out `[id "..."]`.
- `MetricsWriter.__init__`: opens a new file and writes the header.
- `append_row`: one row, then flush.
- `close`: closes the file.

**Boundary (C):** *Isn't "403 = blocked" a guess?* Juice Shop could send its own 403, which would be counted as blocked with an empty rule
ID. It never happened in my data: all 166 403s have `949110`.

## 6. `analyze.py` + `harness/bypass_analysis.py`

Offline analysis (Sprint 4.6). It reports the overall bypass rate, bypass rate per (family, endpoint), **lift** per obfuscation technique
(% of bypasses using it minus % of blocked payloads using it), and which seeds produce the most bypasses.
- It uses a difference, not a ratio, so a technique that never shows up among blocked payloads can't cause a divide-by-zero.
- It lives **only in the test harness** on purpose. Classifying traffic by what the payload looks like is the signature matching the
  project argues against, so it's never used as a live defense signal.

**Baseline results:**

| Group | Bypass |
|---|---|
| SQLi, login | 60.0% (60/100) |
| SQLi, search | 30.9% (21/68) |
| XSS, Feedbacks | 12.5% (2/16) |
| XSS, search | 1.5% (1/66) |

- Bypasses average 16 decoded characters, blocked payloads 56.
- `mixed_case_keyword` has lift −24.8pp; `inline_comment` has +4.2pp.
- Takeaway: short, plain tautologies get through, and fancy encoding gets caught. "Stronger attacks" means smarter logic, not more encoding.

**Functions (B):**
- `_FEATURES`: 8 one-line regex detectors.
- `_has_mixed_case_keyword`: catches things like `sElEcT`.
- `_decoded_len`: length after URL-decoding.
- `_is_bypass`: uses the `blocked` column, or status ≠ 403 for old CSVs.
- `analyze`: builds the report.
- `analyze.py`: loads the newest (or named) CSVs and prints.

**Boundary (C):** *Is lift statistically significant?* No. It's descriptive statistics over one 250-row run, and it can be confounded (quiz Q5).

---

## Problems found in this step

| # | Problem | What I decided |
|---|---|---|
| 1 | **The 33.6% baseline includes junk.** The Aug 9 run came before the timeout and junk filter. Today's filter rejects 13 rows, all counted as bypasses (mostly `[`/`]`). Without them: **71/237 = 30.0%** | New baseline in the Sprint 5 runs. Annotated in `Sprint2_Summary.md` |
| 2 | **Uneven seed coverage + wave size not guaranteed** (section 4). The `build_wave` docstring claims both are fine | Fix before Sprint 5; plan in `future-improvements.md` |
| 3 | `Sprint2_Summary.md` says 16 seeds; only 13 were fired | Annotated |
| 4 | `orchestrator.py` pause comment said "no defensive agent exists yet" | Updated: the agent exists, it just isn't auto-triggered |
| 5 | CLAUDE.md says metrics CSVs are gitignored, but the baseline CSV is in git | I force-added it on purpose on Aug 23 (`77a6802`) to back up the baseline. Fine as long as new CSVs aren't force-added |

---

## Quiz

**Q1. Why does `fire.py` put `_wave_marker` in the query string even on JSON POSTs? What does the MCP server lose without the marker?**
- **Didn't know the first part:** the access and error logs record the request line (method, path, query string) but never the body. A marker
  in the body would be invisible to the logs the bypass count comes from.
- **Got right:** the MCP server recognizes attack traffic by the marker.
- **Added:** without it, no request counts as a bypass, the threshold never trips, and the agent never acts, the same blind spot as a direct
  hit on Juice Shop in Step 2. It also means the defender relies on the attacker labeling itself, which is a lab simplification.

**Q2. With `WAVE_SIZE = 32`, how many variants per seed are requested, and which seeds get cut? How would you make coverage even?**
- **Corrected:** `ceil(32/16) = 2`, not 4. The last seeds in the list (the end of the XSS block) still get cut, because Llama often returns
  *more* than requested, so the early seeds fill the slots first.
- **Corrected:** the per-seed count already scales with wave size (that's the `ceil`). The fix is in *how they're combined*: trim each seed to
  its share and take them round-robin (or shuffle the seed order), so cutting to the wave size drops evenly.

**Q3. Line-split produces `[`, `' OR 1=1--`, and `]`. What happens to each, and why does dropping `[` matter to the defender?**
- **Didn't know this one.** Line-split makes each line its own variant, so these are three separate requests, not one string. `[` and `]` are under
  4 characters and get dropped. `' OR 1=1--` passes (has a quote, long enough) and gets fired. Before the filter, `[` would be fired, the WAF
  would rightly allow it, and the MCP server would count it as a **bypass**. That could trip the threshold on noise and hand the agent `[` as
  "evidence", and any rule that blocks `[` would break normal traffic.

**Q4. Why is `matched_rule_id` empty for bypasses? What does a row blocked by rule `1000000` show?**
- **Got right:** no rule blocked a bypass, and a row blocked by my rule shows `1000000`.
- **Added:** the mechanics: `log_reader` is only called on 403s, and the error log only has denied requests, so there's nothing to look up. A
  `1000000` row means CRS didn't reach the threshold and my rule did the blocking. If CRS also scored it high enough, `949110` would block it
  first (Step 2), and that's what keeps RGI honest.

**Q5. What does −24.8pp lift for `mixed_case_keyword` mean? Does it prove mixed case causes blocking?**
- **Got right:** it's associated with being blocked, it doesn't prove cause, and mixed case alone doesn't help get past the WAF.
- **Added:** there's a confounder. 47 of the 65 mixed-case rows are **XSS**, which almost always gets blocked anyway. Within login SQLi alone,
  mixed-case variants bypassed 7/12 (58%), about the same as that group's 60% overall. So it isn't hurting; it does nothing, which makes sense
  because CRS normalizes case before matching.

---

## Questions I should be able to answer

1. **"What does the attacker pipeline do, end to end?"** Seeds → Llama makes variants → fire through the WAF with a marker → 403 = blocked,
   look up the rule ID → one CSV row per payload → `analyze.py` reads the CSVs.
2. **"Why a local model for the attacker?"** Cloud models refuse to write exploits. Local also means zero cost and no data leaves the machine.
3. **"How do you handle bad LLM output?"** A three-tier parser, a junk filter (length + attack token), one retry, a 90s timeout and token cap.
4. **"How do you tell attack traffic from normal traffic?"** The `_wave_marker`. It's a lab simplification: the attacker labels itself, and
   production would need a real detection signal.
5. **"Why is the marker in the query string?"** The logs record the request line, never the body.
6. **"What counts as a bypass?"** Anything other than a 403, including 401/500. It means the WAF let it through, not that the attack worked.
7. **"What's your baseline bypass rate?"** 33.6% as recorded, 30.0% excluding 13 junk rows. A new baseline comes in the Sprint 5 runs.
8. **"Is the attack mix balanced?"** No. 168 SQLi / 82 XSS, and 3 XSS seeds never fired because of seed-order truncation. Being fixed.
9. **"Why does every block say 949110?"** Anomaly scoring: the scoring rule blocks, not the signature that matched. My rules show their own ID.
10. **"Does the attacker adapt?"** No, it's open-loop. Variation between waves is sampling noise. Adapting is a future improvement.
11. **"What gets through, and why?"** Short SQLi tautologies on the login JSON body (60%). Encoded XSS is almost all blocked. Lift is descriptive and confounded by family.
12. **"Why isn't the bypass analysis used as a defense?"** It classifies by what payloads look like, which is the signature matching the project argues against.

---

## What changed in the repo during this step
Docs plus one comment; no behavior changed. Nothing committed yet.

- `attacker-pipeline/docs/future-improvements.md`: added "Balanced seed coverage + guaranteed wave size" (planned fix) and "Attacker
  doesn't learn from results".
- `attacker-pipeline/docs/Sprint2_Summary.md`: ⚠️ annotations on the seed count (13 fired, not 16) and the 33.6% (30.0% without junk).
- `attacker-pipeline/harness/orchestrator.py` (comment only): the pause comment now says the agent exists but isn't auto-triggered.
- `docs/code-review/README.md`: Step 3 marked done; the seed-coverage fix and new baseline added to the post-review list.

## Open items from this step
- **Fix seed coverage + wave size** before Sprint 5 runs (my call, to cut variables).
- **Rerun the baseline** in Sprint 5 with the current filter, and quote that instead of 33.6%.
- **Attacker learning:** decide with the advisor whether α should measure a fixed attacker or a learning one.
