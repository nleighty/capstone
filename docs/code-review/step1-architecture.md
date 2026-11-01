# Step 1 — Concept & Architecture

Code-review sprint, Step 1. Chat held 2026-10-29 → 2026-10-31.

**Source material:** `docs/proposal/Proposal_20261004.pdf` + `diagram_20261004.png` (the current
versions; the July files are just history), `docs/design-notes.md`, `docs/meeting-notes.md`, plus
spot-checks of the code where the proposal and what got built don't match.

**How this file is laid out:** each part has a short explanation, then the quiz questions. Under each
question is what I got right and what got added or corrected. The end has a list of questions a
grader will probably ask, with short answers.

---

## Part 1 — The problem

### Concepts
- **HTTP request** — method, path, query parameters, headers/cookies, body. The sender picks all
  of it, so an attacker controls all of it.
- **Injection** — the app pastes user input into something that gets *run*.
  - **SQLi:** `SELECT * FROM Users WHERE email = '<input>' AND password = '...'`. Input
    `' OR 1=1--` turns it into `... email = '' OR 1=1--' AND password = ...`.
  - **XSS:** input like `<script>alert(1)</script>` gets shown back on a page without escaping, so
    the *victim's* browser runs the attacker's JavaScript.
  - The real fix is in the app itself (parameterized queries, escaping output).
- **WAF (Web Application Firewall)** — a **reverse proxy** in front of the app. It checks each
  request and either forwards it or blocks it (usually with a `403`). It doesn't fix the app, it
  filters what gets to it ("virtual patching").
- **The stack here:** Nginx (proxy) + ModSecurity (WAF engine) + OWASP **CRS** (Core Rule Set — a
  big set of mostly regex **signatures**).
- **Polymorphism** — same attack, different spelling: `' OR 1=1--` → `'/**/oR/**/2>1--`;
  `<script>alert(1)</script>` → `<svg onload=alert(1)>`. Signatures match text, not meaning.
- **Thesis:** LLMs make mutating attacks cheap, creative, and fast. Manual rule updates can't keep
  up, so the defender needs to be automated too. The October revision adds that attacker and
  defender are **different models** (local Llama-3 vs. Claude), so "the defender caught the attacker"
  isn't just one model agreeing with itself.

### Quiz
**Q1. Walk through `' OR 1=1--` piece by piece.**
- **Got right:** the `'` closes out the string, so `OR 1=1` gets read as raw SQL and the query is
  always true, which allows a login.
- **Added:** `--` starts a SQL comment, so everything after it is ignored. That gets rid of the app's
  leftover `'` (which would otherwise break the query) and the `AND password = ...` check. The full
  chain is break out → always true → cut off the rest. The query returns every user, and the app logs
  in as the first one (admin in Juice Shop).

**Q2. If the WAF were perfect, would Juice Shop still be vulnerable?**
- **Got right:** yes. Juice Shop is vulnerable at the app level, and the WAF just keeps those
  vulnerabilities from being exploited by blocking attacks before they reach the endpoints.
- **Added:** since the app really is vulnerable, a bypass is a real compromise. That's why bypass
  count is the core measurement.

**Q3. Why do regex signatures struggle with mutated payloads?**
- **Got right:** the regex might not account for the mutated version, so it gets through even if the
  plain version is blocked.
- **Added:** a regex matches text, not meaning. There are endless ways to spell an attack and only so
  many patterns. The defender has this same problem, which is what RGI measures.

**Q4. Why use a different LLM on each side?**
- **Got right:** the attacker is local so cloud guardrails don't block it from making attacks. A
  different defensive model keeps the two sides independent, and one might catch what the other
  missed.
- **Added:** local models do have *some* safety tuning, but it's weaker and under my control (cloud
  guardrails are enforced on their servers). "One catches what the other misses" is the reason for the
  design, not a measured result, so I should present it that way.

---

## Part 2 — The pieces and how a request moves

### Two zones (see `diagram_20261004.png`)
- **WSL2 host** — the Python scripts (attacker, MCP server, defensive agent) and Ollama run here.
- **Docker** (`waf-defense/docker-compose.yml`) — two containers, `juice-shop` and `waf`, on a
  private network called `waf-net`.

### Arrow colors
| Color | Meaning | Connects |
|---|---|---|
| Red | Attack traffic | attacker → WAF → Juice Shop |
| Black | LLM calls | attacker ↔ Ollama (`localhost:11434`); agent ↔ Claude (internet) |
| Blue | Defensive control | agent ↔ MCP server ↔ WAF |

### One attack request
1. A seed payload comes from `attacker-pipeline/payloads/seeds.py`.
2. Ollama/Llama-3 mutates it.
3. `fire.py` sends it to `localhost:8080`, tagged with a `_wave_marker` query param.
4. Port 8080 is the **only** way in. Docker forwards it to the `waf` container (Nginx + ModSecurity +
   CRS + custom rules).
5. Blocked → `403`. Allowed → it goes on to `juice-shop:3000` over the private network, and the
   status isn't 403.
6. Logs (`access.log`, `error.log`, `modsec_audit.log`) go to a **bind-mounted** folder, meaning
   the same folder shows up in the container and on the host at `waf-defense/logs/`.

### Defensive side
The MCP server reads those logs and counts bypasses per endpoint → the agent (an MCP client) calls
the tools and Claude designs a rule → the MCP server writes
`waf-defense/modsec-rules/ai_generated_rules.conf` (also bind-mounted) → tests the config →
reloads. The WAF↔MCP "arrow" is really **shared files + `docker exec`**, not a network connection.

### Quiz
**Q1. Which arrow goes out to the internet, and why is that OK for the defender but not the attacker?**
- **Got right:** agent → Claude. It's fine because the defense uses a cloud LLM and the attacker uses
  a local one, for the reasons from Part 1.
- **Added:** what leaves the machine is log excerpts (including the payloads) plus draft rules, which
  is part of the trust model in `SECURITY.md`. Claude is only called **after a threshold trips**,
  never per request, so normal traffic never waits on an LLM.

**Q2. Why does Juice Shop have no host port?**
- **Got right:** all traffic has to go through the WAF. If an attacker could reach Juice Shop
  directly, it would defeat the point of the WAF and the project.
- **Added:** the real-world version of this mistake is **origin exposure**, where attackers find the
  server's real IP and skip the cloud WAF entirely.

**Q3. How does the defender tell (a) an attack from normal traffic and (b) a bypass from a block?**
- **Got right:** (b) a block is a 403 and a bypass isn't.
- **Corrected:** for (a), WAF rules only decide block or allow. They can't tell an attacker from a
  normal user. **`_wave_marker` is the whole answer:** only `fire.py` adds it, and the MCP server only
  counts tagged access-log lines. Tagged + not 403 = bypass. A bypass is *any* non-403, including
  401/500 (`design-notes.md` lines 24–34).
- **Own this as a lab shortcut:** a real attacker won't tag their traffic. In the lab the marker gives
  exact ground truth, and detecting bypasses in production is out of scope.

**Q4. What two things are bind-mounted, and why does each need to be?**
- **Got right:** the logs, because the WAF is in Docker but the thing reading the logs isn't.
- **Added:** that's the MCP *server*, not the client. The rules file is shared because the MCP
  server on the host *writes* the rule and the WAF in the container has to *load* it; the bind mount
  is how it gets there. Inside the container it's mounted as
  `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` (`docker-compose.yml` line 41), a filename CRS
  already loads, so nobody has to edit the main config ("Scoped Inclusion", covered in Step 2). Nginx
  still needs a reload because it only reads config at startup or reload.

---

## Part 3 — The defensive loop and MCP

### Concepts
- **Tool calling:** an LLM only outputs text. Code gives it a list of tools (name, description,
  parameters), the model replies "call X with Y", the code runs it and sends the result back.
- **MCP (Model Context Protocol):** an open standard (Anthropic, late 2024). An **MCP server** lists
  tools, and any **MCP client** can discover them (`tools/list`) and call them (`tools/call`) using
  **JSON-RPC** ("call function X with these arguments" written as JSON). Here it runs over HTTP on
  `127.0.0.1:8000`, loopback-only. Think of it as "USB for AI tools".
- **What MCP gives this project:** (1) the model can be swapped (going from Llama-3 to Claude didn't
  touch `mcp-server/`); (2) a narrow boundary, since the tool list *is* everything the agent is
  allowed to do.

### Tools: 4 proposed → 7 built
| Tool | Purpose | Proposed? |
|---|---|---|
| `read_waf_logs` | recent log lines | yes |
| `get_breach_status` | bypass counts per endpoint, tripped endpoints (≥ 5), sample payloads | added |
| `read_current_rule` | what's already written for a rule_id | added |
| `write_idempotent_rule` | write or overwrite by rule_id | yes |
| `test_waf_configuration` | `nginx -t` in the container | yes |
| `reload_waf` | `nginx -s reload` | yes |
| `verify_rule` | replay recorded bypasses + a small benign set | added (4.5) |

### One run (`defensive-agent/agent.py`)
1. I start it by hand. It does a single pass, with no polling.
2. **Code** calls `get_breach_status` (lines 54–56).
3. **Code** assigns the `rule_id` through `RuleRegistry` (line 66); the same endpoint always gets
   the same ID.
4. Claude gets the endpoint, the rule ID, and samples, then runs a **ReAct** loop (think → call a
   tool → look at the result → repeat; LangGraph runs the loop): write → test → reload → verify →
   revise if it fails.
5. Exit.

**Design principle:** plain code handles everything that has to be repeatable (detection, IDs). The
LLM only decides **what the rule says**. **Idempotent** means doing something twice gives the same
result as doing it once.

### Quiz
**Q1. What does MCP give you vs. plain functions plus a direct Claude API call?**
- **Got right:** both points. It's modular across LLMs because it's standardized, like a USB port,
  and it's more secure because only specific tools are exposed to the agent.
- **Added:** a good way to say it on a slide: "the tool list is the agent's entire set of permissions."

**Q2. Why does code assign `rule_id` instead of Claude?**
- **Didn't know this one.**
- **Answer:** `write_idempotent_rule` overwrites **by ID**. If Claude picked the IDs, run 2 might
  pick a different number (it doesn't remember run 1), so the overwrite finds nothing and **appends**
  instead. After 10 runs there could be 10 overlapping or contradictory rules for one endpoint, and two
  endpoints could land on the same ID and silently wipe out each other's rules. `RuleRegistry` stores
  endpoint → ID on disk (`defensive-agent/state/`), so the guarantee comes from code instead of hoping
  the LLM is consistent. That's what "static rule IDs for idempotency" means in the proposal.

**Q3. Why test before reload?**
- **Got right:** so a config that would break the WAF doesn't get loaded.
- **Added:** `nginx -s reload` actually refuses a broken config on its own and keeps the old one. The
  real problem is that the broken rule is **already saved to disk**, so the **next container restart
  fails** and the whole site goes down (there's no way around the WAF). Also, the test-then-reload
  order is **only suggested in the tool docstrings, not enforced**; `reload_waf` doesn't run the test
  itself (`mcp-server/server.py` lines 118–126). Something to discuss in Step 4, not something to
  change.

**Q4. What does each half of `verify_rule` catch?**
- **Got right:** the recorded bypasses check that they're now blocked, and the benign traffic checks
  that it still gets through.
- **Added:** the replayed bypasses are the same ones Claude saw while writing the rule, so a PASS
  means the rule **fits** its evidence, not that it **generalizes** (`rule_verifier.py` lines 35–41).

**Q5. Since a person starts the agent, which claim gets weaker, and which metric can't be measured
honestly yet?**
- **Got right:** the automation claim ("autonomous" / "self-healing" / "continuous") and MTTM. The
  time gap would include how long it took me to start the agent.
- **Corrected:** RFPR isn't affected, because it's measured after any reload no matter what triggered
  it.

---

## Part 4 — The four metrics

A **wave** is 50 mutated payloads (W₁, W₂, …). The metrics are measured by a separate **test
harness**.

| Metric | Formula | Question | Good = |
|---|---|---|---|
| **MTTM** | T_deploy − T_threshold | How fast is a fix live after a threshold trips? | lower, and dropping over waves |
| **α** | (B(Wₙ) − B(Wₙ₋₁)) / B(Wₙ₋₁) | Are bypasses shrinking from wave to wave? | negative |
| **RGI** | unseen variants blocked by earlier custom rules ÷ total unseen × 100 | Did the rule learn the *pattern* or just the *spelling*? | high |
| **RFPR** | benign blocked ÷ benign sent × 100 | Did the fix break normal traffic? | 0% |

Notes and gotchas:
- **α** — It divides by zero once a wave
  has 0 bypasses. It's called "exponential" but it's really just a percentage change. Every wave is a
  new random batch, so some of α comes from easier or harder waves, not the defense.
- **RGI** — a block is credited to a custom rule by its ID range (custom 1000000–1999999 vs. CRS
  900000–999999).
- **RFPR** — the proposal says 100 tricky benign requests after every reload. `verify_rule`'s own
  benign set (about 12 requests, `rule_verifier.py` lines 62–86, e.g. `o'brien@example.com`, "salt
  and pepper or sugar, select one") is kept **separate** on purpose, so the agent isn't graded on
  the same requests it practiced against.
- **Status:** the Sprint 2 baseline is 250 payloads with **33.6%** getting past stock CRS. The
  `verify_rule` FAIL→revise→PASS runs exist. **There are no multi-wave MTTM/α/RGI/RFPR numbers yet**
  (Sprint 5, paused).

### Quiz
**Q1. Why do RGI and RFPR pull against each other?**
- **Got right:** a very general rule blocks more future variations but is more likely to block normal
  traffic too, so you need a balance.
- **Added:** examples: an exact-string rule gets RFPR 0% but RGI ≈ 0%; "block any `'`" gets high
  RGI and high RFPR. The goal is a rule aimed at the attack's **structure** (e.g. a quote followed by
  a logic operator and a comparison).

**Q2. Wave 3 has 8 bypasses and wave 4 has 10. What's α?**
- **Got right:** divided by the right wave (2/8 = ¼).
- **Corrected:** the sign. α = (10 − 8) / 8 = **+0.25**, which is a 25% **increase** (worse, or just
  a harder wave), not a reduction. Rule: new minus old; if it went up, it's positive, and positive is
  bad.

**Q3. Why does the harness need to be a separate layer?**
- **Got right:** it acts as an independent third-party reviewer of the system.
- **Corrected:** "white box" was the wrong term. It's closer to a **black box**: it tests from the
  outside without relying on the system's internals (white box means testing *with* knowledge of the
  internals). The reasons: a system shouldn't grade itself, since a bug could mess up both the behavior
  and the measurement; experiment code stays out of the security code (`design-notes.md` lines
  65–83); and the same ruler works if the defender model gets swapped.

**Q4. Why doesn't passing `verify_rule` prove RGI?**
- **Got right:** the idea that the harness has its own separate test set, but that's the reason for
  RFPR.
- **Corrected:** for RGI the key word is **unseen**. `verify_rule` replays the bypasses the rule was
  written from, while RGI measures *new* mutations in the next wave. Slide line: "verify_rule shows
  the rule fits its evidence; RGI shows it generalizes."

---

## Part 5 — Proposal vs. what was built

| # | Proposal / diagram | What the code actually does | Talking point |
|---|---|---|---|
| 1 | MCP server inside Docker | Runs **on the WSL2 host**, `127.0.0.1:8000` | It needs direct access to the bind-mounted files and the `docker` command. *(Claude's guess — not written down anywhere in the repo:* inside a container it would need the Docker socket mounted, which is basically root on the host.) |
| 2 | WAF ↔ MCP drawn as a network arrow | Bind-mounted files (logs, rules) + `docker exec` | The diagram is conceptual; the arrow means "controls". |
| 3 | "FastMCP from FastAPI" / "FastAPI-MCP" | Official `mcp` SDK v2, class `MCPServer` (`server.py` lines 6–9) | The proposal mixes up two libraries. |
| 4 | 4 tools | 7 tools | Improvement, especially `verify_rule`. |
| 5 | Per-endpoint threshold is the goal, global count is the MVP | **Per-endpoint built** (threshold 5) | Went past the MVP. |
| 6 | "Autonomous", "continuous closed loop" | **Single pass, started by hand**; auto-trigger parked | Biggest gap between what's claimed and what's built; blocks an honest MTTM. |
| 7 | Four metrics across waves | Only the baseline + `verify_rule` | Sprint 5; see the 2026-10-30 advisor notes. |

**Leftovers in the October proposal:** the Ollama box still says "could be modified to use
separate LLMs" (they already are separate); Resource Requirements still says "$0.00" and that
Claude "would entail additional cost", while page 3 crosses out "zero financial cost"; it still
says "FastAPI-MCP". **Decision (2026-10-31): leaving these alone for now.** It's a proposal, not the
final report, so I may fix it later. If it comes up: "the proposal came before some implementation
decisions; here's what was actually built."

### Quiz
**Q1. A grader asks, "Your MCP server is in Docker, right?"**
- **Got right:** no, it runs outside Docker directly on WSL, and the rules file is bind-mounted so
  both the MCP server and the firewall can get to it.
- **Added:** the logs are shared the same way, and test/reload go through `docker exec`.

**Q2. Which difference hurts the headline claim the most?**
- **Got right:** #6. It undercuts the practical point of the project, and MTTM can't be measured
  without it running on its own.
- **Added:** "autonomous / self-healing / continuous" are right in the abstract, so it's better to
  bring this up myself. Whether to build the auto-trigger is my call after the review.

**Q3. Which difference is an improvement worth pointing out?**
- **Got right:** there are more MCP tools than proposed.
- **Added:** lead with `verify_rule` (the rule checks itself). Per-endpoint tracking going past the
  MVP (#5) is another one.

---

## Be ready for these grader questions

1. **"Isn't a WAF just a band-aid?"** — Yes, on purpose: it's virtual patching for when the app can't
   be fixed quickly. The real fix is in the app (parameterized queries/escaping).
2. **"How do you know a request was an attack?"** — `_wave_marker`, which only the attacker pipeline
   sets. It's a lab shortcut for ground truth; detecting bypasses in production is out of scope.
3. **"Why Claude for defense but not offense?"** — It keeps the two models independent, and cloud
   guardrails block making exploits but not writing rules.
4. **"What does MCP actually get you?"** — A swappable model (proven by the Llama → Claude swap with
   no server changes) and a small, auditable set of permissions.
5. **"What stops the LLM from messing up rule IDs?"** — It never picks them; `RuleRegistry` does.
6. **"Does passing `verify_rule` mean the rule generalizes?"** — No, it's a fit check. RGI (Sprint 5)
   measures generalization on unseen variants.
7. **"Is it really autonomous?"** — Not yet. The agent is a single pass started by hand, and the
   auto-trigger is parked. Say this before they ask.
8. **"What's α if bypasses go from 8 to 10?"** — +0.25. Positive is worse.

## Open items from this step
- **Advisor direction on evaluation** — recorded in `docs/meeting-notes.md` (2026-10-30). There
  wasn't a direct answer on how much evaluation is expected; the emphasis was on demonstrating
  functionality first, then performance, with iterative attacker/defender rounds. My takeaway:
  automating the MCP client/agent (difference #6 above) is the important building block.
- **Proposal leftovers** — leaving them for now (see Part 5).
- **Test-before-reload is only advisory** — bring it up in Step 4 as a design discussion; no change
  planned.
