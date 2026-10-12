# Demo Walkthrough — Sprint 4.5 (Self-Verifying Defender)

A rehearsable script for showing the advisor what Sprint 4.5 accomplished (everything except the
VS Code linting cleanup, which isn't demo-worthy). Written so you can run it yourself first, then
repeat it live.

**The headline:** the defensive agent went from "write a rule and *hope* it works" to "write it,
**test it against real attacks and real benign traffic**, and revise itself when it's wrong." The
rest of the sprint is what makes that verification trustworthy.

**Related docs:** `docs/demo-walkthrough.md` (offensive pipeline, Sprint 1-2) and
`docs/demo-walkthrough-mcp.md` (MCP server mechanism, Sprint 3). This one is Sprint 4.5 and
assumes those pieces exist; it does not re-explain them.

---

## Scope — set this expectation up front

This demo is about *trust in the defender's output*, not raw capability. The key question it
answers for the advisor is: **"how do you know a rule the agent wrote actually works and didn't
break the site?"** Sprint 4 could write rules; Sprint 4.5 can now check them.

One honesty note to internalize before you present (and state if asked): a **PASS means the rule
covers the evidence it was written from — not that it generalizes to unseen variants.** That's
what Sprint 5's RGI metric is for. The agent says this itself in its own summary; don't oversell
it as proof of general correctness.

---

## The centerpiece: a captured FAIL → revise → PASS transcript (guaranteed)

The single most compelling moment is the agent **catching its own too-broad rule and fixing it**.
This happened on a real run (2026-10-09). **Use the saved verbatim transcript as the guaranteed
centerpiece** — it's deterministic and always available, no stack required:

> **`defensive-agent/docs/transcripts/sprint4.5-fail-revise-pass.txt`**

Open it in an editor or `cat` it on screen. (A prose summary of the same run is in
`defensive-agent/docs/Sprint4.5_Cleanup.md` under "Second agent run"; the transcript is the full
tool-by-tool output. One elision: the large `read_waf_logs` result is replaced by a one-line note
— it's 40 lines of repetitive CRS boilerplate and not load-bearing for the demo.)

Why the captured transcript and not only a live run: whether a *live* run produces a FAIL depends
on what rule the agent writes that run. A fresh rule often PASSes on the first try (also a fine
outcome to show); the FAIL → revise → PASS sequence reliably appears when an over-broad rule
already exists to be broadened. So treat a live run as a real-time *supplement*, and keep the
captured transcript as the thing you're guaranteed to be able to walk through.

**Walk the advisor through these four moments in the transcript:**

1. The agent reads the existing rule, then writes a broadened version.
2. **`verify_rule` returns `FAIL: 3 benign request(s) are now blocked`.** Stop here. This is the
   whole point: the agent's own rule was too aggressive (it blocked ordinary inputs like a product
   search `'apple'; juice` and a feedback comment `great 'service'; would buy again`), and the
   system *caught it before it could matter* — `nginx -t` had already said the config was fine.
3. The agent narrows the regex and re-verifies → **`PASS`** (7/7 recorded attacks still blocked,
   0/12 benign requests blocked).
4. Read its closing summary aloud: it states the trade-off it chose (slightly less attack coverage
   in exchange for not blocking benign traffic) and admits PASS means "covers the evidence," not
   "covers unseen variants."

That one sequence demonstrates the closed verification loop, the benign-traffic guard, and the
agent's honesty in a single artifact.

---

## Optional live run (real-time supplement)

If you want to show it happening live, here's the full sequence. **Rehearse it once beforehand** —
outcomes vary (see above), and it depends on the stack being up.

### Prerequisites

1. **Docker + WAF/Juice Shop up:**
   ```bash
   docker compose -f ~/capstone/waf-defense/docker-compose.yml up -d
   ```
   If `docker` errors out entirely, Docker Desktop's WSL integration is off on the Windows side —
   restart Docker Desktop.
2. **Ollama up** (the wave needs it for mutation): `systemctl status ollama`, and warm it once per
   `docs/common-commands.md` if it's been idle.
3. **`ANTHROPIC_API_KEY`** set in `defensive-agent/.env` (the agent needs it).
4. **Reset to a clean slate, then start the server** (order matters — the server captures log
   offsets at startup):
   ```bash
   cd ~/capstone/mcp-server && source .venv/bin/activate
   python3 reset_state.py && docker exec waf nginx -s reload
   python3 server.py          # leave running in this terminal
   ```

### Step 1 — Fire a wave, and point out the junk-mutation filter

In a second terminal:
```bash
cd ~/capstone/attacker-pipeline && source .venv/bin/activate
python3 run.py --waves 2 --wave-size 50 --pause 0 --label demo
```
As it runs, watch for lines like `[mutate] xss: dropped N degenerate variant(s) ...`. **Point
these out** — that's Sprint 4.5's validity filter discarding mangled model output (e.g. an XSS
payload llama-3 collapsed to a lone `[`) *before* it can be fired and miscounted as a WAF bypass.
Across the existing metrics CSVs that was ~4% of rows; left in, it inflates bypass counts and
corrupts Sprint 5's metrics.

### Step 2 — Show the evidence the agent will get (body capture + sample diversity)

```bash
# third terminal, or reuse the attacker one
cd ~/capstone/mcp-server && source .venv/bin/activate && python3 demo_client.py
# choose get_breach_status
```
Point at two things in `sample_bypasses` for `/rest/user/login`:
- **Real request bodies are visible** (e.g. `body: {"email": " OR 1=1;--", ...}`). Before Sprint
  4.5 these POST payloads weren't logged at all, so the agent was guessing from GET siblings.
- **The samples span several different seeds** (sqli-01, -02, -03, -08, across both waves), not 5
  near-identical ones from a single seed — so the agent designs against the real spread of
  mutations, not one accident of recency.

### Step 3 — Run the agent (the live centerpiece)

```bash
cd ~/capstone/defensive-agent && source .venv/bin/activate && python3 agent.py
```
Narrate the streamed steps: `read_current_rule → read_waf_logs → write → test → reload →
verify_rule`. The `verify_rule` result is the moment to focus on — PASS or FAIL, read out the
`attack_replay` and `benign_check` numbers. If it FAILs, watch it revise and re-verify (this is
the live version of the captured centerpiece).

At the very end, point at the **token-usage line**:
```
token usage over N model call(s): input=... (cache_read=..., cache_write=..., uncached=...), ...
```
`cache_read` being 75-89% of input is Sprint 4.5's prompt-caching fix working — it roughly halves
the per-run API cost. (Before this sprint, caching was believed configured but wasn't; the Console
showed zero cache activity.)

---

## Supporting points to narrate (no screen needed)

- **A real latent bug was found *by* this verification work.** Any `%` character in a rule's
  description silently broke the entire WAF configuration (ModSecurity treats `%` in `msg` as a
  macro). An agent describing URL-encoding evasions writes `%27`/`%2F` constantly, so this was a
  landmine it only survived by luck. Found by bisecting against the live `nginx -t`, fixed in
  `rule_writer`, and regression-tested. Good "the testing paid for itself" point.
- **Offline regression tests now exist** — 24 tests across `mcp-server/tests/` and
  `attacker-pipeline/tests/`, runnable with no WAF/Docker/network (see `docs/common-commands.md`).
- **A known-limitations register** lives at the end of `defensive-agent/docs/Sprint4.5_Cleanup.md`
  — worth showing him directly as evidence you track what the work does and doesn't prove.

---

## Two questions to put to the advisor (this is what the meeting is for)

Frame these as open Sprint 5 decisions that need his judgment:

1. **Metric attribution.** Custom rules load *after* CRS's blocking evaluation, so most 403s are
   CRS's block, not the agent's. MTTM and the bypass-decay rate (α) must credit the rule that
   *actually denied* the request (recorded in `matched_rule_id`), or the agent will look more
   effective than it is. How strict should that attribution be?
2. **RFPR independence.** The small benign set the agent iterates against during `verify_rule`
   cannot also be the set that grades its false-positive rate — that would be grading against the
   training target. Sprint 5 needs a fresh, held-out benign corpus (the proposal says 50-100
   requests). Is there traffic he'd want represented in it?
3. **When to move into report/presentation preparation** (when to make sure I commence testing follows from this)

---

## If something breaks live

- **Docker/WAF unreachable:** `docker compose -f ~/capstone/waf-defense/docker-compose.yml up -d`;
  if `docker` itself errors, restart Docker Desktop (WSL integration).
- **Port 8000 in use:** `ss -ltnp | grep 8000`, kill the stale `server.py`, restart.
- **Agent errors on a tool name** (e.g. `verify_rule` not found): the running `server.py` predates
  the tool — restart it (it loads tools at startup).
- **Low on time, or the live run misbehaves:** fall back to the saved FAIL → revise → PASS
  transcript at `defensive-agent/docs/transcripts/sprint4.5-fail-revise-pass.txt`. It makes every
  point above with zero setup risk — this is the recommended default if you're not confident the
  stack is warm.
