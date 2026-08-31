# Demo Walkthrough — Concept of Operations (MCP Defensive Server)

A rehearsable script for demoing Sprint 3 to the advisor: the defensive MCP server's five tools
(`read_waf_logs`, `get_breach_status`, `test_waf_configuration`, `write_idempotent_rule`,
`reload_waf`), exercised by hand through `mcp-server/demo_client.py` since Sprint 4's agent doesn't
exist yet. Written so you can run it yourself, alone, then repeat verbatim live.

## Scope — set this expectation up front with the advisor

This demo shows the MCP server's *mechanism* only — nothing here decides *when* to write a rule or
*what* it should say; that's Sprint 4's job. You're standing in for the not-yet-built agent, driving
`demo_client.py` by hand through the same five calls Sprint 4's agent will eventually make on its
own.

**Related:** `docs/demo-walkthrough.md` demos the offensive pipeline (Sprint 1-2) standalone. This
doc is written to run on its own too - see the two prereq options below for whether to combine them.

---

## Two ways to build up log entries first

`get_breach_status()` has nothing interesting to show until the WAF's error log has some blocked
requests in it. Pick based on what you're demoing:

- **Combined with the attacker pipeline** (shows the full loop: LLM mutation → fire → block →
  breach tracking → rule write - the strongest version of this demo): run Steps 1, 4, and 5 of
  `docs/demo-walkthrough.md` first (confirm the WAF is up, tail the log, fire a demo wave), then
  come back here and start at "Live walkthrough script" below. That wave is real breach data from
  the actual polymorphism pipeline, not synthetic requests.
- **MCP standalone** (no Ollama/LLM dependency, fastest to rehearse, useful if you're short on time
  or want to isolate Sprint 3 from Sprint 2): use the quick-fire prereq immediately below instead.

### Standalone quick-fire prereq (skip this if you already ran an attacker-pipeline wave)

```bash
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "status: %{http_code}\n" \
    "http://localhost:8080/rest/products/search?q=<script>alert($i)</script>"
done
```

Five requests against the same endpoint, comfortably past `BREACH_THRESHOLD` (default 5). This
trips CRS's default `REQUEST-949-BLOCKING-EVALUATION` catch-all rule on a textbook XSS payload -
fine for exercising the MCP mechanism, just not a demonstration of the offensive pipeline's actual
value (that's what the combined option above is for).

---

## Before the meeting — rehearse this once, alone tonight

1. **Confirm the WAF environment is up:**
   ```bash
   docker compose -f ~/capstone/waf-defense/docker-compose.yml ps
   ```
2. **Reset to a clean slate** so the demo's breach counts and rules aren't polluted by earlier
   poking around:
   ```bash
   cd ~/capstone/mcp-server && source .venv/bin/activate && python3 reset_state.py
   docker exec waf nginx -s reload
   ```
3. **Start the MCP server** in one pane (leave it running):
   ```bash
   cd ~/capstone/mcp-server && source .venv/bin/activate && python3 server.py
   ```
4. **Build up log entries** using one of the two options above.
5. **Do one full rehearsal of the live walkthrough below, start to finish, out loud**, as if the
   advisor were in the room. Time it.

---

## Live walkthrough script

Two terminal panes: one running `server.py` (already up from rehearsal step 3), one for
`demo_client.py` and the verification `curl` calls.

### Step 1 — Show the server is a standalone service (talking point: "Sprint 3 architecture")

Point at the `server.py` pane's `Uvicorn running on http://127.0.0.1:8000` line. *Say:* "This is a
standalone MCP server exposing five tools over streamable-HTTP - the same always-on local service
pattern as the WAF and Ollama. Sprint 4's agent will be a client of this exact server; this demo
script is a stand-in client for today."

### Step 2 — Build up breach history (if not already done)

Run the standalone quick-fire prereq, or point back at the already-completed attacker-pipeline wave
if combining demos.

### Step 3 — `get_breach_status()`: the tripwire

Start `demo_client.py`, pick option `2`, leave `endpoint` blank. *Say:* "This is the per-endpoint
breach tracker - not one of the proposal's original four tools, called out separately in the
Sprint 3 timeline as its own deliverable. It scans the WAF log incrementally and reports which
endpoints have crossed the threshold." Point at `/rest/products/search` showing up with a count at
or above 5 and appearing in `tripped_endpoints`.

### Step 4 — `read_waf_logs()`: what actually got logged

Option `1`. *Say:* "It just called `get_breach_status()` itself and defaulted `lines` to the total
blocked-request count, so nothing gets cut off even on a bigger wave than expected." Point at the
raw ModSecurity log lines - the matched rule file/id, the raw payload in the `request:` field.

### Step 5 — `write_idempotent_rule()`: write a custom rule

Option `4`. Use a synthetic, deterministic pattern rather than depending on which real payload
happens to be bypassing CRS at demo time - e.g. `rule_id=1000001`, `attack_pattern=demo-trigger-pattern`,
`description=demo rule`. *Say:* "In the real loop, Sprint 4's agent would pick this pattern from an
actual bypassed payload it just read; I'm picking it by hand today to keep the demo deterministic."

Prove it's *not* blocked yet:
```bash
curl -s -o /dev/null -w "status: %{http_code}\n" "http://localhost:8080/rest/products/search?q=demo-trigger-pattern"
```
Expect `status: 200`.

### Step 6 — `test_waf_configuration()` then `reload_waf()`

Options `3` then `5`. *Say:* "Testing before reloading is what caught a real bug during Sprint 3 -
an early rule template referenced a ModSecurity variable that doesn't actually exist. This step is
why that mistake never reached a live reload."

### Step 7 — Prove the new rule is live

```bash
curl -s -o /dev/null -w "status: %{http_code}\n" "http://localhost:8080/rest/products/search?q=demo-trigger-pattern"
```
Expect `status: 403` now. *Say:* "Same request, same endpoint - the only thing that changed is the
rule I just wrote and reloaded. This is the mechanical half of the self-healing loop; Sprint 4 is
about teaching an agent to drive these same five calls on its own, deciding when and what instead
of me picking the pattern by hand."

### Step 8 — Wrap-up talking points

- What's built: Sprint 3's five MCP tools plus per-endpoint breach tracking, all exercised above
  by hand through `demo_client.py`.
- What's next: Sprint 4 wires a LangGraph agent to poll `get_breach_status()` on its own schedule
  and make these same five calls automatically once a threshold trips - no more standing in for it
  by hand.
- If combined with the attacker-pipeline demo: point back at a bypassed payload from that run and
  note that a *real* Sprint 4-written rule would target that pattern, not the synthetic one used
  here for determinism.

---

## If something breaks live

- **Docker/WAF unreachable:** `docker compose -f ~/capstone/waf-defense/docker-compose.yml up -d`.
  If `docker` itself errors out (e.g. an `Input/output error` talking to the daemon), that's Docker
  Desktop's WSL integration on the Windows side, not this project - restart Docker Desktop.
- **Port 8000 already in use:** `ss -ltnp | grep 8000` to find the stale `server.py` process, kill
  it, restart.
- **Running low on time:** skip straight to Steps 5-7 with a freshly reset state; Steps 3-4 (breach
  tracking, log reading) are the least visually interesting part live and easy to narrate over a
  screenshot instead if needed.
