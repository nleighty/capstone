# Demo Walkthrough — Concept of Operations (Attacker Pipeline)

A rehearsable script for demoing Sprint 1 + Sprint 2 to the advisor: the Docker WAF environment and
the offensive pipeline (local LLM payload mutation → fire at WAF → block/bypass → log correlation).
Written so you can run it yourself, alone, then repeat verbatim live. No AI execution involved —
every command below is one you type.

## Scope — set this expectation up front with the advisor

This demo shows the **offensive side only** (proposal timeline items 1-2). There is no defensive
agent yet (that's Sprint 3-4 — the MCP server and LangGraph agent don't exist yet), so every payload
you fire either gets blocked by the *existing* default ModSecurity/CRS ruleset or bypasses it — you
won't see the WAF learn or adapt during the demo. That's expected, not a gap: this demo is showing
"the attack half of the loop works," not the full self-healing story yet.

## Metrics note — this run does not touch the official baseline data

Sprint 2's real baseline capture is already recorded (`attacker-pipeline/metrics/run_20260809_140007.csv`
— 250 payloads, 5 waves, the numbers in `attacker-pipeline/docs/Sprint2_Summary.md`). The demo run
below uses `--label demo`, which names its output `run_demo_<timestamp>.csv` — visually and
filterably distinct from the unlabeled baseline files, so nothing from tomorrow's demo (or tonight's
rehearsal) gets mistaken for or mixed into the thesis's metrics later.

---

## Before the meeting — rehearse this once, alone tonight

1. **Confirm the WAF environment is up:**
   ```bash
   docker compose -f ~/capstone/waf-defense/docker-compose.yml ps
   ```
   Expect both `juice-shop` and `waf` as `Up`/`healthy`. If not: `docker compose -f ~/capstone/waf-defense/docker-compose.yml up -d`.

2. **Confirm Ollama is running and llama3 is loaded:**
   ```bash
   curl -s http://localhost:11434/api/tags
   ```
   Expect `llama3` in the JSON response. Ollama runs as a systemd service (`ollama.service`) and
   auto-starts with WSL, so this should already be up; if not, `sudo systemctl start ollama` (see
   `docs/common-commands.md`'s Ollama section).

3. **Warm up the model once** (the first generation call after Ollama starts loads the model into
   memory and is noticeably slower — do this now so the live demo's first LLM call isn't an awkward
   pause):
   ```bash
   curl -s http://localhost:11434/api/generate -d '{"model":"llama3","prompt":"hello","stream":false}'
   ```

4. **Do one full rehearsal of the live walkthrough below, start to finish, out loud**, as if the
   advisor were in the room. Time it.

---

## Live walkthrough script

Open two terminal panes in VS Code (`` Ctrl+` `` then split), plus the seed/core/harness files open
in the editor for reference.

### Step 1 — Show the target + WAF are up (talking point: "Sprint 1 environment")

```bash
docker compose -f ~/capstone/waf-defense/docker-compose.yml ps
```
*Say:* "Juice Shop is the deliberately vulnerable target; it's not directly reachable — all traffic
has to go through this Nginx/ModSecurity reverse proxy on port 8080, which is what makes this a WAF
defense project and not just an attack script."

### Step 2 — Prove the WAF blocks a naive, well-known payload manually

```bash
curl -s -o /dev/null -w "status: %{http_code}\n" "http://localhost:8080/rest/products/search?q=<script>alert(1)</script>"
```
Expect `status: 403`. *Say:* "This is a textbook XSS payload — CRS's default signature set already
catches this. The interesting question is what happens once the payload doesn't look textbook
anymore."

### Step 3 — Show the seed payloads and the LLM mutation code (in the editor, no execution)

Open `attacker-pipeline/payloads/seeds.py` — point at one SQLi and one XSS seed, and the real Juice
Shop endpoint/field each targets. Then open `attacker-pipeline/core/mutate.py`'s
`generate_variants()` — *say:* "This is the proposal's 'local LLM obfuscates payloads into
polymorphic variants' step — it's llama3 running entirely on this machine, no cloud API calls."

### Step 4 — Start tailing the WAF log in the second pane (leave this running)

```bash
tail -f ~/capstone/waf-defense/logs/error.log
```
*Say:* "I'll fire attacks in the other pane — watch this one for the block lines appearing live."

### Step 5 — Run the demo wave

In the first pane:
```bash
cd ~/capstone/attacker-pipeline
source .venv/bin/activate
python run.py --waves 1 --label demo
```
This runs one full wave (all 16 seeds, ~50 mutated payloads) against the live WAF — takes a couple
of minutes, dominated by the 16 real LLM calls (one per seed). *Say, while it runs:* "Each of these
is a real call to the local model generating novel obfuscated variants right now — this isn't
canned data." Point at the second pane as block lines scroll by.

When it finishes, it prints a per-wave summary line and the CSV path, e.g.:
```
wave 1: 14/50 bypassed, 36/50 blocked
metrics written to /home/nicle/capstone/attacker-pipeline/metrics/run_demo_20260810_...csv
```

### Step 6 — Look at a bypass and a block side by side

*Say:* "This blocked row shows exactly which ModSecurity rule caught it — that correlation is what
Sprint 3's defensive agent will read to decide what rule to write next. This bypassed row is the
polymorphism problem in one line: same underlying attack, different surface form, and the static
signature-based ruleset just... didn't recognize it."

### Step 7 — Wrap-up talking points

- What's built: Sprint 1 (WAF+target+logging), Sprint 2 (this pipeline — LLM mutation, firing,
  wave orchestration, block/bypass + rule-ID metrics).
- What's next: Sprint 3 (MCP server exposing `read_waf_logs`/`write_idempotent_rule`/etc.),
  Sprint 4 (LangGraph defensive agent wired to those tools), Sprint 5 (multi-wave loops measuring
  MTTM/Bypass Decay Rate/RGI/RFPR against a WAF that's actually adapting).
- Today's numbers are illustrative (demo-labeled); the actual Sprint 2 baseline — 250 payloads
  across 5 waves, 66% blocked / 34% bypassed — is already recorded and written up in
  `attacker-pipeline/docs/Sprint2_Summary.md`.

---

## If something breaks live

- **Container down:** `docker compose -f ~/capstone/waf-defense/docker-compose.yml up -d`, wait ~10s.
- **Ollama not responding:** check `curl localhost:11434/api/tags`; `sudo systemctl restart ollama`
  if needed.
- **Running low on time:** skip Step 5's live run — instead show the *already-generated* demo CSV
  from tonight's rehearsal and Step 4's log tail as a recording of what just happened, and narrate
  Step 6/7 against that. Rehearsing tonight is exactly what makes this fallback available.
