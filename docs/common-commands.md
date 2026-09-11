# Common Commands

Day-to-day operation reference for the WAF environment, Ollama, and the attacker pipeline. For the
narrated advisor-demo script, see `docs/demo-walkthrough.md`; for what each piece actually is, see
`waf-defense/docs/Sprint1_Summary.md` and `attacker-pipeline/docs/Sprint2_Summary.md`.

## Docker (WAF + Juice Shop)

Start:
```bash
docker compose -f ~/capstone/waf-defense/docker-compose.yml up -d
```
Status:
```bash
docker compose -f ~/capstone/waf-defense/docker-compose.yml ps
```
Stop, keeping containers (short break):
```bash
docker compose -f ~/capstone/waf-defense/docker-compose.yml stop
```
Resume stopped containers:
```bash
docker compose -f ~/capstone/waf-defense/docker-compose.yml start
```
Full teardown / clean slate (removes containers + network, not images — next `up -d` is still fast):
```bash
docker compose -f ~/capstone/waf-defense/docker-compose.yml down
```
Tail the live WAF log:
```bash
tail -f ~/capstone/waf-defense/logs/error.log
```
Manual known-payload sanity check (expect `403`):
```bash
curl -s -o /dev/null -w "status: %{http_code}\n" "http://localhost:8080/rest/products/search?q=<script>alert(1)</script>"
```
Clear the log files (fresh start — e.g. before a rehearsal, so `tail -f` output isn't cluttered
with old runs; requires `sudo` since the container writes these as root via the bind mount).
Running `mcp-server/reset_state.py` also works for this, and is the preferred method.:
```bash
sudo truncate -s 0 /home/nicle/capstone/waf-defense/logs/access.log /home/nicle/capstone/waf-defense/logs/error.log
```

## Ollama

Installed via the official installer as a systemd service (`ollama.service`), backed by
`/usr/local/bin/ollama` — see `attacker-pipeline/docs/debug-notes-sprint2-log-granularity.md` for
the migration history (this WSL2 distro needed systemd enabled via `/etc/wsl.conf` first, since it
had none). The service is enabled, so it starts automatically whenever this WSL distro boots — no
manual `ollama serve` step needed day-to-day.

Status:
```bash
systemctl status ollama
```
Start / stop / restart (rarely needed — it's already running):
```bash
sudo systemctl start ollama
sudo systemctl stop ollama
sudo systemctl restart ollama
```
Tail the service log:
```bash
journalctl -u ollama -f
```
Confirm it's up and `llama3` is loaded:
```bash
curl -s http://localhost:11434/api/tags
```
Warm up the model once after starting (avoids a slow first call later):
```bash
curl -s http://localhost:11434/api/generate -d '{"model":"llama3","prompt":"hello","stream":false}'
```

## Running the attacker pipeline

```bash
cd ~/capstone/attacker-pipeline
source .venv/bin/activate
python3 run.py [--waves N] [--wave-size N] [--pause SECONDS] [--label TEXT]
```

| Flag | Default | Use |
|---|---|---|
| `--waves` | `config.NUM_WAVES` (5) | Number of attack waves to fire |
| `--wave-size` | `config.WAVE_SIZE` (50) | Payloads per wave |
| `--pause` | `config.WAVE_PAUSE_SECONDS` (60) | Seconds between waves |
| `--label` | none | Tags the output filename (`run_<label>_<timestamp>.csv`) — use for demo/rehearsal runs so they're never mistaken for real baseline data |

Common invocations:
- Real baseline capture (defaults): `python3 run.py`
- Quick smoke test: `python3 run.py --waves 1 --wave-size 5 --pause 0`
- Advisor demo: `python3 run.py --waves 1 --label demo`

For proposed-but-not-yet-built CLI flags, see `attacker-pipeline/docs/future-improvements.md`.

## Running the MCP server

Standalone service, listens on `http://127.0.0.1:8000/mcp` (streamable-HTTP) until stopped:
```bash
cd ~/capstone/mcp-server
source .venv/bin/activate
python3 server.py
```

Exposes 5 tools to any MCP client: `read_waf_logs`, `get_breach_status`, `test_waf_configuration`,
`write_idempotent_rule`, `reload_waf`. See `mcp-server/docs/Sprint3_Summary.md` for what each does.

Resetting between test runs (clears `ai_generated_rules.conf`, truncates the WAF log files —
prompts for `sudo`, run from a real terminal, not scripted/non-interactively):
```bash
cd ~/capstone/mcp-server
source .venv/bin/activate
python3 reset_state.py
```
After running it, restart the server (its in-memory breach tally only resets on restart) and
reload the WAF so it picks up the now-empty rules file:
```bash
docker exec waf nginx -s reload
```

### Demoing the tools by hand (`demo_client.py`)

Standing in for the not-yet-built Sprint 4 agent: a small interactive MCP client with a numbered
menu over the five tools. Requires `server.py` already running (above) in another terminal:
```bash
cd ~/capstone/mcp-server
source .venv/bin/activate
python3 demo_client.py
```
Pick a tool by number, fill in the prompted arguments (blank keeps the default where one exists),
`q` to quit. For `read_waf_logs`, it calls `get_breach_status()` first and defaults `lines` to the
current total blocked-request count (floor of 50) instead of a fixed guess, so it won't silently
miss lines from a larger-than-expected wave. See `docs/demo-walkthrough-mcp.md` for a full
rehearsable script built around this client.

## Metrics output

CSVs land in `attacker-pipeline/metrics/` (gitignored), one per run: `run_<timestamp>.csv` for
real captures, `run_<label>_<timestamp>.csv` for labeled ones (demo/smoke). The Sprint 2 baseline
is `run_20260809_140007.csv` (250 payloads, 5 waves — see `attacker-pipeline/docs/Sprint2_Summary.md`
for the full analysis).
