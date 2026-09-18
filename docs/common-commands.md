# Common Commands

Day-to-day operation reference for the WAF environment, Ollama, and the attacker pipeline. For the
narrated advisor-demo script, see `docs/demo-walkthrough.md`; for what each piece actually is, see
`waf-defense/docs/Sprint1_Summary.md` and `attacker-pipeline/docs/Sprint2_Summary.md`.

Sections below are in the order you'd actually run them for a fresh test: infra up, MCP server up
(it reads logs from an offset captured at startup, so it must be running *before* traffic fires or
it silently misses everything already sitting in the logs), then fire traffic, then
inspect/act on it.

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

## Resetting to a clean slate (do this before starting the server, not after firing a wave)

Clears `ai_generated_rules.conf`, truncates the WAF log files, and deletes the MCP server's
persisted breach-tally state (prompts for `sudo`, run from a real terminal, not
scripted/non-interactively):
```bash
cd ~/capstone/mcp-server
source .venv/bin/activate
python3 reset_state.py
docker exec waf nginx -s reload
```
If `server.py` is already running when you do this, stop and restart it afterward — it only reads
the state file at startup, so a reset while it's running won't be picked up until it restarts.

Manual log truncation only, if you don't want the rest of `reset_state.py`'s cleanup (requires
`sudo` since the container writes these as root via the bind mount):
```bash
sudo truncate -s 0 /home/nicle/capstone/waf-defense/logs/access.log /home/nicle/capstone/waf-defense/logs/error.log
```

## Running the MCP server

Start this **before** firing any traffic — it captures each log's starting offset at startup, so
anything already in the logs before it starts is silently skipped, not backfilled. Standalone
service, listens on `http://127.0.0.1:8000/mcp` (streamable-HTTP) until stopped:
```bash
cd ~/capstone/mcp-server
source .venv/bin/activate
python3 server.py
```
Prints a startup line per log noting the offset it's starting from — watch for it, especially a
"file already has N bytes" warning, which means traffic fired before this start and will be missed.

Exposes 5 tools to any MCP client: `read_waf_logs`, `get_breach_status`, `test_waf_configuration`,
`write_idempotent_rule`, `reload_waf`. See `mcp-server/docs/Sprint3_Summary.md` for what each does.

## Running the attacker pipeline

Fire this only after `server.py` (above) is already running:
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

## Inspecting results by hand (`demo_client.py`)

A small interactive MCP client with a numbered menu over the five tools, for exercising them
manually without a live agent involved (e.g. isolating whether a tool call works on its own before
blaming the agent). Requires `server.py` already running:
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

## Running the defensive agent

A single "dry run" pass: connects to the MCP server, checks every endpoint via
`get_breach_status()`, and for any that have tripped the breach threshold, autonomously runs
`read_waf_logs` (optional context) → `write_idempotent_rule` → `test_waf_configuration` →
`reload_waf`, printing each step as it happens. Runs once and exits — this is a human-triggered dry
run, not a polling loop (see `defensive-agent/docs/Sprint4_Summary.md`). Requires `server.py`
already running and a wave already fired:
```bash
cd ~/capstone/defensive-agent
source .venv/bin/activate
python3 agent.py
```
Needs `ANTHROPIC_API_KEY` set in `defensive-agent/.env` (see `defensive-agent/.env.example`).

## Metrics output

CSVs land in `attacker-pipeline/metrics/` (gitignored), one per run: `run_<timestamp>.csv` for
real captures, `run_<label>_<timestamp>.csv` for labeled ones (demo/smoke). The Sprint 2 baseline
is `run_20260809_140007.csv` (250 payloads, 5 waves — see `attacker-pipeline/docs/Sprint2_Summary.md`
for the full analysis).
