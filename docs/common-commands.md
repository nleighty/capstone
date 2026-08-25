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
with old runs; requires `sudo` since the container writes these as root via the bind mount):
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
python run.py [--waves N] [--wave-size N] [--pause SECONDS] [--label TEXT]
```

| Flag | Default | Use |
|---|---|---|
| `--waves` | `config.NUM_WAVES` (5) | Number of attack waves to fire |
| `--wave-size` | `config.WAVE_SIZE` (50) | Payloads per wave |
| `--pause` | `config.WAVE_PAUSE_SECONDS` (60) | Seconds between waves |
| `--label` | none | Tags the output filename (`run_<label>_<timestamp>.csv`) — use for demo/rehearsal runs so they're never mistaken for real baseline data |

Common invocations:
- Real baseline capture (defaults): `python run.py`
- Quick smoke test: `python run.py --waves 1 --wave-size 5 --pause 0`
- Advisor demo: `python run.py --waves 1 --label demo`

For proposed-but-not-yet-built CLI flags, see `attacker-pipeline/docs/future-improvements.md`.

## Metrics output

CSVs land in `attacker-pipeline/metrics/` (gitignored), one per run: `run_<timestamp>.csv` for
real captures, `run_<label>_<timestamp>.csv` for labeled ones (demo/smoke). The Sprint 2 baseline
is `run_20260809_140007.csv` (250 payloads, 5 waves — see `attacker-pipeline/docs/Sprint2_Summary.md`
for the full analysis).
