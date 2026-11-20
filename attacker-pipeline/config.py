"""Central config for the attacker pipeline. Every value is env-overridable so
`run.py` and the smoke-test flow can tweak behavior without editing code.
"""

import os

# Target is the WAF, not Juice Shop directly — traffic must pass through
# ModSecurity for the block/bypass measurement to mean anything.
WAF_BASE_URL = os.environ.get("WAF_BASE_URL", "http://localhost:8080")

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

# Wave defaults per docs/design-notes.md: 50 payloads/wave, 60s pause between
# waves (the pause exists for a future defensive agent to patch mid-run; in
# Sprint 2 there's no agent yet, so it's just idle time).
WAVE_SIZE = int(os.environ.get("WAVE_SIZE", 50))
NUM_WAVES = int(os.environ.get("NUM_WAVES", 5))
WAVE_PAUSE_SECONDS = int(os.environ.get("WAVE_PAUSE_SECONDS", 60))

# Shortest string core.mutate will accept as a real attack variant. Below this
# a "variant" is degenerate model output (a lone "[" from the line-split JSON
# fallback, an empty string), not an attack — see core/mutate.py's validity
# filter. The shortest genuine seed-derived payloads (e.g. "<svg>", "' OR 1=1")
# clear this comfortably.
MIN_VARIANT_LENGTH = int(os.environ.get("MIN_VARIANT_LENGTH", 4))

# Paths anchored to this file's location, not cwd, so the pipeline works
# regardless of where it's invoked from.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WAF_ERROR_LOG = os.path.join(REPO_ROOT, "waf-defense", "logs", "error.log")
METRICS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics")

# Adaptive attacker (`run.py --adaptive`): how many example payloads per seed to
# feed back into the next wave's mutation prompt — a few that got through ("make
# more like these") and a few that were blocked ("avoid these"). Capped so the
# prompt stays short; the attacker only ever sees its own request status codes,
# never the WAF's rules or logs (see core/mutate.py's SeedFeedback).
ADAPTIVE_EXAMPLES_PER_SEED = int(os.environ.get("ADAPTIVE_EXAMPLES_PER_SEED", 3))

# Opt-in diagnostic: when truthy, core.mutate prints a line each time a mutation
# prompt actually carries adaptive feedback (which seed, how many bypassed/blocked
# examples). Off by default so normal runs stay quiet; the prompt isn't otherwise
# logged, so this is the way to confirm wave 2+ really fed results back in.
ADAPTIVE_DEBUG = os.environ.get("ADAPTIVE_DEBUG", "").lower() not in ("", "0", "false", "no")

# Extra Ollama rounds harness/orchestrator.build_wave may spend topping up
# seeds whose variants came back short (junk filtered out, a timeout), so a
# wave still reaches WAVE_SIZE. Capped so a misbehaving model can't hang a run.
WAVE_TOPUP_ROUNDS = int(os.environ.get("WAVE_TOPUP_ROUNDS", 2))

# Auto-triggering the defensive agent between waves (`run.py --defend`, see
# harness/defender.py). The agent runs in its own virtualenv, so the harness
# starts it with that venv's interpreter rather than its own.
DEFENSIVE_AGENT_DIR = os.path.join(REPO_ROOT, "defensive-agent")
DEFENSIVE_AGENT_PYTHON = os.environ.get(
    "DEFENSIVE_AGENT_PYTHON", os.path.join(DEFENSIVE_AGENT_DIR, ".venv", "bin", "python")
)
# Upper bound on one defensive pass (all tripped endpoints). A normal pass is a
# few minutes; this just stops a hung API call from stalling the run forever.
AGENT_TIMEOUT_SECONDS = int(os.environ.get("AGENT_TIMEOUT_SECONDS", 900))
# Pause after a wave before the agent checks breach status, so the WAF's last
# log lines for the wave are on disk.
LOG_SETTLE_SECONDS = float(os.environ.get("LOG_SETTLE_SECONDS", 2))
