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

# Paths anchored to this file's location, not cwd, so the pipeline works
# regardless of where it's invoked from.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WAF_ERROR_LOG = os.path.join(REPO_ROOT, "waf-defense", "logs", "error.log")
METRICS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics")
