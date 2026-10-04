"""Central config for the defensive LangGraph agent. Mirrors mcp-server/config.py
and attacker-pipeline/config.py's os.environ.get(...) pattern so all three
subprojects stay consistent even though they don't share code.

Loads .env via python-dotenv before reading any env var, since ANTHROPIC_API_KEY
is a secret that should live in this subproject's own .env file rather than a
machine-wide shell export - see docs/meeting-notes.md's 2026-09-17 entry for why.
"""

import os

from dotenv import load_dotenv

load_dotenv()

# Paths anchored to this file's location, not cwd, so the agent works
# regardless of where it's invoked from (matches mcp-server/config.py).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_DIR = os.path.dirname(os.path.abspath(__file__))

# The MCP server this agent connects to - same host/port defaults as
# mcp-server/config.py's MCP_HOST/MCP_PORT, since Sprint 3 already validated
# this exact URL over streamable-HTTP via demo_client.py.
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp")

# Claude model for the ReAct agent's reasoning (log interpretation, regex
# design). Opus over Sonnet: the agent only fires on breach events, not
# per-request, so the cost difference is negligible - not worth trading away
# judgment quality for it.
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")

# Custom ModSecurity rule ID range. Duplicated from mcp-server/config.py
# rather than imported - the two subprojects deliberately don't share code
# (core/test-harness separation, docs/design-notes.md) - but the *range
# itself* must stay identical to mcp-server's, since write_idempotent_rule()
# rejects IDs outside it. If this range ever changes, mcp-server/config.py is
# the source of truth; update both.
CUSTOM_RULE_ID_MIN = 1000000
CUSTOM_RULE_ID_MAX = 1999999

RULE_REGISTRY_STATE_FILE = os.environ.get(
    "RULE_REGISTRY_STATE_FILE", os.path.join(AGENT_DIR, "state", "rule_registry_state.json")
)
