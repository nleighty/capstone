"""Central config for the defensive MCP server. Every value is env-overridable,
mirroring attacker-pipeline/config.py's pattern so the two subprojects stay
consistent even though they don't share code (core/production vs. test-harness
layers are kept separate per docs/design-notes.md).
"""

import os

# Paths anchored to this file's location, not cwd, so the server works
# regardless of where it's invoked from.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WAF_ERROR_LOG = os.path.join(REPO_ROOT, "waf-defense", "logs", "error.log")
WAF_ACCESS_LOG = os.path.join(REPO_ROOT, "waf-defense", "logs", "access.log")
RULES_FILE = os.path.join(
    REPO_ROOT, "waf-defense", "modsec-rules", "ai_generated_rules.conf"
)

# Matches docker-compose.yml's `container_name: waf`.
WAF_CONTAINER_NAME = os.environ.get("WAF_CONTAINER_NAME", "waf")

# Per-endpoint breach count that trips get_breach_status()'s "tripped" flag.
# Default of 5 matches the example used in docs/design-notes.md.
BREACH_THRESHOLD = int(os.environ.get("BREACH_THRESHOLD", 5))

# Custom ModSecurity rule IDs are conventionally reserved in this range
# (docs/design-notes.md, "Scoped Inclusion" pattern) so they never collide
# with CRS's own rule IDs (900000-999999 vs. CRS's 9xxxxx/949xxx ranges).
CUSTOM_RULE_ID_MIN = 900000
CUSTOM_RULE_ID_MAX = 999999

MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", 8000))
