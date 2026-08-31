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

# Custom ModSecurity rule IDs, per the "Scoped Inclusion" pattern
# (docs/design-notes.md). NOTE: 900000-999999 is NOT free for custom rules -
# that whole block is CRS's own reserved range (confirmed against the real
# ruleset shipped in owasp/modsecurity-crs, and CRS's own docs/CHANGES.md:
# "rule IDs to start from CRS reserved range: 900000"). Using 900000-999999
# here risked an AI-picked rule_id silently colliding with a real CRS rule
# (e.g. 949110, the anomaly-scoring rule). 1000000-1999999 is a 7-digit
# range, so it can never overlap CRS's 6-digit block - see
# docs/design-notes.md's annotation and mcp-server/docs for the correction.
CUSTOM_RULE_ID_MIN = 1000000
CUSTOM_RULE_ID_MAX = 1999999

MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", 8000))
