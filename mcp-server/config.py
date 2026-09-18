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

# BreachTracker's persisted state (per-endpoint tallies + each log's read
# offset) - anchored to this subproject's own directory since it's MCP-server
# state, not something shared with waf-defense/attacker-pipeline. Survives a
# server restart on purpose; see docs/debug-notes-sprint3-restart-offset.md
# for why that matters and reset_state.py for how an *intentional* reset
# clears it.
MCP_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
BREACH_STATE_FILE = os.environ.get(
    "BREACH_STATE_FILE", os.path.join(MCP_SERVER_DIR, "state", "breach_tracker_state.json")
)

# Matches docker-compose.yml's `container_name: waf`.
WAF_CONTAINER_NAME = os.environ.get("WAF_CONTAINER_NAME", "waf")

# Per-endpoint breach count that trips get_breach_status()'s "tripped" flag.
# Default of 5 matches the example used in docs/design-notes.md.
BREACH_THRESHOLD = int(os.environ.get("BREACH_THRESHOLD", 5))

# Cap on how many raw bypass lines BreachTracker keeps per (endpoint, attack
# family) bucket - not per endpoint alone, since one endpoint can see more
# than one family bypass in the same wave (see core/log_parser.py's module
# docstring). Small on purpose: this is a representative sample for the
# defensive agent to read, not an audit log - the exact count already lives
# in bypass_counts.
BYPASS_SAMPLE_LIMIT = int(os.environ.get("BYPASS_SAMPLE_LIMIT", 5))

# Custom ModSecurity rule IDs, per the "Scoped Inclusion" pattern
# (docs/design-notes.md). CRS reserves 900000-999999 for its own rules
# (confirmed against the real ruleset shipped in owasp/modsecurity-crs, and
# CRS's own docs/CHANGES.md: "rule IDs to start from CRS reserved range:
# 900000"), so this range is a disjoint 7-digit block - it can never overlap
# CRS's 6-digit one, ruling out an AI-picked rule_id ever silently colliding
# with a real CRS rule (e.g. 949110, the anomaly-scoring rule).
CUSTOM_RULE_ID_MIN = 1000000
CUSTOM_RULE_ID_MAX = 1999999

MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", 8000))
