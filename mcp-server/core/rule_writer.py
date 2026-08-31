"""Implements the "Scoped Inclusion" idempotent rule-writing pattern from
docs/design-notes.md: every custom rule is keyed by a unique numeric ID, and
writing a rule with an ID that already exists overwrites that line in place
instead of appending a duplicate. Rerunning with the same IDs forever leaves
the file the same size — no unbounded growth, no colliding rules.
"""

import re
from pathlib import Path

import config

_RULE_TEMPLATE = (
    'SecRule REQUEST_COOKIES|ARGS "@rx {attack_pattern}" '
    '"id:{rule_id},phase:2,deny,status:403,msg:\'{description}\'"\n'
)


def _id_line_pattern(rule_id: int) -> re.Pattern:
    # The trailing comma disambiguates e.g. id:1000001 from id:10000010 - the
    # latter would not contain the literal substring "id:1000001," anywhere.
    return re.compile(r"id:%d," % rule_id)


def write_rule(rule_id: int, attack_pattern: str, description: str) -> str:
    """Write (or overwrite) a rule in config.RULES_FILE. `attack_pattern` is a
    raw regex (no need to prefix it with an operator - the template adds
    `@rx` explicitly). Returns a short human-readable status string
    describing what happened, for the MCP tool to hand back to its caller.
    """
    if not (config.CUSTOM_RULE_ID_MIN <= rule_id <= config.CUSTOM_RULE_ID_MAX):
        return (
            f"Error: rule_id {rule_id} is outside the reserved custom rule "
            f"range ({config.CUSTOM_RULE_ID_MIN}-{config.CUSTOM_RULE_ID_MAX}); "
            "not written."
        )

    # Defensive escaping so a stray quote in the LLM-supplied strings can't
    # break the SecRule directive's own quoting.
    safe_pattern = attack_pattern.replace('"', '\\"')
    safe_description = description.replace("'", "\\'")
    new_line = _RULE_TEMPLATE.format(
        attack_pattern=safe_pattern, rule_id=rule_id, description=safe_description
    )

    rules_path = Path(config.RULES_FILE)
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    existing_lines = (
        rules_path.read_text().splitlines(keepends=True) if rules_path.exists() else []
    )

    id_pattern = _id_line_pattern(rule_id)
    for i, line in enumerate(existing_lines):
        if id_pattern.search(line):
            existing_lines[i] = new_line
            rules_path.write_text("".join(existing_lines))
            return f"Overwrote existing rule id:{rule_id} in {rules_path.name}."

    existing_lines.append(new_line)
    rules_path.write_text("".join(existing_lines))
    return f"Added new rule id:{rule_id} to {rules_path.name}."
