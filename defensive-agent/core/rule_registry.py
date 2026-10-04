"""RuleRegistry: the deterministic, code-owned source of truth for "static
rule IDs" - Sprint 4's idempotency requirement.

The Scoped Inclusion pattern (docs/design-notes.md) only works if repeated
fixes to the *same* endpoint reuse the *same* rule_id, so
write_idempotent_rule() overwrites in place instead of piling up duplicate
rules. Nothing about that requires the LLM to be the one deciding or
remembering the ID - and having it try would be fragile, since a fresh
LangGraph run has no memory of a prior run's choice. Instead, this registry
assigns an ID once per newly-seen endpoint and persists it, so the ID is
handed to the agent as a fixed fact ("use exactly this value") rather than
left for the model to invent or recall.

Persistence technique (atomic tmp-file + replace) mirrors
mcp-server/core/log_parser.py's BreachTracker - reimplemented rather than
imported, since the two subprojects deliberately don't share code (core vs.
agent layer, matching the core/test-harness separation principle in
docs/design-notes.md).
"""

import json
from pathlib import Path

import config


class RuleRegistry:
    """Maps endpoint -> a stable custom rule_id, assigned once and reused
    forever after. IDs are handed out sequentially starting at
    config.CUSTOM_RULE_ID_MIN.
    """

    def __init__(self, state_file: str | None = None):
        self._state_path = Path(state_file or config.RULE_REGISTRY_STATE_FILE)
        state = self._load_state()
        self._endpoints: dict[str, int] = state.get("endpoints", {})
        self._next_id: int = state.get("next_id", config.CUSTOM_RULE_ID_MIN)

    def get_or_assign(self, endpoint: str) -> int:
        """Return endpoint's existing rule_id, or assign and persist a new
        one if this is the first time this endpoint has tripped. Calling
        this repeatedly for the same endpoint always returns the same
        number - that stability is the entire point.
        """
        if endpoint in self._endpoints:
            return self._endpoints[endpoint]

        if self._next_id > config.CUSTOM_RULE_ID_MAX:
            # ~1M IDs in the reserved range - unreachable at capstone scale.
            # Fail loudly rather than silently wrapping/colliding if it ever
            # somehow happened.
            raise RuntimeError(
                f"Rule ID range exhausted (next_id {self._next_id} > "
                f"{config.CUSTOM_RULE_ID_MAX}) - no more IDs to assign."
            )

        rule_id = self._next_id
        self._endpoints[endpoint] = rule_id
        self._next_id += 1
        self._save_state()
        return rule_id

    def _load_state(self) -> dict:
        try:
            return json.loads(self._state_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_state(self) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"endpoints": self._endpoints, "next_id": self._next_id}
        # Write-to-tmp-then-replace so a crash mid-write can't leave a
        # half-written, unparseable state file behind - same technique as
        # BreachTracker._save_state (Path.replace is atomic on same filesystem).
        tmp_path = self._state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload))
        tmp_path.replace(self._state_path)
