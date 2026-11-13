"""Offline tests for core/graph.py's code-bound rule tools and run summary.

No MCP server, WAF, or Anthropic API: the MCP tools are replaced with fakes
that record the arguments they were called with. Run from defensive-agent/:
    python -m unittest discover -s tests -t .
"""

import asyncio
import json
import unittest

from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool

from core import graph


def _fake_tool(name, calls, result="ok"):
    """A stand-in MCP tool that records its args and returns MCP-style
    content blocks (the shape langchain-mcp-adapters actually returns)."""
    async def run(**kwargs):
        calls.append((name, kwargs))
        return [{"type": "text", "text": result}]
    # Accept any arguments, like the real MCP tools' schemas would.
    return StructuredTool.from_function(coroutine=run, name=name, description=name,
                                        args_schema={"type": "object", "properties": {}, "additionalProperties": True})


class BoundTools(unittest.TestCase):
    def setUp(self):
        self.calls = []
        names = ("read_current_rule", "write_idempotent_rule", "verify_rule",
                 "read_waf_logs", "test_waf_configuration", "reload_waf")
        self.tools = {n: _fake_tool(n, self.calls) for n in names}
        self.bound = {t.name: t for t in graph._bound_tools(self.tools, "/rest/user/login", 1000003)}

    def test_model_cannot_supply_rule_id_or_endpoint(self):
        # The schemas the model sees have no rule_id/endpoint parameter at all.
        self.assertNotIn("rule_id", self.bound["write_idempotent_rule"].args)
        self.assertNotIn("rule_id", self.bound["read_current_rule"].args)
        self.assertNotIn("endpoint", self.bound["verify_rule"].args)

    def test_assigned_values_are_filled_in_by_code(self):
        asyncio.run(self.bound["write_idempotent_rule"].ainvoke({"attack_pattern": "x", "description": "d"}))
        asyncio.run(self.bound["read_current_rule"].ainvoke({}))
        asyncio.run(self.bound["verify_rule"].ainvoke({}))
        self.assertEqual(self.calls, [
            ("write_idempotent_rule", {"rule_id": 1000003, "attack_pattern": "x", "description": "d"}),
            ("read_current_rule", {"rule_id": 1000003}),
            ("verify_rule", {"endpoint": "/rest/user/login"}),
        ])

    def test_same_tool_names_as_before(self):
        self.assertEqual(set(self.bound), set(self.tools))


class SummarizeRun(unittest.TestCase):
    def _verify_msg(self, verdict):
        return ToolMessage(content=json.dumps({"verdict": verdict}), name="verify_rule", tool_call_id="x")

    def test_last_verdict_and_attempt_count(self):
        msgs = [self._verify_msg("FAIL: 1 recorded bypass(es) still get through"), self._verify_msg("PASS")]
        self.assertEqual(graph.summarize_run(msgs), {"verdict": "PASS", "verify_attempts": 2})

    def test_never_verified(self):
        self.assertEqual(graph.summarize_run([]), {"verdict": "never verified", "verify_attempts": 0})


if __name__ == "__main__":
    unittest.main()
