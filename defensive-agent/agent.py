"""Entrypoint for the Sprint 4 defensive agent - a single "dry run" pass.

Per the sprint's own name ("Agent Integration & Dry Runs"), this runs once:
connect to the MCP server, check every endpoint via get_breach_status(), act
on any that have tripped, and exit. A human triggers it and watches the
transcript - there's no polling loop here. Automated multi-wave loops belong
to Sprint 5 ("Automated Testing"), which will need real process-lifecycle
handling (background start/stop, restart-on-crash) alongside the metrics
collection loop anyway - building a partial poller now would mean rebuilding
it later.

get_breach_status() is called directly here, outside any LLM call, so breach
detection and rule-ID assignment (via RuleRegistry) stay deterministic and
reproducible. Only the "what should the rule say" judgment is handed to
Claude, via core/graph.py's ReAct agent - see that module for why.
"""

import asyncio
import json

from langchain_mcp_adapters.client import MultiServerMCPClient

import config
from core import graph
from core.rule_registry import RuleRegistry


def _parse_tool_result(result):
    """MultiServerMCPClient wraps a dict-returning MCP tool's result as a
    list of content blocks (e.g. [{"type": "text", "text": "<json>"}]), not
    a bare dict - confirmed against the running server, not assumed. Extract
    and parse the JSON text block; fall back to treating the result as
    already-parsed if some other shape shows up (defensive, not expected).
    """
    if isinstance(result, list) and result and isinstance(result[0], dict) and "text" in result[0]:
        return json.loads(result[0]["text"])
    if isinstance(result, str):
        return json.loads(result)
    return result


async def main() -> None:
    client = MultiServerMCPClient(
        {"waf-defense": {"url": config.MCP_SERVER_URL, "transport": "streamable_http"}}
    )
    tools = await client.get_tools()
    tools_by_name = {tool.name: tool for tool in tools}

    raw_status = await tools_by_name["get_breach_status"].ainvoke({})
    status = _parse_tool_result(raw_status)
    tripped = status["tripped_endpoints"]

    if not tripped:
        print("No tripped endpoints - nothing to do.")
        return

    registry = RuleRegistry()
    react_agent = graph.build_agent(tools_by_name)

    for endpoint in tripped:
        rule_id = registry.get_or_assign(endpoint)
        samples = status["sample_bypasses"].get(endpoint, {})
        print(f"\n=== {endpoint} tripped -> rule_id {rule_id} ===")
        try:
            await graph.run_for_endpoint(react_agent, endpoint, rule_id, samples)
        except Exception as exc:
            # Don't let one bad endpoint (an Anthropic API error, a
            # docker-exec hiccup) abort the whole dry run - log and move on
            # to the next tripped endpoint. No retry/backoff: this sprint's
            # scope is a human-watched single pass, not unattended automation.
            print(f"[{endpoint}] agent run failed: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
