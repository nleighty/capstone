"""Entrypoint for the defensive agent - a single pass.

This runs once: connect to the MCP server, check every endpoint via
get_breach_status(), act on any that have tripped, and exit. There's no
polling loop here. It's started either by hand (a "dry run" a human watches)
or by the attacker harness after every wave (`run.py --defend`, which is how a
multi-wave run becomes a closed attack -> defend loop). For the harness, pass
`--summary-json PATH`: one record per endpoint handled (rule_id, start/finish
time, last verify_rule verdict) is written there, which is where the harness
gets its time-to-mitigation numbers.

get_breach_status() is called directly here, outside any LLM call, so breach
detection and rule-ID assignment (via RuleRegistry) stay deterministic and
reproducible. Only the "what should the rule say" judgment is handed to
Claude, via core/graph.py's ReAct agent - see that module for why.
"""

import argparse
import asyncio
import json
import time
from typing import Any, cast

from langchain_mcp_adapters.client import MultiServerMCPClient

import config
from core import graph
from core.rule_registry import RuleRegistry


def _parse_tool_result(result: Any) -> dict:
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
    # Defensive fallback (not expected in practice): the result already has
    # some other shape. The contract is a dict, so assert that for the type
    # checker rather than leak a `list` branch out of the isinstance narrowing
    # above - behavior is unchanged, the value is returned as-is.
    return cast(dict, result)


async def main(summary_path: str | None = None) -> None:
    client = MultiServerMCPClient(
        {"waf-defense": {"url": config.MCP_SERVER_URL, "transport": "streamable_http"}}
    )
    tools = await client.get_tools()
    tools_by_name = {tool.name: tool for tool in tools}

    raw_status = await tools_by_name["get_breach_status"].ainvoke({})
    status = _parse_tool_result(raw_status)
    tripped = status["tripped_endpoints"]

    runs = []
    if not tripped:
        print("No tripped endpoints - nothing to do.")

    registry = RuleRegistry()
    for endpoint in tripped:
        rule_id = registry.get_or_assign(endpoint)
        samples = status["sample_bypasses"].get(endpoint, {})
        print(f"\n=== {endpoint} tripped -> rule_id {rule_id} ===")
        # Built per endpoint because rule_id and endpoint are bound into the
        # rule tools in code (graph._bound_tools), not left to the model.
        react_agent = graph.build_agent(tools_by_name, endpoint, rule_id)
        record = {"endpoint": endpoint, "rule_id": rule_id, "started_at": time.time()}
        try:
            record.update(await graph.run_for_endpoint(
                react_agent, endpoint, rule_id, samples, status["bypass_counts"].get(endpoint, 0)
            ))
        except Exception as exc:
            # Don't let one bad endpoint (an Anthropic API error, a
            # docker-exec hiccup, hitting AGENT_MAX_STEPS) abort the whole
            # pass - record it and move on to the next tripped endpoint.
            print(f"[{endpoint}] agent run failed: {exc}")
            record.update({"verdict": f"error: {type(exc).__name__}: {exc}", "verify_attempts": None})
        record["finished_at"] = time.time()
        runs.append(record)

    if summary_path:
        with open(summary_path, "w") as f:
            json.dump(runs, f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run one defensive pass over every tripped endpoint.")
    parser.add_argument("--summary-json", default=None,
                        help="Write one JSON record per endpoint handled (used by the attacker harness)")
    args = parser.parse_args()
    asyncio.run(main(args.summary_json))
