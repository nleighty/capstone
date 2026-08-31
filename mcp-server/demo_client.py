"""Ad-hoc interactive MCP client for demoing the Sprint 3 WAF-Defense-Server
tools by hand. Stands in for the not-yet-built Sprint 4 agent: connects to an
already-running server.py over streamable-HTTP, lists the five tools as a
numbered menu, prompts for arguments, and pretty-prints whatever comes back.

Not a general-purpose MCP client - just enough scaffolding to run the demo
narrative (fire a wave, check breach status, read logs, write + test + reload
a rule, re-fire) without hand-typing MCP protocol calls live.

Usage: python demo_client.py  (server.py must already be running)
"""

import asyncio
import json

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import config

SERVER_URL = f"http://{config.MCP_HOST}:{config.MCP_PORT}/mcp"

_REQUIRED = object()

# menu key -> (tool name, [(arg name, caster, default-or-_REQUIRED), ...])
# read_waf_logs's [("lines", ...)] entry here is a fallback only - main()
# overrides it per-call with a default computed from get_breach_status(),
# so a demo run doesn't silently tail fewer lines than the wave produced.
_TOOLS = {
    "1": ("read_waf_logs", [("lines", int, 50)]),
    "2": ("get_breach_status", [("endpoint", str, None)]),
    "3": ("test_waf_configuration", []),
    "4": (
        "write_idempotent_rule",
        [
            ("rule_id", int, _REQUIRED),
            ("attack_pattern", str, _REQUIRED),
            ("description", str, _REQUIRED),
        ],
    ),
    "5": ("reload_waf", []),
}


def _prompt_args(spec: list[tuple[str, type, object]]) -> dict:
    """Prompt for each declared arg, casting to the right type. Required args
    (no default) re-prompt on a blank line; optional args fall back to their
    default (or are omitted entirely, for None-default args) on blank input.
    """
    args = {}
    for name, caster, default in spec:
        tag = "required" if default is _REQUIRED else f"default={default!r}"
        while True:
            raw = input(f"    {name} ({tag}): ").strip()
            if raw:
                args[name] = caster(raw)
                break
            if default is _REQUIRED:
                print("      This argument is required - try again.")
                continue
            if default is not None:
                args[name] = default
            break
    return args


async def _breach_total(session: ClientSession) -> int:
    """Sum blocked-request counts across all endpoints, so read_waf_logs can
    default its `lines` argument to "enough to cover everything the breach
    tracker has seen" instead of a fixed guess that might be too small for a
    larger-than-expected wave.
    """
    result = await session.call_tool("get_breach_status", {})
    status = result.structured_content
    if status is None:
        text = "".join(getattr(block, "text", "") for block in result.content)
        status = json.loads(text)
    return sum(status.get("counts", {}).values())


def _print_result(result) -> None:
    if result.structured_content is not None:
        print(json.dumps(result.structured_content, indent=2))
        return
    for block in result.content:
        text = getattr(block, "text", None)
        print(text if text is not None else block)


async def main() -> None:
    print(f"Connecting to {SERVER_URL} ...")
    async with streamable_http_client(SERVER_URL) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            print("Connected.\n")

            while True:
                print("Tools:")
                for key, (name, _) in _TOOLS.items():
                    print(f"  {key}) {name}")
                print("  q) quit")
                choice = input("\n> ").strip().lower()
                if choice in ("q", "quit", "exit"):
                    break
                if choice not in _TOOLS:
                    print("Unknown option.\n")
                    continue

                name, spec = _TOOLS[choice]
                if name == "read_waf_logs":
                    total = await _breach_total(session)
                    default_lines = max(total, 50)
                    print(
                        f"  (get_breach_status reports {total} blocked requests so far - "
                        f"defaulting lines to {default_lines})"
                    )
                    spec = [("lines", int, default_lines)]
                args = _prompt_args(spec)
                result = await session.call_tool(name, args)
                print(f"\n--- {name} result ---")
                _print_result(result)
                print()


if __name__ == "__main__":
    asyncio.run(main())
