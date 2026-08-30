"""The defensive MCP server: exposes the WAF's "hands and eyes" as MCP tools
so a future agent (Sprint 4) can read logs, check breach thresholds, validate
a proposed rule, write it, and reload the WAF - without needing to know any
of the underlying Docker/file details itself.

Note on the class name: docs/design-notes.md's sketch uses `FastMCP` from the
`mcp` SDK's v1 API; this project installed mcp 2.x, where that class was
renamed to `MCPServer` (same decorator-based `@app.tool()` API, just a rename
- see https://py.sdk.modelcontextprotocol.io/v2/migration/).

Runs as a standalone, always-on local service over streamable-HTTP (same
"long-running service other scripts connect to" pattern as the WAF/Juice Shop
Docker containers and the Ollama systemd service), rather than being launched
per-client over stdio - there's no natural client to launch it yet until
Sprint 4's agent exists.
"""

import config
from core import rule_writer, waf_control
from core.log_parser import BreachTracker
from mcp.server.mcpserver import MCPServer

app = MCPServer("WAF-Defense-Server")

# Single tracker instance for the server's lifetime: state (the per-endpoint
# tally and the log read offset) accumulates across tool calls and resets
# only if the server process restarts - see docs/design-notes.md and this
# sprint's summary for why that's an accepted, documented tradeoff rather
# than a gap.
_breach_tracker = BreachTracker()


@app.tool()
def read_waf_logs(lines: int = 50) -> str:
    """Return the last `lines` raw lines from the WAF's ModSecurity error log."""
    log_path = config.WAF_ERROR_LOG
    try:
        with open(log_path, "r", errors="replace") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        return f"Error: log file not found at {log_path}"
    return "".join(log_lines[-lines:])


@app.tool()
def get_breach_status(endpoint: str | None = None) -> dict:
    """Return per-endpoint breach counts (URL path, query string stripped)
    accumulated since this server started, plus which endpoints have reached
    config.BREACH_THRESHOLD. Pass `endpoint` to restrict the result to one
    specific path (e.g. "/rest/user/login"); omit it to see every endpoint
    that's been breached so far.
    """
    return _breach_tracker.status(endpoint)


@app.tool()
def test_waf_configuration() -> str:
    """Validate the WAF's current configuration (`nginx -t` inside the WAF
    container) without applying anything. Run this before reload_waf() to
    catch a bad rule before it can take the WAF down.
    """
    ok, output = waf_control.test_configuration()
    status = "OK" if ok else "FAILED"
    return f"{status}\n{output}"


@app.tool()
def write_idempotent_rule(rule_id: int, attack_pattern: str, description: str) -> str:
    """Write (or overwrite) a custom ModSecurity rule in the AI-generated
    rules file, keyed by `rule_id` (900000-999999). Calling this again with
    the same `rule_id` overwrites the existing rule in place rather than
    appending a duplicate - the "Scoped Inclusion" idempotency pattern from
    docs/design-notes.md. `attack_pattern` is a raw regex (matched via @rx)
    against REQUEST_COOKIES/ARGS; `description` becomes the rule's msg.
    """
    return rule_writer.write_rule(rule_id, attack_pattern, description)


@app.tool()
def reload_waf() -> str:
    """Reload the WAF (`nginx -s reload` inside the WAF container) so a
    newly written rule takes effect. Call test_waf_configuration() first to
    avoid reloading a broken config.
    """
    ok, output = waf_control.reload()
    status = "OK" if ok else "FAILED"
    return f"{status}\n{output}"


if __name__ == "__main__":
    app.run(transport="streamable-http", host=config.MCP_HOST, port=config.MCP_PORT)
