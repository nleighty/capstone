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
from core import rule_verifier, rule_writer, waf_control
from core.log_parser import BreachTracker, compact_error_line
from mcp.server.mcpserver import MCPServer

app = MCPServer("WAF-Defense-Server")

# Single tracker instance for the server's lifetime: state (the per-endpoint
# tally and each log's read offset) accumulates across tool calls and is also
# persisted to config.BREACH_STATE_FILE (see core/log_parser.py), so it
# survives a server restart too - only an intentional reset_state.py run
# clears it. See docs/debug-notes-sprint3-restart-offset.md for the bug this
# fixed.
_breach_tracker = BreachTracker()


@app.tool()
def read_waf_logs(lines: int = 50, raw: bool = False) -> str:
    """Return the last `lines` entries from the WAF's ModSecurity error log.

    By default each blocked request is condensed to one short line (time,
    status, rule id, message, matched data if any, request line) - the full
    raw line is mostly constant boilerplate. Pass raw=True for the unabridged
    lines (e.g. when debugging with demo_client.py).
    """
    log_path = config.WAF_ERROR_LOG
    try:
        with open(log_path, "r", errors="replace") as f:
            # Hide verify_rule()'s own replay traffic (tagged _replay=1): the
            # agent would otherwise read its own test blocks back as if they
            # were fresh attack evidence. Filtered before taking the last N so
            # replays can't also crowd real entries out of the window.
            log_lines = [line for line in f if "_replay=1" not in line]
    except FileNotFoundError:
        return f"Error: log file not found at {log_path}"
    selected = log_lines[-lines:]
    if raw:
        return "".join(selected)
    return "\n".join(compact_error_line(line) for line in selected)


@app.tool()
def get_breach_status(endpoint: str | None = None) -> dict:
    """Return per-endpoint blocked_counts and bypass_counts (URL path, query
    string stripped) accumulated since this server started, plus which
    endpoints have reached config.BREACH_THRESHOLD on bypass_counts -
    blocked_counts is telemetry only and never trips the threshold, since a
    blocked payload is already handled and isn't the gap a new rule needs to
    close. Pass `endpoint` to restrict the result to one specific path (e.g.
    "/rest/user/login"); omit it to see every endpoint tracked so far.

    Also returns sample_bypasses: {endpoint: {family: [sample text]}} - a
    representative subset of what actually got through (each sample is the
    request line, plus the body for a POST), since counts alone don't say what
    a new rule should match. Bucketed by attack family (read off _wave_marker,
    not payload content - see core/log_parser.py) because one endpoint can see
    more than one family bypass in the same wave. Within a family the subset is
    chosen for diversity across seed payloads rather than recency (at most
    config.BYPASS_SAMPLES_PER_SEED per seed, config.BYPASS_SAMPLE_LIMIT per
    family), so a flood from one mutation can't hide the others.
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
def read_current_rule(rule_id: int) -> str:
    """Return the existing custom rule line for `rule_id`, if one has already
    been written, or a clear "no existing rule" message if this is a fresh
    ID. Call this before write_idempotent_rule() when re-visiting an endpoint
    that already has a rule - write_idempotent_rule() overwrites by id, so
    without checking first, a rewrite scoped only to today's evidence could
    silently drop coverage the existing rule already had for a pattern that
    isn't bypassing right now.
    """
    return rule_writer.read_rule(rule_id)


@app.tool()
def write_idempotent_rule(rule_id: int, attack_pattern: str, description: str) -> str:
    """Write (or overwrite) a custom ModSecurity rule in the AI-generated
    rules file, keyed by `rule_id` (1000000-1999999). Calling this again with
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


@app.tool()
def verify_rule(endpoint: str) -> dict:
    """Check whether the rule(s) now live actually work, for one endpoint
    (URL path, e.g. "/rest/user/login"). Call this AFTER reload_waf(): it
    re-sends the requests previously recorded as bypassing the WAF for that
    endpoint, and a small fixed set of ordinary requests, through the live WAF.

    Reports (a) attack_replay.still_bypassing - recorded attacks that still
    get through (gaps in your rule), and (b) benign_check.falsely_blocked -
    ordinary requests the WAF now rejects on ANY endpoint (rules are not scoped
    to a URL, so a rule written for one endpoint is live everywhere - your rule
    is too broad). verdict is
    PASS only if both lists are empty. It cannot send anything other than
    what the server already logged plus its built-in benign set. A passing
    verdict means the rule covers the evidence it was written from - not that
    it covers unseen variants.
    """
    try:
        return rule_verifier.verify(endpoint, _breach_tracker.samples_for(endpoint))
    except OSError as exc:
        return {"endpoint": endpoint, "verdict": f"ERROR: could not reach the WAF to replay ({exc})"}


if __name__ == "__main__":
    app.run(transport="streamable-http", host=config.MCP_HOST, port=config.MCP_PORT)
