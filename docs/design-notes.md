# Early Design Notes

Planning/design reasoning from pre-proposal brainstorming sessions (Gemini, 2026-06-13). These are
the "early planning notes" referenced in `waf-defense/docs/Sprint1_Summary.md` re: the Scoped
Inclusion pattern. Kept here as the rationale behind decisions baked into the proposal and Sprint 1.

## Threshold tracking: per-endpoint vs. global count

- The WAF is a proxy, so every request log (Nginx/ModSecurity) already includes the request URI —
  no need for heavy app-level monitoring to track breaches per endpoint.
- Simple approach: group logs by URL path using a `defaultdict(int)` in the MCP server when reading
  logs (strip query params, keep the path, e.g. `/api/login`).
- **MVP fallback**: start with a *global* breach count (e.g., any 5 breaches site-wide trips the
  threshold) rather than per-endpoint tracking. Per-endpoint tracking is a Phase 2 refinement — fine
  to document the global-count version as a known Phase 1 limitation.

## Idempotency: the "Scoped Inclusion" pattern

Problem: if the defensive agent just appends new rules every time it fires, the rules file bloats,
duplicate/colliding rules pile up, and eventually Nginx refuses to reload.

Solution (this is what Sprint 1's rule-injection target implements):
1. Don't let the agent touch the main `modsecurity.conf`. Instead, maintain a separate file,
   `ai_generated_rules.conf`, included from the main config via a single `Include` directive.
2. Every custom rule gets a unique numeric ID. ModSecurity convention: custom rule IDs in the
   `900000`–`999999` range.
3. Force the LLM's output into a strict schema tied to a stable ID per attack vector, e.g.:
   ```json
   {
     "target_endpoint": "/api/login",
     "rule_id": 900001,
     "rule_logic": "SecRule REQUEST_COOKIES:session ..."
   }
   ```
4. When the agent fires, the MCP server doesn't append — it opens `ai_generated_rules.conf`, finds
   the line starting with that `rule_id`, and **overwrites** it in place.
5. Result: the file never grows unbounded. Rerun the agent 1,000 times and it's still one line per
   known vector — idempotent by construction, no extra bookkeeping needed.

## Metrics: keep the test harness separate from the core system

Core principle: metric-gathering logic must never pollute the core security code. Two distinct
layers:

```
+--------------------------------------------------------+
| TEST HARNESS (the "scientist" layer)                   |
| - Controls attack waves                                |
| - Sends benign control traffic                         |
| - Calculates decay, RGI, and RFPR                       |
+--------------------------------------------------------+
                           |
                           v  (triggers & observes)
+--------------------------------------------------------+
| CORE SYSTEM (the "production" layer)                    |
| [Offensive LLM] -> [WAF Proxy] -> [MCP Server/Agent]     |
+--------------------------------------------------------+
```

Per-metric implementation notes:

- **MTTM** — lives in the defensive MCP server/agent loop. Grab `start_time` when the threshold
  trips, `end_time` when the WAF successfully reloads with the new rule; diff and append to a local
  `metrics.csv`.
- **Bypass Decay / RGI** — lives in the offensive script, since it's the one that knows what a
  "wave" is. Fire 50 payloads per wave, track `200 OK` (bypass) vs `403 Forbidden` (blocked). For
  RGI specifically: ModSecurity logs the exact rule ID that blocked a request (e.g. `[id
  "900001"]"`) — if a Wave 2 attack is blocked by a rule generated in Wave 1, that's an RGI point.
  Pause ~60s between waves to let the agent patch before the next wave fires.
- **RFPR** — lives in the test harness as a post-deployment hook. Maintain a fixed set of 50–100
  legitimate benign requests (browse home page, add to cart, normal login, etc.). Whenever the
  defensive agent deploys a new rule, the harness immediately fires all of them; any `403` on a
  benign request is a false positive.

Deliverable framing for the thesis: two graphs — the **Convergence Curve** (bypass rate over
waves, trending to zero) and the **Safety Ceiling** (a flat 0% line showing benign traffic was never
blocked despite the rule set changing repeatedly).

## MCP server — conceptual shape (early sketch, not the final API)

Early conceptual blueprint of what the MCP server looks like structurally — decorate plain Python
functions as tools, the agent discovers and calls them over JSON-RPC:

```python
from mcp.server.fastapi import FastMCP
import subprocess

app = FastMCP("WAF-Defense-Server")

@app.tool()
def read_waf_logs(lines: int = 50) -> str:
    """Reads the latest entries from the ModSecurity/Nginx error log."""
    with open("/var/log/nginx/error.log", "r") as f:
        log_lines = f.readlines()
    return "".join(log_lines[-lines:])

@app.tool()
def write_idempotent_rule(rule_id: int, attack_pattern: str, description: str) -> str:
    """Writes/overwrites a custom ModSecurity rule in ai_generated_rules.conf, keyed by rule_id
    (Scoped Inclusion pattern above) — never appends, so repeated calls stay idempotent."""
    new_rule = f'SecRule REQUEST_COOKIES|REQUEST_PARAMETERS "{attack_pattern}" "id:{rule_id},phase:2,deny,status:403,msg:\'{description}\'"\n'
    # find-and-replace the line starting with this rule_id, or append if it's new
    ...

@app.tool()
def reload_waf() -> str:
    """Reloads Nginx/ModSecurity so a newly written rule takes effect."""
    subprocess.run(["nginx", "-s", "reload"], check=True)
    return "WAF reloaded."
```

(`test_waf_configuration()` — the fourth tool in the proposal's set — isn't sketched here; it's a
validation step, likely `nginx -t` or equivalent, run before `reload_waf()` to catch a bad rule
before it takes down the WAF.)

> ⚠️ **Correction (Sprint 3):** the sketch above targets `REQUEST_COOKIES|REQUEST_PARAMETERS`, but
> `REQUEST_PARAMETERS` isn't a real ModSecurity variable — the actual collection is `ARGS`. Caught by
> `test_waf_configuration()` rejecting the generated rule the first time it was tried against the
> real WAF; see `mcp-server/docs/debug-notes-sprint3-rule-syntax.md`. The implemented version in
> `mcp-server/core/rule_writer.py` uses `REQUEST_COOKIES|ARGS` with an explicit `@rx` operator.
> Left the original text below unedited as the historical record of the sketch.

Names here match the proposal's finalized tool set: `read_waf_logs()`, `test_waf_configuration()`,
`write_idempotent_rule()`, `reload_waf()`. This is still just a conceptual sketch, not
implementation — the actual overwrite-in-place logic (find the line starting with `rule_id`,
replace it) needs to be written when the MCP server subproject is built.

## Swapping LLMs

If an agent framework/abstraction layer is used for LLM calls (LiteLLM, LangGraph, CrewAI), the
backend model becomes a one-line config swap since MCP decouples the model from the tools:

```python
# Local, zero-cost:
ai_agent.set_llm(model="ollama/llama3")

# Swap to a cloud model later:
ai_agent.set_llm(model="anthropic/claude-3-5-sonnet")
```

The MCP client turns whatever text the chosen model produces into a tool call against the same
local WAF server — no architecture changes needed to switch models.
