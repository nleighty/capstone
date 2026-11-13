"""Builds the LangGraph "brain" that decides what a new WAF rule should say,
once a tripped endpoint and its evidence have already been determined
elsewhere (agent.py's deterministic step - see that file for why the split).

Deliberately a single langgraph.prebuilt.create_react_agent (itself a
compiled StateGraph) rather than a hand-built outer graph: a dry run's flow
is a straight line with one bounded loop (check status once, act on each
tripped endpoint, exit) - wrapping that in a custom StateGraph would define a
state schema and edges purely to express what a `for` loop already
expresses. If Sprint 5 needs real polling/scheduling/retry logic, that's the
point an outer graph would earn its keep, not before.

The ReAct agent is deliberately NOT given get_breach_status - that tool is
called directly in agent.py's deterministic step, before any LLM is
involved, specifically so breach detection and rule-ID assignment stay
code-owned and reproducible rather than something the model has to reason
its way to correctly every run.
"""

import json

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import SystemMessage
from langchain_core.tools import StructuredTool
from langgraph.prebuilt import create_react_agent

import config

# MCP tools handed to the model unchanged - none of them take an argument that
# could point the agent at another endpoint's rule.
PASSTHROUGH_TOOL_NAMES = ("read_waf_logs", "test_waf_configuration", "reload_waf")

SYSTEM_PROMPT = """You are the defensive half of an adaptive WAF security system.

A breach-detection step outside your control has already determined that a specific endpoint has \
been bypassed by attack traffic at least the configured threshold number of times, and has assigned it a fixed \
rule ID. Your job is judgment - reading the evidence and designing a rule - not bookkeeping.

For the endpoint you're given, you will also be given a sample of raw requests that bypassed the \
WAF, grouped by attack family. More than one family may be present for the same endpoint - a \
single rule_id covers the whole endpoint, so your regex must account for every family shown, not \
just the first one. You may also call read_waf_logs for supplementary context (e.g. what similar \
attacks CRS already blocks), but the bypass samples you're given are the primary evidence, since \
they show what actually got through - the error log only shows what was already caught.

read_current_rule and read_waf_logs answer different questions - do not treat them as \
interchangeable. read_current_rule's return value is the ONLY authoritative source for what this \
rule_id currently contains. read_waf_logs is a historical audit trail, not a snapshot of current \
state: an old entry may reference a pattern or message from an earlier version of this same rule \
that has since been revised or removed. A pattern or description text appearing in log history is \
not, by itself, evidence that it belongs in the rule you write now - only trust read_current_rule \
for that question.

Your rule_id and endpoint are fixed by code: read_current_rule, write_idempotent_rule and \
verify_rule are already bound to them, so you never pass either one.

Steps:
1. Call read_current_rule FIRST, before anything else. If it returns an \
existing rule, treat its current coverage as a floor, not a draft to discard - your job is to \
extend it to also cover today's evidence, not silently narrow it. Today's sample bypasses are \
capped and may not include every pattern the existing rule already protects against; a pattern not \
bypassing right now isn't necessarily safe to stop blocking. This applies only to what \
read_current_rule itself returns - not to anything you later see mentioned in read_waf_logs.
2. Look at the sample bypassing requests. Identify the pattern(s) responsible - the payload is in \
the query string / body content shown in each raw line.
3. Design attack_pattern: a single regex (using alternation to cover every distinct pattern that \
needs coverage - both anything already in the existing rule from step 1, and anything new from \
today's evidence) that matches these payloads and their likely variants, without being so broad it \
would catch ordinary benign input. It will be matched via ModSecurity's @rx operator against \
REQUEST_COOKIES|ARGS automatically - you only supply the raw regex body.
4. Call write_idempotent_rule with your attack_pattern and a short description. It always \
overwrites your assigned rule in place, so a repeat fix replaces the old rule instead of piling up \
a duplicate.
5. Call test_waf_configuration. If it reports failure, revise attack_pattern and call \
write_idempotent_rule again, then re-test.
6. Only once a test reports success, call reload_waf.
7. Then call verify_rule. test_waf_configuration only proves the config parses - \
verify_rule is the only check that the rule actually works. It replays the bypassing requests \
recorded for this endpoint through the live WAF, re-tests every attack an earlier verified rule \
blocked, and also sends a few ordinary requests. Read all three lists in its result:
   - attack_replay.still_bypassing: recorded attacks your rule failed to block. Work out why each \
slipped past (an encoding you didn't anticipate, an anchor that's too strict) and widen the regex.
   - benign_check.falsely_blocked: ordinary requests your rule now blocks. Your regex is too broad - \
narrow it. A false positive on legitimate traffic is worse than a missed attack, so when the two \
conflict, favor not blocking benign traffic.
   - coverage_check.regressions: attacks that were blocked before your rewrite and now get through - \
you dropped coverage the old rule had. Put that coverage back.
   If the verdict is not PASS, revise attack_pattern and repeat steps 4-7, up to \
3 verify_rule attempts in total, then stop and report what remains.
8. Some recorded "bypasses" are not attacks at all (e.g. a request whose entire payload is a single \
character like "["): the WAF correctly let them through. If a still_bypassing entry looks like \
ordinary input, do not write a rule to block it - say so in your final summary instead. In your \
final summary also state the last verify_rule verdict honestly; passing means the rule covers the \
evidence it was written from, not that it covers variants nobody has seen yet.

Always call tools in this order: read_current_rule -> read_waf_logs (optional) -> write -> test -> \
reload -> verify_rule. Never call reload_waf unless the most recent test_waf_configuration reported \
success. Call verify_rule only after reload_waf - before that the new rule isn't live."""


def _as_text(result) -> str:
    """Flatten an MCP tool result (a list of content blocks, a string, or a
    dict) into plain text for the model and for verdict parsing."""
    if isinstance(result, list):
        return "\n".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in result)
    return result if isinstance(result, str) else json.dumps(result)


def _bound_tools(tools_by_name: dict, endpoint: str, rule_id: int) -> list:
    """The tool set for one endpoint's run, with rule_id and endpoint filled
    in by code instead of by the model.

    Before this (post-review fix, 2026-11-13), the assigned rule_id was only
    enforced by the prompt ("use exactly this value"): the model could pass
    any in-range ID to write_idempotent_rule - by mistake or because injected
    log text told it to - and overwrite another endpoint's rule, and
    verify_rule (checking only *its* endpoint) wouldn't notice. Now those
    three tools simply have no rule_id/endpoint parameter for the model to
    get wrong. The MCP server's own tools are unchanged; this is enforced at
    the agent layer, which is the only MCP client.
    """
    read_rule = tools_by_name["read_current_rule"]
    write_rule = tools_by_name["write_idempotent_rule"]
    verify = tools_by_name["verify_rule"]

    async def read_current_rule() -> str:
        return _as_text(await read_rule.ainvoke({"rule_id": rule_id}))

    async def write_idempotent_rule(attack_pattern: str, description: str) -> str:
        return _as_text(await write_rule.ainvoke(
            {"rule_id": rule_id, "attack_pattern": attack_pattern, "description": description}
        ))

    async def verify_rule() -> str:
        return _as_text(await verify.ainvoke({"endpoint": endpoint}))

    bound = [
        StructuredTool.from_function(
            coroutine=read_current_rule, name="read_current_rule",
            description="Return your assigned rule's current line, or a 'no existing rule' message.",
        ),
        StructuredTool.from_function(
            coroutine=write_idempotent_rule, name="write_idempotent_rule",
            description=(
                "Write (or overwrite in place) your assigned rule. attack_pattern is a raw regex, "
                "matched via @rx against REQUEST_COOKIES|ARGS; description becomes the rule's msg."
            ),
        ),
        StructuredTool.from_function(
            coroutine=verify_rule, name="verify_rule",
            description=(
                "After reload_waf: replay this endpoint's recorded bypasses, every attack an earlier "
                "verified rule blocked, and a benign set through the live WAF. PASS only if all hold."
            ),
        ),
    ]
    return bound + [tools_by_name[name] for name in PASSTHROUGH_TOOL_NAMES]


def build_agent(tools_by_name: dict, endpoint: str, rule_id: int):
    """Compile the ReAct agent for one endpoint, bound to only the tools it's
    allowed to act with (see module docstring for why get_breach_status is
    excluded, and _bound_tools for how rule_id/endpoint are fixed).
    """
    # Prompt caching (Anthropic only caches when asked - nothing is cached by
    # default, which is why the Console showed zero cache activity before this
    # was added). Two breakpoints, per Anthropic's recommended agent-loop pattern:
    #  1. Explicit marker on the system prompt block. Render order is
    #     tools -> system -> messages, so this one marker caches the tool
    #     definitions AND the system prompt - the part identical across every
    #     endpoint and every run - as a guaranteed read point.
    #  2. Top-level automatic cache_control (via model_kwargs), which moves a
    #     breakpoint to the end of the conversation each turn, so the
    #     read -> write -> test -> reload loop re-reads its own growing history
    #     instead of re-paying for it on every tool round-trip.
    # Both use the default 5-minute TTL: turns within one endpoint are seconds
    # apart, and endpoints in the same dry run are minutes at most.
    # pyright/Pylance can't resolve langchain's pydantic field alias, so it
    # reports `model` as unknown and demands model_name/timeout/stop. The call
    # is the documented langchain-anthropic API and is exercised live; the
    # diagnostic is a stub limitation, not a real error, so suppress just it.
    model = ChatAnthropic(model=config.ANTHROPIC_MODEL, model_kwargs={"cache_control": {"type": "ephemeral"}})  # pyright: ignore[reportCallIssue]
    # The bound tools' names, descriptions, and schemas are identical for every
    # endpoint (only the values captured inside them differ), so building a new
    # agent per endpoint doesn't break the prompt cache.
    react_tools = _bound_tools(tools_by_name, endpoint, rule_id)
    system_message = SystemMessage(
        content=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]
    )
    return create_react_agent(model, tools=react_tools, prompt=system_message)


def _format_samples(samples_by_family: dict[str, list[str]]) -> str:
    """Render an endpoint's {family: [raw lines]} into the task prompt's
    evidence section. Families with no captured samples are omitted rather
    than shown as an empty block - nothing useful to show the model there.
    """
    if not samples_by_family:
        return "(no bypass samples captured yet)"
    sections = []
    for family, lines in samples_by_family.items():
        if not lines:
            continue
        block = "\n".join(f"  {line}" for line in lines)
        sections.append(f"[{family}] ({len(lines)} example(s)):\n{block}")
    return "\n\n".join(sections) if sections else "(no bypass samples captured yet)"


async def run_for_endpoint(
    agent, endpoint: str, rule_id: int, samples_by_family: dict[str, list[str]], bypass_count: int
) -> dict:
    """Invoke the ReAct agent once for a single tripped endpoint. Each call
    starts a fresh conversation (no shared checkpointer across endpoints or
    runs) - a dry run has no need for multi-turn memory here, and adding one
    now would be designing for a hypothetical requirement.

    Streams and prints each step so a human watching a dry run sees the
    read -> write -> test -> reload sequence happen live - the same "watch
    it work" spirit as mcp-server/demo_client.py's numbered menu, just
    automated instead of hand-driven.

    Returns a short run summary - the last verify_rule verdict and how many
    times verify_rule was called - for agent.py's per-run summary (which the
    attacker harness reads when it auto-triggers the agent).
    """
    task = (
        f"Endpoint: {endpoint}\n"
        f"Assigned rule_id: {rule_id} (already bound to your rule tools - you never pass it)\n"
        f"{bypass_count} bypassing requests have been recorded for this endpoint; the "
        f"{sum(len(v) for v in samples_by_family.values())} below are a representative subset, "
        f"chosen to cover as many distinct attack variants as possible (not the most recent), so "
        f"other variants of the same kinds likely exist - generalize rather than match only "
        f"these.\n"
        f"Sample bypassing requests, grouped by attack family (a request line, plus its body for "
        f"POSTs - the payload is in the query string or the body):\n\n"
        f"{_format_samples(samples_by_family)}\n\nBegin."
    )

    final_state = None
    printed = 0
    # recursion_limit is a hard backstop on runaway loops: the "up to 3
    # verify_rule attempts" cap is otherwise only in the prompt, and once the
    # harness auto-triggers the agent nobody is watching to stop it. A run past
    # the limit raises GraphRecursionError, which agent.py records as an error.
    async for step in agent.astream(
        {"messages": [("user", task)]}, {"recursion_limit": config.AGENT_MAX_STEPS}, stream_mode="values"
    ):
        final_state = step
        messages = step["messages"]
        # stream_mode="values" re-emits the *full* accumulated message list
        # each step, and a single step can add more than one message at once
        # (e.g. Claude issuing read_current_rule and read_waf_logs as
        # parallel tool calls, or their two ToolMessage results both landing
        # in the same step) - only looking at messages[-1] silently drops
        # every message but the last one in a batch. Printing messages[printed:]
        # instead prints every new message exactly once, in order, regardless
        # of how many arrived in one step.
        for message in messages[printed:]:
            tool_calls = getattr(message, "tool_calls", None)
            if tool_calls:
                for call in tool_calls:
                    print(f"  [{endpoint}] -> calling {call['name']}({call['args']})")
            elif getattr(message, "type", None) == "tool":
                print(f"  [{endpoint}] <- {message.name} result: {message.content}")
            elif getattr(message, "content", None):
                print(f"  [{endpoint}] agent: {message.content}")
        printed = len(messages)

    # final_state is None only if the stream yielded nothing (no model call
    # happened at all) - nothing to summarize, and _print_cache_usage would
    # fail on final_state["messages"]. Return an empty state in that case.
    if final_state is None:
        return {"verdict": "no model call happened", "verify_attempts": 0}
    _print_cache_usage(endpoint, final_state)
    return summarize_run(final_state["messages"])


def summarize_run(messages: list) -> dict:
    """Pull the outcome out of a finished run's messages: how many times
    verify_rule was called and the verdict of the last call. Read from the
    tool's own output, not from the model's closing summary, so the recorded
    result is the objective check rather than the model's account of it.
    """
    verdict, attempts = "never verified", 0
    for message in messages:
        if getattr(message, "type", None) == "tool" and getattr(message, "name", None) == "verify_rule":
            attempts += 1
            try:
                verdict = json.loads(_as_text(message.content)).get("verdict", "unknown")
            except (json.JSONDecodeError, AttributeError):
                verdict = "unparseable verify_rule result"
    return {"verdict": verdict, "verify_attempts": attempts}


def _print_cache_usage(endpoint: str, final_state: dict) -> None:
    """Sum token usage across every model call in this run and print the
    cache breakdown. This is the ground truth for whether prompt caching is
    working (the Anthropic Console lags): a healthy run shows cache_read
    growing on every call after the first. langchain-anthropic reports
    input_tokens as the TOTAL prompt, with cache reads/writes broken out
    under input_token_details, so uncached = input - read - creation.
    """
    total_in = cache_read = cache_write = total_out = calls = 0
    for message in final_state["messages"]:
        usage = getattr(message, "usage_metadata", None)
        if not usage:
            continue
        details = usage.get("input_token_details") or {}
        calls += 1
        total_in += usage.get("input_tokens", 0)
        total_out += usage.get("output_tokens", 0)
        cache_read += details.get("cache_read", 0)
        # langchain-anthropic 1.7 reports writes under the per-TTL keys and
        # leaves "cache_creation" at 0 (confirmed against the live API), so
        # take whichever is larger rather than trusting one key.
        cache_write += max(
            details.get("cache_creation", 0),
            details.get("ephemeral_5m_input_tokens", 0) + details.get("ephemeral_1h_input_tokens", 0),
        )
    print(
        f"  [{endpoint}] token usage over {calls} model call(s): input={total_in} "
        f"(cache_read={cache_read}, cache_write={cache_write}, "
        f"uncached={total_in - cache_read - cache_write}), output={total_out}"
    )
