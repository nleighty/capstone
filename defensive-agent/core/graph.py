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

from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent

import config

REACT_TOOL_NAMES = ("read_waf_logs", "write_idempotent_rule", "test_waf_configuration", "reload_waf")

SYSTEM_PROMPT = """You are the defensive half of an adaptive WAF security system.

A breach-detection step outside your control has already determined that a specific endpoint has \
been bypassed by attack traffic more than the configured threshold, and has assigned it a fixed \
rule ID. Your job is judgment - reading the evidence and designing a rule - not bookkeeping.

For the endpoint you're given, you will also be given a sample of raw requests that bypassed the \
WAF, grouped by attack family. More than one family may be present for the same endpoint - a \
single rule_id covers the whole endpoint, so your regex must account for every family shown, not \
just the first one. You may also call read_waf_logs for supplementary context (e.g. what similar \
attacks CRS already blocks), but the bypass samples you're given are the primary evidence, since \
they show what actually got through - the error log only shows what was already caught.

Steps:
1. Look at the sample bypassing requests. Identify the pattern(s) responsible - the payload is in \
the query string / body content shown in each raw line.
2. Design attack_pattern: a single regex (using alternation if more than one family is present) \
that matches these payloads and their likely variants, without being so broad it would catch \
ordinary benign input. It will be matched via ModSecurity's @rx operator against \
REQUEST_COOKIES|ARGS automatically - you only supply the raw regex body.
3. Call write_idempotent_rule using EXACTLY the rule_id you were given - never invent your own. \
Reusing the same ID is what makes a repeat fix overwrite the old rule instead of piling up a \
duplicate.
4. Call test_waf_configuration. If it reports failure, revise attack_pattern and call \
write_idempotent_rule again with the same rule_id, then re-test.
5. Only once a test reports success, call reload_waf.

Always call tools in this order: read (optional) -> write -> test -> reload. Never call reload_waf \
unless the most recent test_waf_configuration reported success."""


def build_agent(tools_by_name: dict):
    """Compile the ReAct agent, bound to only the tools it's allowed to act
    with (see module docstring for why get_breach_status is excluded).
    """
    model = ChatAnthropic(model=config.ANTHROPIC_MODEL)
    react_tools = [tools_by_name[name] for name in REACT_TOOL_NAMES]
    return create_react_agent(model, tools=react_tools, prompt=SYSTEM_PROMPT)


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


async def run_for_endpoint(agent, endpoint: str, rule_id: int, samples_by_family: dict[str, list[str]]) -> dict:
    """Invoke the ReAct agent once for a single tripped endpoint. Each call
    starts a fresh conversation (no shared checkpointer across endpoints or
    runs) - a dry run has no need for multi-turn memory here, and adding one
    now would be designing for a hypothetical requirement.

    Streams and prints each step so a human watching a dry run sees the
    read -> write -> test -> reload sequence happen live - the same "watch
    it work" spirit as mcp-server/demo_client.py's numbered menu, just
    automated instead of hand-driven.

    Returns the final graph state for the caller's summary line.
    """
    task = (
        f"Endpoint: {endpoint}\n"
        f"Assigned rule_id: {rule_id} (fixed - use exactly this value, never choose your own)\n"
        f"Sample bypassing requests, grouped by attack family (raw access-log lines - the payload "
        f"is in the query string):\n\n{_format_samples(samples_by_family)}\n\nBegin."
    )

    final_state = None
    async for step in agent.astream({"messages": [("user", task)]}, stream_mode="values"):
        final_state = step
        last_message = step["messages"][-1]
        # AIMessages with tool calls print the call; ToolMessages print the
        # result - printing both is what makes the sequence visible live.
        tool_calls = getattr(last_message, "tool_calls", None)
        if tool_calls:
            for call in tool_calls:
                print(f"  [{endpoint}] -> calling {call['name']}({call['args']})")
        elif getattr(last_message, "type", None) == "tool":
            print(f"  [{endpoint}] <- {last_message.name} result: {last_message.content}")
        elif getattr(last_message, "content", None):
            print(f"  [{endpoint}] agent: {last_message.content}")

    return final_state
