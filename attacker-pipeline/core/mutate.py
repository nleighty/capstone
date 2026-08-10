"""Ollama-driven payload mutation.

Core-layer primitive: knows how to turn one seed payload into N obfuscated
variants. Has no concept of "wave size" or metrics — that's the harness's job.
"""

import json
import re

import ollama

import config

_SYSTEM_PROMPT = (
    "You are a security research tool generating polymorphic variants of a single "
    "web attack payload for authorized WAF testing in a local sandboxed lab. Given a "
    "seed payload and its attack type (sqli or xss), output {n} syntactically "
    "different but semantically equivalent variants using techniques such as case "
    "randomization, inline comments, alternate encoding (URL/hex/unicode), "
    "whitespace substitution, alternate tag/function synonyms, or string "
    "concatenation. Respond with ONLY a raw JSON array of {n} strings — no markdown "
    "fences, no keys, no commentary."
)

_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)

_client = ollama.Client(host=config.OLLAMA_HOST)


def _normalize_json_text(text: str) -> str:
    """Clean up common ways llama3's output isn't quite valid JSON, before
    we even try to parse it. See docs/debug-notes-sprint2-log-granularity.md
    for the catalog of failure modes this was reverse-engineered from.
    """
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    # llama3 frequently emits Python/JS-style escaped single quotes (\'),
    # which is not a legal JSON escape and trips json.loads immediately.
    text = text.replace("\\'", "'")
    return text


def _parse_variants(text: str) -> list[str]:
    """Best-effort extraction of a list of payload strings from a raw model
    response. Three tiers, each catching what the previous one couldn't:
    1. Straight `json.loads` after normalization — the common case.
    2. Regex-extract the first `[...]` block and retry — handles the model
       wrapping the array in prose despite instructions not to.
    3. Naive line-split — for genuinely malformed JSON. Still yields usable
       (if occasionally messy) strings rather than dropping the response.
    """
    text = _normalize_json_text(text)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(v) for v in parsed]
    except json.JSONDecodeError:
        pass

    match = _ARRAY_RE.search(text)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, list):
                return [str(v) for v in parsed]
        except json.JSONDecodeError:
            pass

    print(f"[mutate] WARNING: falling back to line-split parsing for response: {text!r}")
    variants = []
    for line in text.splitlines():
        cleaned = line.strip().strip("-*0123456789. \t\"'")
        if cleaned:
            variants.append(cleaned)
    return variants


def generate_variants(seed_payload: str, attack_type: str, n: int) -> list[str]:
    """Ask llama3 for up to `n` obfuscated variants of one seed payload.

    Has no concept of "wave size" — the orchestrator decides how many seeds
    x variants make a wave; this function only ever answers "seed -> variants".
    May return fewer than `n` (deduped, possibly below-target) if the model
    won't cooperate even after one retry — callers should not assume an exact
    count back.
    """
    prompt = (
        f"{_SYSTEM_PROMPT.format(n=n)}\n\n"
        f"attack_type: {attack_type}\n"
        f"seed_payload: {seed_payload}"
    )

    response = _client.generate(model=config.OLLAMA_MODEL, prompt=prompt, stream=False)
    variants = _parse_variants(response["response"])

    # Case-insensitive dedup: the model sometimes repeats a variant with only
    # a capitalization difference, which isn't a meaningfully distinct mutation.
    seen = set()
    deduped = []
    for v in variants:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    # One retry (not a loop) if we came up short — enough to smooth out an
    # occasional bad response without risking an unbounded number of calls
    # to a local model that's already the slowest part of the wave loop.
    if len(deduped) < n:
        response = _client.generate(model=config.OLLAMA_MODEL, prompt=prompt, stream=False)
        retry_variants = _parse_variants(response["response"])
        for v in retry_variants:
            key = v.lower()
            if key not in seen:
                seen.add(key)
                deduped.append(v)

    return deduped
