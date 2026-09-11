"""Ollama-driven payload mutation.

Core-layer primitive: knows how to turn one seed payload into N obfuscated
variants. Has no concept of "wave size" or metrics — that's the harness's job.
"""

import json
import re

import httpx
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

# A request timeout guards against llama3 dropping into a degenerate
# repetition loop and never emitting an end-of-sequence token — observed
# during Sprint 2/3 testing to run past 25 minutes and 9000+ tokens for what
# should be a short JSON array before something on our end finally kills it.
# 90s comfortably covers a normal ~200-800 token response even on CPU/low-GPU
# hardware, while still failing fast instead of hanging the whole wave loop.
_GENERATE_TIMEOUT_SECONDS = 90

# Upper bound on response length. n variants of a short XSS/SQLi payload
# should top out in the low hundreds of tokens; this is a generous ceiling
# that still turns a runaway generation into a fast failure (caught below)
# instead of an unbounded hang.
_MAX_PREDICT_TOKENS = 1024

_client = ollama.Client(host=config.OLLAMA_HOST, timeout=_GENERATE_TIMEOUT_SECONDS)


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


def _safe_generate(prompt: str) -> str:
    """Call the model with the token cap applied, treating a timeout the same
    as any other uncooperative response (empty string) rather than crashing
    the wave loop — a hung/looping generation should cost one wasted attempt,
    not the whole run.
    """
    try:
        response = _client.generate(
            model=config.OLLAMA_MODEL,
            prompt=prompt,
            stream=False,
            options={"num_predict": _MAX_PREDICT_TOKENS},
        )
        return response["response"]
    except httpx.TimeoutException:
        print(f"[mutate] WARNING: generate() timed out after {_GENERATE_TIMEOUT_SECONDS}s, treating as empty response")
        return ""


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

    variants = _parse_variants(_safe_generate(prompt))

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
        retry_variants = _parse_variants(_safe_generate(prompt))
        for v in retry_variants:
            key = v.lower()
            if key not in seen:
                seen.add(key)
                deduped.append(v)

    return deduped
