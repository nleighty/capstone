"""Closes the loop the defensive agent was missing: after a rule is written and
the WAF reloaded, *does the rule actually do its job?*

Before this module the agent's only check was `nginx -t` (syntax), so a regex
that parsed fine but matched nothing relevant looked identical to a good one.
verify() answers two questions against the live WAF:

1. **Attack replay** - re-send the requests BreachTracker recorded as having
   bypassed the WAF. Any that still return non-403 are gaps the rule left open.
2. **Benign guard** - send a small fixed set of ordinary requests, covering
   *every* endpoint, not just the one being fixed: the generated SecRule
   matches REQUEST_COOKIES|ARGS with no URL condition, so a rule written for
   /rest/user/login is live on /api/Feedbacks and /rest/products/search too
   (a first version that only tried the tripped endpoint's benign requests
   passed a login rule that was in fact blocking ordinary feedback comments).
   Any that now return 403 mean the rule is too broad (a false positive). This matters
   because "block everything that bypassed" is a trap: a degenerate mutation
   such as the lone character `[` is recorded as a "bypass", and a rule that
   blocked it would break real searches. Having both halves means the agent
   sees that tension in the numbers instead of silently resolving it by
   over-blocking.

Design constraints worth knowing:

- **Not a generic "send this request" tool.** The agent never supplies a
  request: it can only ask the server to replay what the server itself logged
  for an endpoint, plus the fixed benign set. The tool therefore can't be used
  to fire arbitrary traffic at arbitrary hosts.
- **Replays are tagged `_replay=1` and stripped of `_wave_marker`.** Keeping
  the marker would make BreachTracker (and the attacker harness's LogReader,
  which also correlates on it) count the replays as fresh attacker traffic and
  corrupt the bypass tallies and Sprint 5's metrics. See
  log_parser._extract_blocked_endpoint for the matching exclusion on the
  error-log side, which has no marker check.
- **This is a fit check, not a generalization check.** The replayed requests
  are the same ones the agent saw while writing the rule, so passing proves the
  rule covers its evidence, not that it covers unseen variants - that is what
  the independent harness's RGI measures in Sprint 5. The benign set here is
  likewise small and defender-side; the harness's RFPR set (50-100 requests,
  docs/design-notes.md) stays separate so the final metric isn't graded by the
  same set the agent iterated against.
"""

import json
import time
import urllib.error
import urllib.request

import config

# Neutral UA: urllib's default ("Python-urllib/x") is the kind of string CRS's
# scanner-detection rules can flag, which would turn the benign guard into a
# false alarm unrelated to the agent's rule.
_USER_AGENT = "waf-defense-rule-verifier/1.0"

# Small fixed benign set, per endpoint. Chosen to be ordinary traffic that
# *superficially resembles* an attack - apostrophes in names, SQL keywords
# used as plain English, a bare bracket - since those are exactly the inputs
# an over-broad regex breaks. (Plain "hello world" requests would never catch
# anything.) Each entry: (description, method, uri, body, content_type).
_JSON = "application/json"
_BENIGN: dict[str, list[tuple]] = {
    "/rest/user/login": [
        ("normal login", "POST", "/rest/user/login", {"email": "customer@juice-sh.op", "password": "correct-horse-battery"}, _JSON),
        ("apostrophe in email", "POST", "/rest/user/login", {"email": "o'brien@example.com", "password": "x"}, _JSON),
        ("SQL words as plain-English password", "POST", "/rest/user/login",
         {"email": "anna@example.com", "password": "salt and pepper or sugar, select one"}, _JSON),
    ],
    "/rest/products/search": [
        ("plain search", "GET", "/rest/products/search?q=apple+juice", None, None),
        ("search containing 'or'", "GET", "/rest/products/search?q=orange+or+banana", None, None),
        ("search with apostrophe", "GET", "/rest/products/search?q=mom%27s+favorite", None, None),
        ("search with quoted phrase then semicolon", "GET", "/rest/products/search?q=%27apple%27%3B+juice", None, None),
        ("search for a lone bracket", "GET", "/rest/products/search?q=%5B", None, None),
    ],
    "/api/Feedbacks": [
        ("feedback with quoted word then semicolon", "POST", "/api/Feedbacks",
         {"comment": "Fast delivery, great 'service'; would buy again", "rating": 5, "captchaId": 0, "captcha": "0"}, _JSON),
        ("feedback with quoted word then #", "POST", "/api/Feedbacks",
         {"comment": "Loved the 'juice' #1 shop", "rating": 5, "captchaId": 0, "captcha": "0"}, _JSON),
        ("normal feedback", "POST", "/api/Feedbacks",
         {"comment": "Great shop, fast delivery!", "rating": 5, "captchaId": 0, "captcha": "0"}, _JSON),
        ("feedback with apostrophe", "POST", "/api/Feedbacks",
         {"comment": "It's great, I'll order again", "rating": 5, "captchaId": 0, "captcha": "0"}, _JSON),
    ],
}


def _retag(uri: str) -> str:
    """Drop `_wave_marker` from a recorded URI and add `_replay=1` (see module
    docstring for why). The remaining query params are passed through
    byte-for-byte - decoding and re-encoding them could change exactly the
    obfuscation that made the original request interesting.
    """
    path, _, query = uri.partition("?")
    params = [p for p in query.split("&") if p and not p.startswith("_wave_marker=")]
    params.append("_replay=1")
    return path + "?" + "&".join(params)


def _send(method: str, uri: str, body: str | None, content_type: str | None) -> int:
    """Send one request to the WAF and return its HTTP status. HTTP errors
    (4xx/5xx) are results, not exceptions - a 403 is the signal we want.
    Raises urllib.error.URLError only if the WAF is unreachable.
    """
    headers = {"User-Agent": _USER_AGENT}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(
        config.WAF_BASE_URL + uri,
        data=body.encode() if body is not None else None,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=config.VERIFY_REQUEST_TIMEOUT) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def verify(endpoint: str, samples: list[dict]) -> dict:
    """Replay `samples` (BreachTracker's structured bypass records for
    `endpoint`) and the endpoint's benign set against the live WAF, and
    return a structured report. Call only after reload_waf(): a rule that is
    written but not yet reloaded isn't live, so every replay would just
    re-confirm the old gaps.
    """
    # nginx's `-s reload` returns once the signal is sent; new workers pick up
    # the new ruleset asynchronously. Without a short settle, an immediate
    # replay can still be served by an old worker and report false gaps.
    time.sleep(config.VERIFY_SETTLE_SECONDS)

    still_bypassing, blocked, not_replayable = [], 0, 0
    for sample in samples:
        method, uri, body = sample.get("method"), sample.get("uri"), sample.get("body")
        # A POST recorded only from the access log has no body (nginx doesn't
        # log one), so replaying it would send a different, empty request.
        if not method or not uri or (method != "GET" and body is None):
            not_replayable += 1
            continue
        status = _send(method, _retag(uri), body, sample.get("content_type"))
        if status == 403:
            blocked += 1
        else:
            still_bypassing.append({"request": sample["text"], "status": status})

    # All endpoints' benign requests, regardless of `endpoint` (see the
    # module docstring: rules are global, not per-URL).
    benign = [entry for entries in _BENIGN.values() for entry in entries]
    falsely_blocked = []
    for description, method, uri, body, content_type in benign:
        encoded = json.dumps(body) if body is not None else None
        status = _send(method, _retag(uri), encoded, content_type)
        if status == 403:
            falsely_blocked.append({"description": description, "request": f"{method} {uri} {encoded or ''}".strip()})

    problems = []
    if still_bypassing:
        problems.append(f"{len(still_bypassing)} recorded bypass(es) still get through")
    if falsely_blocked:
        problems.append(f"{len(falsely_blocked)} benign request(s) are now blocked")
    return {
        "endpoint": endpoint,
        "attack_replay": {
            "replayed": blocked + len(still_bypassing),
            "now_blocked": blocked,
            "still_bypassing": still_bypassing,
            "not_replayable": not_replayable,
        },
        "benign_check": {
            "sent": len(benign),
            "falsely_blocked": falsely_blocked,
            "note": "covers all endpoints - rules apply site-wide, not just to the endpoint being fixed",
        },
        "verdict": "PASS" if not problems else "FAIL: " + "; ".join(problems),
    }
