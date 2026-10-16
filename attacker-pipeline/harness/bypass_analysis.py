"""Bypass-pattern analysis over the harness's metrics CSVs.

Answers the question parked in docs/future-improvements.md and raised by the
advisor (Sprint 4.6): *how much gets through the WAF, and what do the payloads
that bypass have in common that the ones CRS blocks don't?* The practical point
is to see whether the offensive model is producing genuinely hard variants (and
which obfuscation techniques correlate with getting through), so we know where
the AI-generated rules can add value beyond the CRS baseline.

Scope and a deliberate boundary: this inspects payload *structure* (length,
encoding layers, comment styles, case-mixing) purely as offline measurement of
our *own* recorded test data. It is intentionally NOT reused as a live
detection signal - classifying real traffic by payload content is exactly the
naive signature matching the project exists to defeat (see
mcp-server/core/log_parser.py's module docstring). Keeping the analysis in the
test-harness layer, never in the defensive core, preserves that separation.

Pure functions over already-parsed rows; the CLI (../analyze.py) owns file I/O
and printing. "Bypass" here means the same thing it means everywhere else in
the project: the WAF returned something other than 403 (see
docs/design-notes.md), read off the CSV's `blocked` column.
"""

import re
from collections import defaultdict
from urllib.parse import unquote

# --- Structural feature detectors --------------------------------------------
# Each answers "does this payload use obfuscation technique X?" on the *raw*
# mutated payload as fired. They describe how a payload was dressed up, not
# whether it is an attack (the family is already known from the seed). Kept
# broad and cheap on purpose - this is descriptive statistics over our own
# data, not a classifier.

_FEATURES = {
    # Percent-encoding, e.g. %3C for '<' or %27 for a quote.
    "url_encoded": lambda p: bool(re.search(r"%[0-9a-fA-F]{2}", p)),
    # Double/nested percent-encoding, e.g. %253C (a %25 that decodes to another %).
    "double_url_encoded": lambda p: bool(re.search(r"%25[0-9a-fA-F]{2}", p)),
    # HTML entities, named or numeric/hex, e.g. &lt; &#60; &#x3c;.
    "html_entity": lambda p: bool(re.search(r"&(#x?[0-9a-fA-F]+|[a-zA-Z]+);?", p)),
    # Backslash hex/unicode escapes, e.g. \x3c <.
    "hex_unicode_escape": lambda p: bool(re.search(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})", p)),
    # SQL/JS inline comment used as a token separator or terminator.
    "inline_comment": lambda p: bool(re.search(r"/\*.*?\*/|--|#", p, re.DOTALL)),
    # Mixed-case keyword, e.g. sElEcT / oNcLiCk - a classic case-folding evasion.
    "mixed_case_keyword": lambda p: _has_mixed_case_keyword(p),
    # Non-trivial whitespace play: tabs/newlines, or a comment used *as* a space.
    "whitespace_trick": lambda p: bool(re.search(r"[\t\n\r]|/\*\*/|\s{2,}", p)),
    # Concatenation / splitting, e.g. 'un'+'ion', char() building, string breaks.
    "concatenation": lambda p: bool(re.search(r"\+|\|\||concat|char\s*\(|chr\s*\(", p, re.IGNORECASE)),
}

# Keywords worth checking for case-folding, across both families. A keyword
# counts as "mixed case" only if it appears with a case pattern that isn't all-
# lower or all-upper (so plain `SELECT` or `select` doesn't trip it).
_KEYWORDS = (
    "select", "union", "from", "where", "or", "and", "insert", "update", "delete",
    "drop", "order", "sleep", "benchmark", "script", "img", "svg", "iframe", "onerror",
    "onload", "onclick", "alert", "prompt", "javascript", "body", "href",
)


def _has_mixed_case_keyword(payload: str) -> bool:
    for kw in _KEYWORDS:
        for m in re.finditer(re.escape(kw), payload, re.IGNORECASE):
            token = m.group(0)
            if token != token.lower() and token != token.upper():
                return True
    return False


def _decoded_len(payload: str) -> int:
    """Length of the payload after one URL-decode pass, so an obfuscation that
    is *longer* as raw text (percent-escapes expand each char to three) is
    measured by the real content it carries, consistent with the defender-side
    _meaningful_len guard in mcp-server/core/log_parser.py.
    """
    return len(unquote(payload))


# --- Aggregation -------------------------------------------------------------


def _is_bypass(row: dict) -> bool:
    """A row is a bypass iff the WAF didn't block it. Prefer the explicit
    `blocked` column; fall back to status_code != 403 for older CSVs that
    might predate it.
    """
    blocked = row.get("blocked")
    if blocked is not None and blocked != "":
        return str(blocked).strip().lower() != "true"
    return str(row.get("status_code", "")).strip() != "403"


def _feature_vector(payload: str) -> dict:
    return {name: detect(payload) for name, detect in _FEATURES.items()}


def analyze(rows: list[dict]) -> dict:
    """Turn metrics rows into a structured bypass-pattern report.

    Returns a dict with:
      - `overall`: totals and bypass rate.
      - `by_group`: per (attack_type, endpoint) totals + bypass rate.
      - `feature_lift`: per feature, how much more common it is among bypasses
        than among blocked payloads (the headline "what gets through" signal).
      - `top_bypass_seeds`: which seed payloads produced the most bypasses.
    """
    total = len(rows)
    bypasses = [r for r in rows if _is_bypass(r)]
    blocked = [r for r in rows if not _is_bypass(r)]

    by_group: dict[tuple, dict] = defaultdict(lambda: {"total": 0, "bypassed": 0})
    for r in rows:
        key = (r.get("attack_type", "?"), r.get("endpoint", "?"))
        by_group[key]["total"] += 1
        if _is_bypass(r):
            by_group[key]["bypassed"] += 1
    for stats in by_group.values():
        stats["bypass_rate"] = stats["bypassed"] / stats["total"] if stats["total"] else 0.0

    # Feature lift: P(feature | bypassed) vs P(feature | blocked). A feature
    # that shows up far more among bypasses than blocks is a technique the WAF
    # is weak against - the actionable output for both #1 (attacker) and the
    # defender (what a new rule might need to catch).
    feature_lift = {}
    for name in _FEATURES:
        in_bypass = sum(_FEATURES[name](r.get("mutated_payload", "")) for r in bypasses)
        in_blocked = sum(_FEATURES[name](r.get("mutated_payload", "")) for r in blocked)
        p_bypass = in_bypass / len(bypasses) if bypasses else 0.0
        p_blocked = in_blocked / len(blocked) if blocked else 0.0
        feature_lift[name] = {
            "pct_of_bypasses": p_bypass,
            "pct_of_blocked": p_blocked,
            # Difference, not ratio, so a feature absent from blocked payloads
            # doesn't produce a divide-by-zero / infinite "lift".
            "lift": p_bypass - p_blocked,
            "count_in_bypasses": in_bypass,
        }

    seed_bypasses: dict[str, int] = defaultdict(int)
    for r in bypasses:
        seed_bypasses[r.get("seed_payload", "?")] += 1

    avg_len = (
        sum(_decoded_len(r.get("mutated_payload", "")) for r in bypasses) / len(bypasses)
        if bypasses else 0.0
    )
    avg_len_blocked = (
        sum(_decoded_len(r.get("mutated_payload", "")) for r in blocked) / len(blocked)
        if blocked else 0.0
    )

    return {
        "overall": {
            "total": total,
            "bypassed": len(bypasses),
            "blocked": len(blocked),
            "bypass_rate": len(bypasses) / total if total else 0.0,
            "avg_decoded_len_bypassed": avg_len,
            "avg_decoded_len_blocked": avg_len_blocked,
        },
        "by_group": {f"{a} {e}": s for (a, e), s in sorted(by_group.items())},
        "feature_lift": feature_lift,
        "top_bypass_seeds": dict(
            sorted(seed_bypasses.items(), key=lambda kv: kv[1], reverse=True)
        ),
    }
