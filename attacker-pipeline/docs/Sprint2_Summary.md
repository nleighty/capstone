# Sprint 2 Summary — Attacker Pipeline & Test Harness

**Project:** An Adaptive Defense Framework Against GenAI-Driven Web Payload Polymorphism Using MCP
**Sprint Dates:** work completed 2026-08-09
**Student:** Nic Leighty

## Objective

Per the project timeline, Sprint 2's goal was to build the offensive pipeline — a local Ollama LLM
that mutates SQLi/XSS payloads into polymorphic variants and fires them at the WAF — plus a test
orchestrator that manages attack waves and captures baseline metrics, before any defensive agent
exists (that's Sprint 3-4). This establishes the "before" data point the later Convergence Curve
gets compared against.

## What Was Built

A new sibling subproject, `attacker-pipeline/`, with a deliberate layer split (mirroring
`docs/design-notes.md`'s "keep the test harness separate from the core system" principle):

- **`core/`** — offensive LLM → WAF, no metrics/wave awareness:
  - `mutate.py` — prompts local `llama3` (via Ollama, native WSL2 install) to produce N obfuscated
    variants of a seed payload, with a multi-tier parse fallback (JSON → regex-extracted JSON
    array → line-split) since a local 8B model doesn't always emit strict JSON.
  - `fire.py` — sends a payload at the target through the WAF and reports the status code, tagging
    every request (GET or POST) with a `_wave_marker` query param for later log correlation.
- **`harness/`** — orchestration + metrics, the "scientist" layer:
  - `orchestrator.py` — the wave loop; the only module importing both `core.*` and `harness.*`.
  - `log_reader.py` — correlates a fired request with its WAF log entry by `_wave_marker`,
    extracting the matched ModSecurity rule ID.
  - `metrics_writer.py` — sole owner of the output CSV schema.
- **`payloads/seeds.py`** — 16 hand-curated seeds (8 SQLi, 8 XSS) targeting real Juice Shop
  surfaces: `POST /rest/user/login` (SQLi login-bypass), `GET /rest/products/search?q=` (SQLi/XSS
  reflected), `POST /api/Feedbacks` (persisted XSS).
- **`run.py`** — CLI entrypoint with `--waves`/`--wave-size`/`--pause` overrides for smoke testing.

Ollama itself was installed natively in WSL2 (user's explicit choice over a Dockerized service, for
simpler GPU passthrough) — worked around a blocked interactive `sudo` prompt in this environment by
doing a user-space manual install to `~/.local` instead of the official script's `/usr/local`
target; see the debug notes for details.

## Validation

- Docker stack (Juice Shop + WAF) brought up and confirmed reachable (`200` on `/`); the exact XSS
  payload Sprint 1 proved gets blocked was re-confirmed blocked (`403`) before any pipeline code
  ran, as a sanity baseline.
- **Smoke test** (5 payloads, no pause): confirmed mutated payloads differ from their seeds (proof
  Ollama actually ran), `blocked` correctly tracked `status_code`, and — critically — the
  `_wave_marker` correlation was verified by hand against the raw `waf-defense/logs/error.log` line
  it claimed to match.
- **Full baseline capture**: 5 waves × 50 payloads (250 total), 60s pause between waves, against
  the untouched Sprint 1 WAF ruleset (no defensive agent exists yet).

## Baseline Results

| Wave | Blocked | Bypassed | Bypass % |
|---|---|---|---|
| 1 | 40 | 10 | 20% |
| 2 | 29 | 21 | 42% |
| 3 | 34 | 16 | 32% |
| 4 | 31 | 19 | 38% |
| 5 | 32 | 18 | 36% |

Overall: **166/250 blocked (66%), 84/250 bypassed (34%)** — SQLi bypassed roughly half the time
(81/168), XSS bypassed rarely (3/82). Wave-to-wave variance (20%–42%) reflects the LLM's stochastic
sampling of obfuscation techniques, not the WAF changing — the ruleset is static this sprint, so
this variance is itself useful signal: it's the noise floor that Sprint 3-5's Bypass Decay Rate
needs to trend below to demonstrate the defensive agent is actually doing something, not just
riding sampling luck.

Every blocked row correlated to ModSecurity rule `949110` (see debug notes) — expected under the
current CRS anomaly-scoring config, and confirmed as the intended future hook point for RGI once
Sprint 3-4's AI-authored rules exist.

**Notable qualitative finding:** one XSS variant, `unescape('<a' + 'lert' + '(1)')</a>` (mutated
from `<script>alert(1)</script>`), bypassed the WAF entirely — the string-concatenation obfuscation
broke the `<script>` signature CRS pattern-matches on, without a defensive agent doing anything.
This is a concrete, observed instance of the exact polymorphism-vs-WAF dynamic the capstone's
thesis is about, captured in Sprint 2's raw baseline data before any AI defense exists.

## Issues Encountered & Resolved

- **Ollama install script needs interactive `sudo`**, which isn't available in this shell —
  resolved via a user-space manual install (see debug notes).
- **`llama3`'s JSON output isn't always valid JSON** — most commonly Python/JS-style `\'`
  escape sequences, which aren't legal JSON escapes and immediately break `json.loads`. Added a
  normalization pass to `mutate.py` (strip markdown fences, un-escape `\'` → `'`) before parsing,
  which fixed the majority of cases. A residual ~15% of rows in the full run still hit the
  line-split fallback due to other malformed-JSON patterns (unescaped inner quotes, octal/`\xNN`
  escapes) — the multi-tier fallback chain absorbs these by design; not pursued further this
  sprint (see debug notes for the tradeoff reasoning).

## Status: Sprint 2 Complete

| Deliverable | Status |
|---|---|
| Local Ollama instance for payload mutation | ✅ Done |
| Test orchestrator managing request batches | ✅ Done |
| Baseline metrics captured | ✅ Done — 250-row baseline in `attacker-pipeline/metrics/` |

## Next Up (Sprint 3)

Per the timeline: MCP Server & Defenses — expose `read_waf_logs()`, `test_waf_configuration()`,
`write_idempotent_rule()`, `reload_waf()` as MCP tools, plus breach-threshold tracking. This
sprint's `_wave_marker`/rule-ID correlation groundwork and the 949110-vs-custom-rule-ID distinction
(debug notes) directly inform how Sprint 3's rule-writing should be designed for RGI to be
measurable later.
