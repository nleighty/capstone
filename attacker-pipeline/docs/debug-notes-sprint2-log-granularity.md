# Debug Notes — Sprint 2

## ModSecurity logs a generic anomaly-score ID, not per-signature rule IDs

**Symptom:** every blocked request in the Sprint 2 baseline correlates to ModSecurity rule
`949110` in `waf-defense/logs/error.log`, regardless of whether the payload was SQLi or XSS, or
which specific CRS signature actually matched it.

**Root cause:** the WAF is running CRS in anomaly-scoring mode (the default for
`owasp/modsecurity-crs`). Individual signature rules (the 941xxx range for XSS, 942xxx for SQLi)
increment an internal `TX:BLOCKING_INBOUND_ANOMALY_SCORE` variable but don't themselves emit a
blocking log line. The actual `Access denied` line comes from a single aggregate rule,
`REQUEST-949-BLOCKING-EVALUATION.conf` / `id "949110"`, once the accumulated score crosses the
threshold. Verified directly against the real Sprint 1 error.log before writing any pipeline code:
521 of 522 existing lines carried `[id "949110"]`, one carried `[id "999999"]` (Sprint 1's manual
test rule).

**Why this doesn't block RGI later:** `docs/design-notes.md`'s MCP sketch has the defensive agent
write rules with a direct `deny` action (`id:{rule_id},...,deny,status:403`), not an anomaly-score
contribution. A `deny` rule logs its own ID directly on match — no aggregation in the way. So
`harness/log_reader.py`'s correlation logic (match `_wave_marker` → extract `[id "(\d+)"]`) will
correctly pick up custom `900001`+ IDs once Sprint 3-4's agent exists; it's only "always 949110"
because there's nothing else to match against yet. No rework needed when that sprint lands.

**Practical implication for reading Sprint 2's `metrics.csv`:** treat `matched_rule_id == 949110`
as "blocked by the default CRS ruleset's cumulative score," not as evidence of which signature
fired. If per-signature attribution is ever needed for Sprint 2-era data specifically, it would
require raising `SecAuditEngine`/audit logging with an appropriate detail level — not attempted
here since it wasn't needed for this sprint's baseline goal.

## `llama3`'s JSON output frequently isn't valid JSON

**Symptom:** the vast majority of `core/mutate.py`'s calls to `llama3` triggered the line-split
fallback warning, even after adding a normalization pass.

**Root causes observed, roughly in order of frequency:**
1. Escaped single quotes with a backslash (`\'`) — not a legal JSON escape (only `\" \\ \/ \b \f
   \n \r \t \uXXXX` are legal). Fixed by a preprocessing replace (`text.replace("\\'", "'")`) in
   `_normalize_json_text()` — this alone fixed the majority of cases.
2. Unescaped literal double quotes *inside* a JSON string (e.g. the model nesting a quoted
   sub-string without escaping it) — genuinely ambiguous to repair generically, since there's no
   reliable way to tell "this quote closes the string" from "this quote is data" without knowing
   the model's intent.
3. Non-JSON escape sequences the model borrows from other languages: `\xNN` (Python/C-style hex),
   `\NNN` (octal), stray `\s`, `\d` (regex-style) inside what's meant to be a plain string.
4. Occasionally mismatched bracket/quote counts entirely (the model runs out of "budget" mid-array
   and truncates unevenly).

**Decision: not chasing full JSON5-style tolerance this sprint.** The multi-tier fallback
(`json.loads` → regex-extracted array + retry → naive line-split) already exists specifically to
absorb this — it's the intended design, not a gap. After the `\'` fix, the residual fallback rate
in the full baseline run was ~15% of rows (37/250), and even those rows still produced *usable*
payloads (just occasionally a messier string than a clean single variant, e.g. an entire
unparsed-array blob sent as one payload). Since Sprint 2's goal is a baseline bypass measurement,
not clean payload provenance, this was judged good enough. Worth revisiting if a future sprint
needs guaranteed-clean single-variant strings (e.g. options: constrained decoding / Ollama's
`format: "json"` mode, a stricter reprompt-on-failure loop, or switching to a model with better
instruction-following for structured output).

## Ollama install: no interactive `sudo` available

**Symptom:** the official install script (`curl -fsSL https://ollama.com/install.sh | sh`) prompts
for a `sudo` password to write to `/usr/local`; this shell has no TTY to satisfy that prompt.

**Resolution:** manual user-space install instead of the install script:
1. Ollama's GitHub releases no longer publish a `.tgz` for `linux-amd64` (the install script's
   `ollama.com/download/...tgz` URL 404s) — current releases use `.tar.zst`
   (`ollama-linux-amd64.tar.zst`).
2. This environment's `tar` (GNU tar 1.34) has no linked `libzstd` and there's no system `zstd`
   binary, so `tar --zstd -xf` fails with `zstd: Cannot exec`. Worked around by `pip install --user
   zstandard` and decompressing in Python first, then extracting the resulting plain `.tar` with
   `tar -xf` into `~/.local` (which already gets prepended to `PATH` by the existing `~/.profile`
   logic for login shells — non-login shells need `export PATH="$HOME/.local/bin:$PATH"` set
   explicitly, e.g. when a script runs `ollama` from a non-interactive shell).
3. `ollama serve` run in the background (`nohup ... &`), confirmed via `curl
   localhost:11434/api/version`; `ollama pull llama3` run to completion (~4.7GB) and verified via
   `ollama list`.

None of this affects the project's design — purely an artifact of installing in a non-interactive,
no-root shell rather than a normal desktop session.

**Follow-up, deferred to a future sprint:** switch to the official installer (run manually, since it
needs an interactive `sudo` password) for a standard `/usr/local` + systemd-service install instead
of this manual `~/.local` one. Requires re-pulling `llama3` (~4.7GB) under the installer's dedicated
`ollama` service-user model storage, and removing `~/.local/bin/ollama` / `~/.local/lib/ollama`
afterward so `ollama` on `PATH` resolves unambiguously to the standard install. Not done yet —
deliberately deferred past the 2026-08-10 advisor demo to avoid any risk of Ollama being down during
that window.

**Cleanup checklist for when that switch happens:**
- Remove `~/.local/bin/ollama` and `~/.local/lib/ollama`.
- Revert the PATH block added to `~/.bashrc` (search for "User-space Ollama install") — it exists
  only to make the manual `~/.local/bin` install resolve in a normal interactive terminal; the
  official install puts `ollama` on `/usr/local/bin`, already on `PATH` by default, so this block
  becomes dead weight once the switch is done.
- Confirm `which ollama` resolves to `/usr/local/bin/ollama` in a fresh terminal afterward.
