# Debug Notes — Sprint 3 (found post-close)

## `get_breach_status()` shows zero breaches after an unplanned server restart, even though the WAF logs are still populated

**Symptom:** logs were populated (a wave had been fired) ahead of an advisor demo. The host machine
restarted in between. After bringing Docker/the WAF back up and restarting `server.py`, the demo's
`get_breach_status()` reported zero bypasses/blocked counts for endpoints that had real, on-disk log
entries from before the restart — despite the logs never having been cleared or reset.

**Root cause:** `_OffsetLog.__init__` (`core/log_parser.py`) seeds its read offset to the log file's
*current size at construction time* — end of file, not byte 0 — so a freshly started `BreachTracker`
only counts activity appended after it starts. This is deliberate (see the class docstring and
`server.py`'s comment above `_breach_tracker = BreachTracker()`) and is exactly what
`docs/common-commands.md`'s documented `reset_state.py` → restart-the-server workflow relies on: the
logs are truncated to empty *before* the restart, so "start at EOF" and "start at byte 0" are the
same thing in that flow.

That assumption breaks if the server process restarts for any *other* reason (crash, or here, the
host OS rebooting) without the logs also being truncated first. The new `BreachTracker` still starts
at EOF — but now EOF is *after* a bunch of real, uncounted bypass/blocked lines. Those lines aren't
re-read later either; `poll()` only ever scans forward from the offset, so anything before it is
permanently invisible to that server process, not delayed.

**Why the log file being "still populated" didn't help:** the raw file on disk was never the
problem — `read_waf_logs()` would have shown the same old lines just fine. The gap is specific to
`BreachTracker`'s in-memory, non-persisted offset, which has no way to tell "an intentional reset
happened" (logs truncated) apart from "the process just happens to be new" (logs untouched). It
silently assumes the former is the only case.

**Practical implication:** any workflow where the MCP server might restart independently of
`reset_state.py` — a demo spanning a reboot (this case), or Sprint 5's multi-wave automated runs if
the server process isn't kept alive for the full run — needs either (a) a guarantee the server
process stays up for the whole measurement window, or (b) the offset tracking to be fixed to survive
restarts.

**Fix (implemented 2026-09-17):** `BreachTracker` now persists its full state — both logs' read
offsets and the per-endpoint `blocked_counts`/`bypass_counts` tallies, not just the offsets — to
`config.BREACH_STATE_FILE` (`mcp-server/state/breach_tracker_state.json`, gitignored) after every
`poll()` that sees new activity, and reloads it on construction. This was deliberately more than
just persisting the offset: persisting the offset alone would stop a restart from *skipping* log
lines, but the in-memory tally dicts would still reset to empty on every restart, so previously
counted breaches would still vanish from `get_breach_status()`'s totals even though no line was
mis-read. Persisting both together means a restart resumes the exact same accumulated state a
continuous run would have reached.

Two edge cases handled in `BreachTracker._initial_offset`:
- **No checkpoint exists** (first run ever, or `reset_state.py` just deleted it) — start at the
  log's current end-of-file, same as the original behavior, so a fresh tracker doesn't sweep in
  unrelated pre-existing history.
- **Checkpoint offset exceeds the log's current size** (e.g. the log was truncated by hand without
  also clearing the state file) — clamp to the current size rather than seeking past end-of-file,
  since the old offset is meaningless against the new (shorter) content. Caught during manual
  testing: clamping the *offset* alone wasn't enough — the loaded `blocked_counts`/`bypass_counts`
  dicts were still the old, now-stale tallies, so a fresh attack after the truncate landed on top of
  numbers that no longer corresponded to anything on disk (5 stale + 1 fresh showed as 6 instead of
  1). Fixed by discarding *both* tallies whenever *either* log's offset needed clamping — a clamp on
  one log is evidence the whole checkpoint is out of sync with reality, not just that one number.

`reset_state.py` now also deletes `config.BREACH_STATE_FILE` alongside truncating the logs, so an
intentional reset can't leave stale tallies sitting next to freshly emptied logs — the two are
always cleared together. The server still needs restarting after `reset_state.py` for its in-memory
copy to pick up the deletion, same as before.
