# Future Improvements

Small, proposed-but-not-yet-built enhancements for `mcp-server/` — not part of any current
sprint's scope, just tracked so the ideas don't get lost.

## Degenerate POST bodies still nudge the bypass *count* (Sprint 4.6)

The Sprint 4.6 defender-side degeneracy guard (`core/log_parser.py`,
`_is_degenerate_payload`) drops junk "variants" (the lone-`[` class) so they don't trip the
breach threshold or become agent evidence. It fully covers GET query payloads (visible on the
access line, where counts are sourced) and keeps junk POST *bodies* out of the agent's evidence
and `verify_rule` replay.

Residual: a degenerate **POST** still increments `bypass_counts`, because the body isn't visible
on the access line where counts are sourced — only in the audit log, which arrives separately.
The proper fix is to source POST bypass counts from the audit log rather than the access log, but
Sprint 4.5 deliberately kept counting on the access log alone (the behavior already proven
correct), so this is a larger change than it looks. The practical harm is small (a slight count
inflation from junk POSTs; the dangerous part — junk reaching the agent/verifier — is already
closed). Revisit only if Sprint 5's α (bypass decay) turns out to be sensitive to it.
