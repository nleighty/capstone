# Debug Notes — Sprint 3

## `docs/design-notes.md`'s rule template used a variable name that doesn't exist

**Symptom:** every `write_idempotent_rule()` call produced a rule that `test_waf_configuration()`
correctly rejected: `nginx -t` failed with `Expecting a variable, got: : REQUEST_PARAMETERS ...`.

**Root cause:** the early design-notes.md sketch's rule template targeted
`REQUEST_COOKIES|REQUEST_PARAMETERS` — but `REQUEST_PARAMETERS` isn't a real ModSecurity variable
name. The actual collection for request parameters/query args is `ARGS`. Confirmed by grepping the
real CRS ruleset shipped in the `owasp/modsecurity-crs:nginx` image
(`/etc/modsecurity.d/owasp-crs/rules/*.conf`), which uses `ARGS` throughout and never
`REQUEST_PARAMETERS`. `core/rule_writer.py`'s template now targets `REQUEST_COOKIES|ARGS`, and adds
an explicit `@rx` operator prefix (also confirmed against real CRS rules, which always use an
explicit operator rather than relying on default-operator inference).

**Why this wasn't caught until now:** design-notes.md's sketch was explicitly labeled a "conceptual
blueprint, not implementation" — this sprint is exactly the point where it got tested against the
real WAF for the first time. Caught immediately by `test_waf_configuration()` doing its job
(rejecting a bad config before `reload_waf()` could apply it) - which is itself a small validation
of why that tool exists as a separate step before reload.

**Also flagged:** an inline note was added to `docs/design-notes.md` at the original sketch marking
this correction, rather than editing the historical sketch itself (per project convention: annotate
stale/incorrect content in place instead of silently rewriting history).

## `nginx -s reload` has a brief propagation delay before the new rules are live

**Symptom:** immediately after `reload_waf()` returned "OK" and a rule was confirmed written, a
verification request against the just-written rule still got the *old* result for well under a
second before the new rule took effect.

**Root cause:** `nginx -s reload` is asynchronous — the master process spawns new worker(s) with
the updated config while old worker(s) drain in-flight connections; a request landing on an
about-to-be-replaced old worker in that brief window still sees the pre-reload ruleset. Not a bug in
`reload_waf()` itself (the command reports success correctly, and the new config *does* take
effect) - just a real propagation delay, observed to be under ~1 second in manual testing.

**Practical implication:** anything that fires a verification request immediately after
`reload_waf()` (Sprint 4's agent doing a self-check, or Sprint 5's MTTM stopwatch) should allow a
short buffer before treating an unexpected result as a real failure, rather than assuming
`reload_waf()` returning "OK" means the new rule is already serving traffic on the very next
request.
