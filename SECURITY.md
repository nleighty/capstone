# Security & Trust Model

This is a **single-host, local, research/lab project** (a capstone — see `CLAUDE.md`). Its
security properties are those of a controlled lab, not a hardened multi-user service. This file
states the trust model explicitly so anyone cloning or extending the project knows what it does
and does **not** protect against. It was written for Sprint 4.6 in response to the question:
"is the security posture (e.g. wiping logs, running the MCP server) sound, and does it carry over
to someone who takes this repo for their own use?" Short answer: **sound for the lab it was built
for; several protections are emergent side effects, not enforced policy, and do not carry over to
a shared or network-exposed host.**

## Intended deployment

- One operator, one trusted host (WSL2 dev machine). Everything runs locally/containerized.
- The MCP server binds **loopback only** (`config.MCP_HOST` default `127.0.0.1`, port 8000). This
  is the project's actual access boundary: only processes on the same host can reach the tools.
- The offensive side fires at the *local* WAF in front of a *local* Juice Shop. It is a closed
  loop — no external target, no real users.

## What is protected, and how

| Asset | Protection | Nature of the protection |
|-------|-----------|--------------------------|
| WAF logs (wiping) | `reset_state.py` needs `sudo` to truncate them | **Emergent** — logs are owned by root because the WAF container writes them to a root-owned bind-mount, not a deliberate authz control. A non-root user genuinely can't wipe them, but that's a side effect of Docker, not a policy. |
| Agent erasing its own rules | `reset_state.py` is deliberately **not** an MCP tool | **By design** — the agent's tool set excludes destructive reset, so it can't erase prior rules (which Sprint 5's RGI metric depends on staying in place). This is a real, intentional control. |
| What the defensive agent can do | The MCP tool list is the agent's entire authority | **By design** — least privilege. Even a jailbroken/prompt-injected model can only read logs and write a rule in the reserved ID range, test, reload, verify. See `docs/sprint-4.6-direction.md` §3. |
| Rule identity/idempotency | `rule_id` assigned by code (`defensive-agent/core/rule_registry.py`), never by the LLM | **By design.** |
| Who can reach the MCP tools | Loopback bind (`127.0.0.1`) | **By design, but it is the *only* thing standing in** — there is **no authentication** on the MCP server (see below). |

## What is NOT protected (and does not carry over to other environments)

- **No authentication / authorization on the MCP server.** Access control is *entirely* the
  loopback bind. Anyone who can reach the port can call every tool (write WAF rules, reload). Fine
  on a single trusted host; **not** fine if the server is ever bound to a non-loopback interface or
  the host is shared. A cloner who changes `MCP_HOST` to `0.0.0.0` removes the only boundary.
- **No access control on `reset_state.py` itself.** The `sudo` requirement is only as strong as
  the host's sudoers config, and nothing stops any user who *can* run it from doing so. The "logs
  need sudo to wipe" property carries over (it comes from the Docker bind-mount), but it is not a
  substitute for real authz.
- **Secrets.** The defensive agent's Anthropic API key lives in `defensive-agent/.env` (gitignored,
  project-scoped on purpose). A cloner must supply their own; don't commit it.
- **Test-only logging choices.** Audit logging captures full request bodies (including login
  credentials) to make POST payloads visible to the agent — intentional for the lab, unacceptable
  in production without redaction/scoping. Noted in `defensive-agent/docs/Sprint4.5_Cleanup.md`.

## If you take this toward a shared or production environment

See `docs/sprint-4.6-direction.md` §4 for the fuller roadmap. The minimum security deltas:

1. Keep the MCP server loopback-only, **or** add authentication + TLS before binding to any
   reachable interface.
2. Put real access control on destructive operations (rule reset, log truncation) — don't rely on
   emergent root-ownership.
3. Redact/scope audit-log body capture so credentials aren't logged in the clear.
4. Deploy AI-generated rules in detection/shadow mode first and gate enforcement on a real
   benign-traffic false-positive check (ties into the RFPR metric).

**Reporting:** this is a student capstone with no production deployment; there is no security
contact or disclosure process. Do not use it as-is to protect anything real.
