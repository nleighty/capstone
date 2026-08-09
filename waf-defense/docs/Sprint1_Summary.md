# Sprint 1 Summary — Environment Setup
**Project:** An Adaptive Defense Framework Against GenAI-Driven Web Payload Polymorphism Using MCP
**Sprint Dates:** Sept. 2 – Sept. 15 (work completed July 19–20, 2026)
**Student:** Nic Leighty

## Objective
Per the project timeline, Sprint 1's goal was to deploy the foundational Docker environment: the vulnerable target application, the WAF proxy in front of it, working logging, and a configuration target for future AI-generated firewall rules.

## What Was Built

A local Docker environment with two containerized services on a shared network:

1. **Target application** — OWASP Juice Shop, a deliberately vulnerable web app, running in isolation (not directly reachable — all traffic must pass through the WAF).
2. **WAF proxy** — Nginx with ModSecurity (OWASP Core Rule Set), acting as a reverse proxy in front of Juice Shop. This is the component that will later be controlled by the MCP server and defensive AI agent.

Supporting infrastructure was also set up:
- **Logging**: WAF access and error logs write to a host folder (`logs/`), so they're accessible outside the container for the future log-reading MCP tool.
- **Rule injection target**: A specific file inside the WAF's rule-loading path was wired up as the location where the defensive agent will later write new firewall rules. This matches the "Scoped Inclusion" idempotency design discussed in early planning notes.

## Validation

Rather than just confirming the containers were "running," each piece was functionally tested:

- Sent a normal request through the WAF → reached Juice Shop successfully.
- Sent a request containing an XSS-style payload (`<script>alert(1)</script>`) → the WAF correctly blocked it (`403 Forbidden`) and logged the full detection detail, including which CRS rule triggered.
- Manually wrote a test rule into the rule-injection file, reloaded the WAF, and confirmed it actively blocked matching traffic — proving the file is truly wired into the WAF's live rule set, not just sitting unused.

## Issues Encountered & Resolved

Three non-obvious configuration problems came up, all specific to this Docker image's internal structure (not conceptual issues with the architecture):

1. **Log path mismatch** — the image's default log locations weren't where we initially mounted; fixed by pointing to the correct paths via the image's supported environment variables.
2. **File permissions** — the container process couldn't write to our log folder until host-side permissions were opened up.
3. **Rule file not loading** — the custom rules file was initially mounted to a path ModSecurity doesn't actually read from. Fixed by mounting it to the correct pre-built location the image already includes by default, then confirmed working via a real block test.

None of these affect the project's design or timeline — they were implementation details specific to this particular Docker image, now documented for future reference.

## Status: Sprint 1 Complete

| Deliverable | Status |
|---|---|
| Docker containers for target app + WAF | ✅ Done |
| Base logging | ✅ Done |
| AI-generated rules configuration target | ✅ Done, verified functional |

## Next Up (Sprint 2)
Per the timeline: build the offensive pipeline — a local Ollama LLM that generates obfuscated payload variants and fires them at the WAF, plus the test orchestrator to manage attack batches and collect baseline metrics.
