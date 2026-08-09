# Sprint 1 Debug Notes — WAF Container Path Corrections
**Date:** July 19–20, 2026

While setting up the `owasp/modsecurity-crs:nginx` container, two default paths in the compose file were wrong. Documenting so the MCP server (Sprint 3) targets the correct locations.

## 1. Access/Error log paths

**Problem:** mounted `./logs` directly to the container's `/var/log`, which wiped out the `nginx/` subdirectory Nginx expects to exist at boot → container crash loop.

**Fix:** mount to a dedicated subfolder instead, and set log paths explicitly via the image's supported env vars:

```yaml
environment:
  ACCESSLOG: "/var/log/waf-logs/access.log"
  ERRORLOG: "/var/log/waf-logs/error.log"
volumes:
  - ./logs:/var/log/waf-logs
```

Also needed `chmod 777 logs/` on the host — the container process doesn't run as the host user, so it can't write to a default-permission host folder.

## 2. Custom rules file (`ai_generated_rules.conf`) not being loaded

**Problem:** mounted the file to `/etc/modsecurity.d/ai_generated_rules.conf` (top level) — never included by ModSecurity.

**Root cause:** `/etc/nginx/modsecurity.d/setup.conf` only includes `/etc/modsecurity.d/owasp-crs/rules/*.conf`. Anything outside that folder is ignored.

**Fix:** mount to the pre-wired placeholder file the image already ships and includes by default:

```yaml
volumes:
  - ./modsec-rules/ai_generated_rules.conf:/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
```

Verified working by writing a test `SecRule` into the file, restarting the WAF, and confirming a matching request returned `403`.

## Takeaway for MCP server (Sprint 3)

`write_idempotent_rule()` should write to `modsec-rules/ai_generated_rules.conf` on the host (mapped to the path above), then `reload_waf()` needs to restart/reload the `waf` container for changes to take effect.
