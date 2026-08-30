"""Talks to the running WAF container directly (docker exec) to validate a
rule set before it goes live, and to reload the WAF once a new rule has been
written. Confirmed working directly against the real `waf` container before
being wrapped here: `docker exec waf nginx -t` / `nginx -s reload` both exit
0 on success (warnings about the unrelated ssl_stapling cert go to stderr
alongside the real result either way).
"""

import subprocess

import config


def _run(*nginx_args: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["docker", "exec", config.WAF_CONTAINER_NAME, "nginx", *nginx_args],
        capture_output=True,
        text=True,
    )
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output


def test_configuration() -> tuple[bool, str]:
    """Runs `nginx -t` inside the WAF container - validates syntax without
    applying anything, so a bad rule can be caught before reload_waf() risks
    taking the WAF down.
    """
    return _run("-t")


def reload() -> tuple[bool, str]:
    """Runs `nginx -s reload` inside the WAF container so a newly written
    rule takes effect.
    """
    return _run("-s", "reload")
