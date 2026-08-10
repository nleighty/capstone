"""HTTP attack firing.

Core-layer primitive: sends one payload at the WAF and reports what came back.
`correlation_id` is an opaque string here — fire.py doesn't know it's "for
metrics," it just rides along as a query param so the harness can later match
this request against a WAF log line.
"""

import time
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

import config

_session = requests.Session()


@dataclass
class FireResult:
    status_code: int
    sent_at: str
    elapsed: float


def send_payload(entry: dict, payload: str, correlation_id: str) -> FireResult:
    """Fire one payload at `entry`'s endpoint and report the WAF's response.

    `entry` is a seed dict from payloads/seeds.py (method/endpoint/location/
    field/extra_fields) — `payload` is the (possibly mutated) string to
    inject into it.
    """
    url = config.WAF_BASE_URL + entry["endpoint"]
    marker_params = {"_wave_marker": correlation_id}

    sent_at = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()

    if entry["location"] == "query":
        params = {**marker_params, entry["field"]: payload}
        response = _session.get(url, params=params, timeout=10)
    elif entry["location"] == "json":
        # The marker always goes on the query string, even for POSTs whose
        # payload lives in the JSON body: ModSecurity's error log echoes the
        # request line (method + path + query string) but never the body, so
        # a body-embedded marker would be invisible to harness/log_reader.py.
        body = {entry["field"]: payload, **entry.get("extra_fields", {})}
        method = entry.get("method", "POST").upper()
        response = _session.request(
            method, url, params=marker_params, json=body, timeout=10
        )
    else:
        raise ValueError(f"Unknown payload location: {entry['location']!r}")

    elapsed = time.monotonic() - start
    return FireResult(status_code=response.status_code, sent_at=sent_at, elapsed=elapsed)
