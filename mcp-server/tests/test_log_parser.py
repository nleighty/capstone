"""Offline regression tests for core/log_parser.py (BreachTracker + helpers).

Everything runs against temp files - no WAF, Docker, or live state is touched.
Run from mcp-server/:  python -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

import config
from core import log_parser
from core.log_parser import BreachTracker, compact_error_line

EP = "/rest/user/login"


def audit_line(marker, body, status=500, method="POST", messages=()):
    return json.dumps({"transaction": {
        "request": {"method": method, "uri": f"{EP}?_wave_marker={marker}", "body": body,
                    "headers": {"Content-Type": "application/json"}},
        "response": {"http_code": status},
        "messages": [{"details": {"data": d}} for d in messages]}}) + "\n"


def access_line(marker, method="POST", status=500, endpoint=EP):
    return f'1.1.1.1 - - [x] "{method} {endpoint}?_wave_marker={marker} HTTP/1.1" {status} 9 "-" "x" "-"\n'


class TrackerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig_state = config.BREACH_STATE_FILE
        config.BREACH_STATE_FILE = os.path.join(self.tmp, "state.json")
        self.paths = {n: os.path.join(self.tmp, n) for n in ("error", "access", "audit")}
        for p in self.paths.values():
            open(p, "w").close()
        self.tracker = self.new_tracker()

    def tearDown(self):
        config.BREACH_STATE_FILE = self._orig_state

    def new_tracker(self):
        return BreachTracker(self.paths["error"], self.paths["access"], self.paths["audit"])

    def feed(self, log, text):
        with open(self.paths[log], "a") as f:
            f.write(text)

    def samples(self, endpoint=EP, family="sqli"):
        return self.tracker.status(endpoint)["sample_bypasses"][endpoint][family]


class SampleSelection(TrackerCase):
    def test_flooding_seed_is_capped_and_rare_seeds_survive(self):
        for i in range(1, 7):  # seed 08 floods
            self.feed("access", access_line(f"w1-sqli-08-{i}"))
            self.feed("audit", audit_line(f"w1-sqli-08-{i}", f'{{"email":"s8-{i}"}}'))
        for seed in ("02", "05"):
            self.feed("access", access_line(f"w1-sqli-{seed}-1"))
            self.feed("audit", audit_line(f"w1-sqli-{seed}-1", f'{{"email":"s{seed}"}}'))
        status = self.tracker.status(EP)
        texts = status["sample_bypasses"][EP]["sqli"]
        self.assertEqual(status["bypass_counts"][EP], 8)
        self.assertEqual(len(texts), config.BYPASS_SAMPLES_PER_SEED * 1 + 2)
        self.assertEqual(sum("s8-" in t for t in texts), config.BYPASS_SAMPLES_PER_SEED)
        self.assertTrue(any("s02" in t for t in texts) and any("s05" in t for t in texts))
        self.assertIn("s8-6", " ".join(texts))  # newest of the flooding seed kept

    def test_total_cap_keeps_as_many_distinct_seeds_as_possible(self):
        for seed in range(30):
            for i in (1, 2):
                m = f"w1-sqli-{seed:02d}-{i}"
                self.feed("access", access_line(m))
                self.feed("audit", audit_line(m, "{}"))
        self.tracker.status(EP)
        bucket = self.tracker._bypass_samples[EP]["sqli"]
        self.assertEqual(len(bucket), config.BYPASS_SAMPLE_LIMIT)
        self.assertEqual(len({s["seed"] for s in bucket}), config.BYPASS_SAMPLE_LIMIT)

    def test_marker_match_is_exact_not_substring(self):
        # "...-02-3" is a substring of "...-02-30"; they are different requests.
        for m in ("w1-sqli-02-3", "w1-sqli-02-30"):
            self.feed("access", access_line(m))
            self.feed("audit", audit_line(m, "{}"))
        self.assertEqual(len(self.samples()), 2)


class AccessAndAuditMerge(TrackerCase):
    def test_audit_body_upgrades_access_only_post_in_either_order(self):
        self.feed("access", access_line("w1-sqli-01-1"))
        self.tracker.status()
        first = self.tracker._bypass_samples[EP]["sqli"][0]
        self.assertEqual((first["method"], first["body"]), ("POST", None))
        self.feed("audit", audit_line("w1-sqli-01-1", '{"email":"x\'--"}'))
        self.tracker.status()
        bucket = self.tracker._bypass_samples[EP]["sqli"]
        self.assertEqual(len(bucket), 1)
        self.assertEqual(bucket[0]["body"], '{"email":"x\'--"}')
        self.assertEqual(bucket[0]["content_type"], "application/json")
        self.feed("access", access_line("w1-sqli-01-1"))  # late duplicate must not add
        self.tracker.status()
        self.assertEqual(len(self.tracker._bypass_samples[EP]["sqli"]), 1)

    def test_403_is_not_a_bypass(self):
        self.feed("access", access_line("w1-sqli-01-1", status=403))
        self.feed("audit", audit_line("w1-sqli-01-1", "{}", status=403))
        self.assertEqual(self.tracker.status(EP)["bypass_counts"].get(EP, 0), 0)

    def test_text_body_capped_but_full_body_kept_for_replay(self):
        big = '{"email":"' + "B" * 2000 + '"}'
        self.feed("access", access_line("w1-sqli-01-1"))
        self.feed("audit", audit_line("w1-sqli-01-1", big))
        text = self.samples()[0]
        self.assertLess(len(text), config.BYPASS_BODY_MAX_CHARS + 200)
        self.assertEqual(self.tracker.samples_for(EP)[0]["body"], big)


class StateAndFilters(TrackerCase):
    def test_legacy_string_samples_load(self):
        legacy = {"error_offset": 0, "access_offset": 0, "audit_offset": 0, "blocked_counts": {},
                  "bypass_counts": {"/x": 6},
                  "bypass_samples": {"/x": {"sqli": ["/x?_wave_marker=w1-sqli-01-1"]}}}
        with open(config.BREACH_STATE_FILE, "w") as f:
            json.dump(legacy, f)
        tracker = self.new_tracker()
        self.assertEqual(tracker.status("/x")["sample_bypasses"]["/x"]["sqli"],
                         ["/x?_wave_marker=w1-sqli-01-1"])

    def test_replay_traffic_never_counts_as_blocked(self):
        deny = ('2026/10/09 18:00:00 [error] ModSecurity: Access denied with code 403 (phase 2). '
                '[id "949110"] request: "GET {uri} HTTP/1.1", host: "localhost"')
        self.assertIsNone(log_parser._extract_blocked_endpoint(deny.format(uri=f"{EP}?_replay=1")))
        self.assertEqual(log_parser._extract_blocked_endpoint(deny.format(uri=f"{EP}?_wave_marker=w1-x")), EP)

    def test_compact_error_line(self):
        raw = ('2026/10/09 18:31:17 [error] 1#1: *1 [client 1.2.3.4] ModSecurity: Access denied with code 403 '
               '(phase 2). Matched "Operator `Ge\' with parameter `5\'" [file "/etc/x.conf"] [id "949110"] '
               '[msg "Inbound Anomaly Score Exceeded (Total Score: 10)"] [data ""] [tag "a"], client: 1.2.3.4, '
               'request: "POST /rest/user/login?_wave_marker=w1-sqli-01-1 HTTP/1.1", host: "localhost:8080"')
        out = compact_error_line(raw)
        self.assertIn("id=949110", out)
        self.assertIn("POST /rest/user/login", out)
        self.assertNotIn("[file", out)
        self.assertLess(len(out), len(raw) // 2)
        self.assertEqual(compact_error_line("nginx: [warn] something  "), "nginx: [warn] something")


if __name__ == "__main__":
    unittest.main()
