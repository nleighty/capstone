"""Offline tests for core/rule_writer.py and core/rule_verifier.py.

rule_verifier's network call (_send) is stubbed, so these check its decision
logic and request rewriting without a live WAF. Whether a rule really blocks
anything is what verify_rule does against the real WAF - not testable offline.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from core import rule_verifier, rule_writer


class RuleWriter(unittest.TestCase):
    def setUp(self):
        self._orig = config.RULES_FILE
        self.path = os.path.join(tempfile.mkdtemp(), "rules.conf")
        config.RULES_FILE = self.path

    def tearDown(self):
        config.RULES_FILE = self._orig

    def test_percent_and_newlines_cannot_break_the_rule_line(self):
        # '%' in msg makes ModSecurity fail to parse the whole file (found
        # against the live nginx -t); a newline would split the one-line format.
        rule_writer.write_rule(1000000, "foo", "uses %20 and %2F, 100% sure\nsecond line 'q'")
        text = Path(self.path).read_text()
        self.assertEqual(text.count("\n"), 1)
        msg = text.split("msg:", 1)[1]
        self.assertNotIn("%", msg)
        self.assertIn("percent-20", msg)

    def test_same_id_overwrites_instead_of_appending(self):
        rule_writer.write_rule(1000000, "one", "d")
        rule_writer.write_rule(1000001, "other", "d")
        rule_writer.write_rule(1000000, "two", "d")
        lines = Path(self.path).read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("two", rule_writer.read_rule(1000000))
        self.assertNotIn("one", rule_writer.read_rule(1000000))

    def test_id_prefix_does_not_collide(self):  # id:1000001 vs id:10000010
        rule_writer.write_rule(1000001, "a", "d")
        self.assertTrue(rule_writer.read_rule(1000000).startswith("No existing rule"))

    def test_out_of_range_id_rejected(self):
        self.assertTrue(rule_writer.write_rule(5, "a", "d").startswith("Error"))


class Verifier(unittest.TestCase):
    def test_retag_strips_marker_keeps_other_params_byte_for_byte(self):
        out = rule_verifier._retag("/p?_wave_marker=w1-sqli-01-1&q=%27+OR%5Cr%5Cn1%3D1")
        self.assertEqual(out, "/p?q=%27+OR%5Cr%5Cn1%3D1&_replay=1")
        self.assertEqual(rule_verifier._retag("/p"), "/p?_replay=1")

    def _sample(self, text, method="POST", body: str | None = "{}"):
        return {"text": text, "method": method, "uri": "/rest/user/login?_wave_marker=w1-sqli-01-1",
                "body": body, "content_type": "application/json"}

    def _verify(self, statuses, samples):
        """Run verify() with _send returning scripted statuses (403 = blocked)."""
        with mock.patch.object(rule_verifier.time, "sleep"), \
             mock.patch.object(rule_verifier, "_send", side_effect=statuses):
            return rule_verifier.verify("/rest/user/login", samples)

    def test_pass_when_all_attacks_blocked_and_no_benign_blocked(self):
        n_benign = sum(len(v) for v in rule_verifier._BENIGN.values())
        r = self._verify([403, 403] + [200] * n_benign, [self._sample("a"), self._sample("b")])
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(r["benign_check"]["sent"], n_benign)  # all endpoints, not just the tripped one

    def test_fail_reports_both_gaps_and_false_positives(self):
        n_benign = sum(len(v) for v in rule_verifier._BENIGN.values())
        r = self._verify([403, 401] + [403] + [200] * (n_benign - 1), [self._sample("a"), self._sample("b")])
        self.assertTrue(r["verdict"].startswith("FAIL"))
        self.assertEqual([s["request"] for s in r["attack_replay"]["still_bypassing"]], ["b"])
        self.assertEqual(len(r["benign_check"]["falsely_blocked"]), 1)

    def test_post_without_body_is_not_replayed(self):
        n_benign = sum(len(v) for v in rule_verifier._BENIGN.values())
        r = self._verify([200] * n_benign, [self._sample("a", body=None)])
        self.assertEqual(r["attack_replay"]["not_replayable"], 1)
        self.assertEqual(r["attack_replay"]["replayed"], 0)


if __name__ == "__main__":
    unittest.main()
