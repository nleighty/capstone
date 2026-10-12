"""Offline tests for core/mutate.py's degenerate-variant filter.

No Ollama/WAF/network: _is_valid_variant is pure, and generate_variants is
exercised with its model call stubbed. Run from attacker-pipeline/:
    python -m unittest discover -s tests -t .
"""

import unittest
from unittest import mock

import config
from core import mutate


class IsValidVariant(unittest.TestCase):
    def test_drops_degenerate_output(self):
        # The exact junk seen leaking from the line-split JSON fallback.
        for junk in ("[", "]", "", "   ", "[\n", "a", "1"):
            self.assertFalse(mutate._is_valid_variant(junk, "sqli"), junk)
            self.assertFalse(mutate._is_valid_variant(junk, "xss"), junk)

    def test_keeps_genuine_sqli_including_encoded(self):
        for v in (
            " OR 1=1%20--%20",
            " OR '1''='1 ",
            "admin@juice-sh.op&#x27--",
            "1%27%2F%2A%2A%2FORDER%2F%2A%2A%2FBY%2F%2A%2A%2F10--",  # fully URL-encoded
            "x' UNION SELECT id,email FROM Users--",
        ):
            self.assertTrue(mutate._is_valid_variant(v, "sqli"), v)

    def test_keeps_genuine_xss_including_encoded(self):
        for v in (
            "<svg/onLoAd=alert(1)>",
            "%3CsCrIpT%3EalErT%281%29%3C%2FsCrIpT%3E",  # fully URL-encoded
            "<img src=x onerror=alert(1)>",
            '"><script>alert(document.cookie)</script>',
        ):
            self.assertTrue(mutate._is_valid_variant(v, "xss"), v)

    def test_unknown_family_skips_signal_check_but_not_length(self):
        # A new family the filter doesn't model shouldn't be gutted by a
        # signal list written for other families...
        self.assertTrue(mutate._is_valid_variant("http://169.254.169.254/latest/", "ssrf"))
        # ...but the family-agnostic length guard still drops obvious junk.
        self.assertFalse(mutate._is_valid_variant("[", "ssrf"))

    def test_min_length_is_configurable(self):
        with mock.patch.object(config, "MIN_VARIANT_LENGTH", 100):
            self.assertFalse(mutate._is_valid_variant("' OR 1=1--", "sqli"))


class GenerateVariants(unittest.TestCase):
    def _run(self, responses, n=5, attack_type="sqli"):
        """Drive generate_variants with _safe_generate returning each item of
        `responses` in turn (one per model call)."""
        with mock.patch.object(mutate, "_safe_generate", side_effect=responses):
            return mutate.generate_variants("' OR 1=1--", attack_type, n)

    def test_filters_junk_out_of_the_returned_list(self):
        # Two valid + two junk, asking for 2, so the kept count meets n and
        # the retry path (covered separately below) doesn't fire.
        resp = '["[", "' + "' OR 1=1--" + '", "]", "x\' OR \'1\'=\'1"]'
        out = self._run([resp], n=2)
        self.assertNotIn("[", out)
        self.assertNotIn("]", out)
        self.assertEqual(len(out), 2)
        self.assertTrue(all(mutate._is_valid_variant(v, "sqli") for v in out))

    def test_retry_fires_when_filter_leaves_it_short(self):
        # First response is all junk -> deduped stays < n -> one retry fires.
        first = '["[", "]", "[", "]"]'
        second = '["\' OR 1=1--", "\' OR \'a\'=\'a", "\' UNION SELECT 1--"]'
        calls = []

        def fake(_prompt):
            calls.append(1)
            return first if len(calls) == 1 else second
        with mock.patch.object(mutate, "_safe_generate", side_effect=fake):
            out = mutate.generate_variants("' OR 1=1--", "sqli", 5)
        self.assertEqual(len(calls), 2)          # retried exactly once
        self.assertGreaterEqual(len(out), 3)
        self.assertTrue(all(mutate._is_valid_variant(v, "sqli") for v in out))


if __name__ == "__main__":
    unittest.main()
