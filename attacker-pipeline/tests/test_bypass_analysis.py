"""Offline tests for harness/bypass_analysis.py.

Pure in-memory rows - no CSV, no WAF, no network (and notably no `ollama`/
`httpx` import, so these run even where the attacker pipeline's runtime deps
aren't installed). Run from attacker-pipeline/:
    python -m unittest tests.test_bypass_analysis
"""

import unittest

from harness import bypass_analysis as ba


def row(mutated, blocked, attack_type="sqli", endpoint="/rest/user/login", seed="' OR 1=1--"):
    return {
        "attack_type": attack_type,
        "endpoint": endpoint,
        "seed_payload": seed,
        "mutated_payload": mutated,
        "status_code": "403" if blocked else "401",
        "blocked": "True" if blocked else "False",
    }


class FeatureDetectors(unittest.TestCase):
    def test_url_and_double_url_encoding(self):
        self.assertTrue(ba._FEATURES["url_encoded"]("%3Cscript%3E"))
        self.assertTrue(ba._FEATURES["double_url_encoded"]("%253Cscript"))
        self.assertFalse(ba._FEATURES["double_url_encoded"]("%3Cscript"))

    def test_mixed_case_keyword_only_on_mixed(self):
        self.assertTrue(ba._FEATURES["mixed_case_keyword"]("sElEcT 1"))
        self.assertFalse(ba._FEATURES["mixed_case_keyword"]("select 1"))
        self.assertFalse(ba._FEATURES["mixed_case_keyword"]("SELECT 1"))

    def test_inline_comment_and_entity(self):
        self.assertTrue(ba._FEATURES["inline_comment"]("' OR 1=1--"))
        self.assertTrue(ba._FEATURES["inline_comment"]("a/*x*/b"))
        self.assertTrue(ba._FEATURES["html_entity"]("&#x3c;script&gt;"))

    def test_decoded_len_measures_decoded_content(self):
        # %3C%3E -> "<>" (2), not the 6-char escaped form.
        self.assertEqual(ba._decoded_len("%3C%3E"), 2)


class Analyze(unittest.TestCase):
    def test_bypass_uses_blocked_column_then_status_fallback(self):
        self.assertTrue(ba._is_bypass({"blocked": "False", "status_code": "401"}))
        self.assertFalse(ba._is_bypass({"blocked": "True", "status_code": "403"}))
        # Fallback when blocked column is absent/empty.
        self.assertFalse(ba._is_bypass({"blocked": "", "status_code": "403"}))
        self.assertTrue(ba._is_bypass({"status_code": "200"}))

    def test_overall_and_grouping(self):
        rows = [
            row("' OR 1=1--", blocked=False),
            row("' OR '1'='1", blocked=False),
            row("<script>alert(1)</script>", blocked=True, attack_type="xss",
                endpoint="/rest/products/search", seed="<script>alert(1)</script>"),
        ]
        rep = ba.analyze(rows)
        self.assertEqual(rep["overall"]["total"], 3)
        self.assertEqual(rep["overall"]["bypassed"], 2)
        self.assertAlmostEqual(rep["by_group"]["sqli /rest/user/login"]["bypass_rate"], 1.0)
        self.assertAlmostEqual(rep["by_group"]["xss /rest/products/search"]["bypass_rate"], 0.0)

    def test_feature_lift_positive_when_feature_favors_bypass(self):
        rows = [
            row("' OR 1=1--", blocked=False),   # has inline_comment
            row("' OR 1=1--", blocked=False),   # has inline_comment
            row("' OR '1'='1", blocked=True),   # no comment
        ]
        lift = ba.analyze(rows)["feature_lift"]["inline_comment"]
        self.assertGreater(lift["lift"], 0)
        self.assertEqual(lift["count_in_bypasses"], 2)

    def test_top_bypass_seeds_counts_only_bypasses(self):
        rows = [
            row("a' OR 1=1--", blocked=False, seed="' OR 1=1--"),
            row("b' OR 1=1--", blocked=False, seed="' OR 1=1--"),
            row("c' OR '1'='1", blocked=True, seed="' OR '1'='1"),
        ]
        top = ba.analyze(rows)["top_bypass_seeds"]
        self.assertEqual(top["' OR 1=1--"], 2)
        self.assertNotIn("' OR '1'='1", top)  # it was blocked, not a bypass

    def test_empty_rows_do_not_crash(self):
        rep = ba.analyze([])
        self.assertEqual(rep["overall"]["total"], 0)
        self.assertEqual(rep["overall"]["bypass_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
