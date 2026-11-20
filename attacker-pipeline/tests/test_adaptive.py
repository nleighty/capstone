"""Offline tests for the adaptive attacker (`run.py --adaptive`): collecting
per-seed feedback from a wave's status codes, forwarding it into the next
wave's mutation calls, and rendering it into the prompt.

No Ollama/WAF/network: the collector is pure, build_wave takes an injected
generator, and the prompt render stubs the model call (same seam as
test_mutate_filter). Run from attacker-pipeline/:
    python -m unittest discover -s tests -t .
"""

import unittest
from unittest import mock

from core import mutate
from harness import orchestrator


class FeedbackFromResults(unittest.TestCase):
    """orchestrator._feedback_from_results: 403 vs. not, capped, in fire order."""

    def test_buckets_by_403_only(self):
        results = [
            ("sqli-01", "A", 403),   # blocked
            ("sqli-01", "B", 401),   # bypass (not 403)
            ("sqli-01", "C", 500),   # bypass (not 403)
            ("sqli-01", "D", 200),   # bypass
        ]
        fb = orchestrator._feedback_from_results(results, limit=10)
        self.assertEqual(fb["sqli-01"].blocked, ["A"])
        self.assertEqual(fb["sqli-01"].bypassed, ["B", "C", "D"])

    def test_caps_each_bucket_in_fire_order(self):
        results = [("xss-01", f"b{i}", 200) for i in range(5)]       # 5 bypasses
        results += [("xss-01", f"k{i}", 403) for i in range(5)]      # 5 blocks
        fb = orchestrator._feedback_from_results(results, limit=2)
        # First two of each, in the order they were fired.
        self.assertEqual(fb["xss-01"].bypassed, ["b0", "b1"])
        self.assertEqual(fb["xss-01"].blocked, ["k0", "k1"])

    def test_keyed_per_seed(self):
        results = [("sqli-01", "x", 200), ("xss-02", "y", 403)]
        fb = orchestrator._feedback_from_results(results, limit=3)
        self.assertEqual(set(fb), {"sqli-01", "xss-02"})
        self.assertEqual(fb["sqli-01"].bypassed, ["x"])
        self.assertEqual(fb["xss-02"].blocked, ["y"])
        self.assertEqual(fb["xss-02"].bypassed, [])

    def test_only_status_codes_are_consumed(self):
        # The tuple the collector accepts has no slot for a rule id / log line,
        # so there is nowhere for defender internals to enter the attacker. This
        # test documents that contract: a 3-field tuple is all it takes.
        fb = orchestrator._feedback_from_results([("sqli-01", "x", 403)], limit=1)
        self.assertEqual(fb["sqli-01"].blocked, ["x"])


class BuildWaveForwarding(unittest.TestCase):
    """build_wave hands each seed its OWN feedback, and None without it."""

    _SEEDS = [
        {"id": "sqli-01", "type": "sqli", "payload": "p1"},
        {"id": "xss-01", "type": "xss", "payload": "p2"},
    ]

    def _recording_generate(self, calls):
        def gen(payload, attack_type, n, feedback=None):
            calls.append((payload, feedback))
            return [f"{payload} v{i}" for i in range(n)]
        return gen

    def test_each_seed_gets_its_own_feedback(self):
        calls = []
        feedback = {
            "sqli-01": mutate.SeedFeedback(bypassed=["b1"], blocked=["k1"]),
            "xss-01": mutate.SeedFeedback(bypassed=["b2"]),
        }
        orchestrator.build_wave(1, 4, seeds=self._SEEDS,
                                generate=self._recording_generate(calls), feedback=feedback)
        by_payload = {payload: fb for payload, fb in calls}
        self.assertEqual(by_payload["p1"], feedback["sqli-01"])
        self.assertEqual(by_payload["p2"], feedback["xss-01"])

    def test_missing_seed_feedback_is_none(self):
        # A seed absent from the feedback dict (e.g. it didn't fire last wave)
        # gets None, i.e. open-loop for that seed, not a crash.
        calls = []
        feedback = {"sqli-01": mutate.SeedFeedback(bypassed=["b1"])}
        orchestrator.build_wave(1, 4, seeds=self._SEEDS,
                                generate=self._recording_generate(calls), feedback=feedback)
        by_payload = {payload: fb for payload, fb in calls}
        self.assertIsNone(by_payload["p2"])

    def test_no_feedback_passes_none(self):
        # The fixed attacker path: every generate call gets feedback=None.
        calls = []
        orchestrator.build_wave(1, 4, seeds=self._SEEDS,
                                generate=self._recording_generate(calls))
        self.assertTrue(all(fb is None for _, fb in calls))


class FeedbackPrompt(unittest.TestCase):
    """generate_variants renders feedback into the prompt, additively."""

    def _capture_prompt(self, feedback):
        """Run generate_variants with the model stubbed, returning the prompt it
        built. The stub returns a full valid array so the short-wave retry (a
        second prompt) never fires."""
        prompts = []

        def fake(prompt):
            prompts.append(prompt)
            return '["\' OR 1=1--", "\' OR \'a\'=\'a", "\' UNION SELECT 1--"]'

        with mock.patch.object(mutate, "_safe_generate", side_effect=fake):
            mutate.generate_variants("' OR 1=1--", "sqli", 3, feedback=feedback)
        return prompts[0]

    def test_none_feedback_matches_fixed_prompt(self):
        prompt = self._capture_prompt(None)
        self.assertNotIn("Feedback from the previous wave", prompt)

    def test_empty_feedback_adds_nothing(self):
        prompt = self._capture_prompt(mutate.SeedFeedback())
        self.assertNotIn("Feedback from the previous wave", prompt)

    def test_both_buckets_render_under_their_headers(self):
        fb = mutate.SeedFeedback(bypassed=["GOTTHROUGH1"], blocked=["WASBLOCKED1"])
        prompt = self._capture_prompt(fb)
        self.assertIn("Feedback from the previous wave", prompt)
        self.assertIn("were NOT blocked", prompt)
        self.assertIn("GOTTHROUGH1", prompt)
        self.assertIn("WERE blocked", prompt)
        self.assertIn("WASBLOCKED1", prompt)

    def test_only_bypassed_omits_the_avoid_half(self):
        prompt = self._capture_prompt(mutate.SeedFeedback(bypassed=["GOTTHROUGH1"]))
        self.assertIn("were NOT blocked", prompt)
        self.assertNotIn("WERE blocked", prompt)

    def test_only_blocked_omits_the_more_like_these_half(self):
        prompt = self._capture_prompt(mutate.SeedFeedback(blocked=["WASBLOCKED1"]))
        self.assertIn("WERE blocked", prompt)
        self.assertNotIn("were NOT blocked", prompt)


if __name__ == "__main__":
    unittest.main()
