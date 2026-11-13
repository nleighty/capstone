"""Offline tests for harness/orchestrator.build_wave: even seed coverage and
a guaranteed wave size. The model is replaced by a fake generator, so no
Ollama/WAF is needed. Run from attacker-pipeline/:
    python -m unittest discover -s tests -t .
"""

import unittest
from collections import Counter

from harness import orchestrator
from payloads.seeds import SEEDS


def over_generator(payload, attack_type, n):
    """Like the real model on a good day: returns MORE than asked (the
    behavior that starved the last seeds in the baseline)."""
    return [f"{payload} v{i}" for i in range(n + 4)]


class BuildWave(unittest.TestCase):
    def test_every_seed_fires_and_size_is_exact(self):
        wave = orchestrator.build_wave(1, 50, generate=over_generator)
        self.assertEqual(len(wave), 50)
        per_seed = Counter(item["seed"]["id"] for item in wave)
        self.assertEqual(set(per_seed), {s["id"] for s in SEEDS})  # xss-06/07/08 included
        self.assertLessEqual(max(per_seed.values()) - min(per_seed.values()), 1)

    def test_extra_variant_rotates_across_waves(self):
        # 50 / 16 seeds leaves 2 seeds with one extra each wave; over 8 waves
        # every seed should get the extra exactly once, not seeds 1-2 every time.
        totals = Counter()
        for wave_id in range(1, 9):
            totals.update(item["seed"]["id"] for item in orchestrator.build_wave(wave_id, 50, generate=over_generator))
        self.assertEqual(set(totals.values()), {25})

    def test_short_seed_is_topped_up(self):
        calls = Counter()

        def flaky(payload, attack_type, n):
            # First call for each seed returns only one variant (as if the
            # junk filter dropped the rest); later calls cooperate.
            calls[payload] += 1
            if calls[payload] == 1:
                return [f"{payload} first"]
            return [f"{payload} first"] + [f"{payload} retry{i}" for i in range(n)]

        wave = orchestrator.build_wave(1, 50, generate=flaky)
        self.assertEqual(len(wave), 50)

    def test_broken_model_gives_short_wave_without_hanging(self):
        wave = orchestrator.build_wave(1, 50, generate=lambda p, t, n: [])
        self.assertEqual(wave, [])

    def test_payload_ids_unique(self):
        wave = orchestrator.build_wave(3, 50, generate=over_generator)
        self.assertEqual(len({item["payload_id"] for item in wave}), 50)


if __name__ == "__main__":
    unittest.main()
