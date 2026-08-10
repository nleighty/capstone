"""Wave loop: the only module that imports from both core.* and harness.*.

Wires the offensive LLM -> WAF core layer to the metrics/log-correlation
harness layer, without either core module knowing metrics exist.
"""

import math
import time

import config
from core import fire, mutate
from harness.log_reader import LogReader
from harness.metrics_writer import MetricsWriter
from payloads.seeds import SEEDS


def build_wave(wave_id: int, wave_size: int) -> list[dict]:
    """Turn the fixed seed list into one wave's worth of mutated payloads.

    Requests `ceil(wave_size / len(SEEDS))` variants per seed so every seed
    gets roughly even coverage, then flattens and truncates to exactly
    `wave_size` — since a seed can return more or fewer variants than asked
    (see core.mutate.generate_variants), the raw candidate count is only
    ever >= wave_size, never short.
    """
    variants_per_seed = math.ceil(wave_size / len(SEEDS))
    candidates = []
    for seed in SEEDS:
        variants = mutate.generate_variants(seed["payload"], seed["type"], variants_per_seed)
        for idx, variant in enumerate(variants, start=1):
            # payload_id doubles as the WAF log correlation marker (core.fire
            # sends it verbatim as `_wave_marker`), and is human-greppable.
            payload_id = f"w{wave_id}-{seed['id']}-{idx}"
            candidates.append({"seed": seed, "mutated": variant, "payload_id": payload_id})
    return candidates[:wave_size]


def run(
    num_waves: int | None = None,
    wave_size: int | None = None,
    pause_seconds: int | None = None,
    label: str | None = None,
) -> str:
    """Fire `num_waves` waves of `wave_size` payloads each at the WAF,
    writing one row per fired payload to a fresh metrics CSV. Returns the
    CSV path. Arguments default to config.py's values when omitted — the
    explicit-override path exists for `run.py`'s CLI flags (smoke testing,
    or a `label="demo"` run that should never be mistaken for baseline data).
    """
    num_waves = config.NUM_WAVES if num_waves is None else num_waves
    wave_size = config.WAVE_SIZE if wave_size is None else wave_size
    pause_seconds = config.WAVE_PAUSE_SECONDS if pause_seconds is None else pause_seconds

    log_reader = LogReader()
    metrics = MetricsWriter(label=label)

    try:
        for wave_id in range(1, num_waves + 1):
            wave = build_wave(wave_id, wave_size)
            blocked_count = 0

            for item in wave:
                seed = item["seed"]
                result = fire.send_payload(seed, item["mutated"], item["payload_id"])

                matched_rule_id = None
                if result.status_code == 403:
                    # Only look up a log line for blocked requests — a 200/401/500
                    # never produced a ModSecurity block line, so skipping the
                    # scan (and its poll delay) for those avoids needless log I/O.
                    matched_rule_id = log_reader.find_matched_rule(item["payload_id"])
                    blocked_count += 1

                metrics.append_row(
                    wave_id=wave_id,
                    payload_id=item["payload_id"],
                    attack_type=seed["type"],
                    seed_payload=seed["payload"],
                    mutated_payload=item["mutated"],
                    endpoint=seed["endpoint"],
                    status_code=result.status_code,
                    matched_rule_id=matched_rule_id,
                    timestamp=result.sent_at,
                )

            bypassed = len(wave) - blocked_count
            print(
                f"wave {wave_id}: {bypassed}/{len(wave)} bypassed, "
                f"{blocked_count}/{len(wave)} blocked"
            )

            if wave_id != num_waves and pause_seconds > 0:
                # No defensive agent exists yet (Sprint 3-4), so this pause
                # doesn't currently let anything patch — it's here so the
                # wave-loop shape is already correct when the agent lands.
                time.sleep(pause_seconds)
    finally:
        metrics.close()

    print(f"metrics written to {metrics.path}")
    return metrics.path
