"""Wave loop: the only module that imports from both core.* and harness.*.

Wires the offensive LLM -> WAF core layer to the metrics/log-correlation
harness layer, without either core module knowing metrics exist.
"""

import math
import time

import config
from core import fire, mutate
from harness import defender
from harness.log_reader import LogReader
from harness.metrics_writer import MetricsWriter
from payloads.seeds import SEEDS


def build_wave(wave_id: int, wave_size: int, seeds: list[dict] | None = None,
               generate=None) -> list[dict]:
    """Turn the fixed seed list into one wave of exactly `wave_size` mutated
    payloads (when the model cooperates), spread evenly across seeds.

    Rewritten after the Step 3 code review (2026-11-13). The old version
    flattened each seed's variants *in seed order* and cut at `wave_size`, and
    since generate_variants often returns more than asked, the seeds at the
    end of the list (xss-06/07/08) never fired at all in the baseline. Now:

    1. Each seed's variants are trimmed to `variants_per_seed`.
    2. **Top-up:** a seed that came up short (junk filtered, timeout) is asked
       again for the shortfall, at most config.WAVE_TOPUP_ROUNDS extra rounds,
       so junk is *replaced* rather than just dropped - but a broken model
       can't hang the run.
    3. **Round-robin:** variants are taken one per seed in turn (seed 1 #1,
       seed 2 #1, ..., seed 1 #2, ...), so cutting to `wave_size` trims every
       seed by at most one instead of dropping whole seeds. The starting seed
       rotates each wave, so the seeds that get the one extra variant change
       from wave to wave instead of always being the first ones listed.

    If the wave is still short after the top-up rounds, it's returned short
    and the caller logs it - an honest smaller wave beats a silent one.
    `seeds`/`generate` are injectable for offline tests.
    """
    seeds = SEEDS if seeds is None else seeds
    generate = mutate.generate_variants if generate is None else generate
    variants_per_seed = math.ceil(wave_size / len(seeds))

    pools: list[list[str]] = []
    for seed in seeds:
        variants = generate(seed["payload"], seed["type"], variants_per_seed)
        pools.append(_dedupe(variants)[:variants_per_seed])

    for _ in range(config.WAVE_TOPUP_ROUNDS):
        short = [i for i, pool in enumerate(pools) if len(pool) < variants_per_seed]
        if not short or sum(len(p) for p in pools) >= wave_size:
            break
        for i in short:
            seed = seeds[i]
            extra = generate(seed["payload"], seed["type"], variants_per_seed - len(pools[i]))
            pools[i] = _dedupe(pools[i] + extra)[:variants_per_seed]

    # Continue the round-robin where the previous wave left off.
    start = ((wave_id - 1) * wave_size) % len(seeds)
    order = list(range(start, len(seeds))) + list(range(start))
    wave = []
    for round_idx in range(variants_per_seed):
        for i in order:
            if round_idx < len(pools[i]):
                seed = seeds[i]
                # payload_id doubles as the WAF log correlation marker
                # (core.fire sends it verbatim as `_wave_marker`), and is
                # human-greppable.
                payload_id = f"w{wave_id}-{seed['id']}-{round_idx + 1}"
                wave.append({"seed": seed, "mutated": pools[i][round_idx], "payload_id": payload_id})
    return wave[:wave_size]


def _dedupe(variants: list[str]) -> list[str]:
    """Drop case-insensitive repeats, keeping the first occurrence. A top-up
    call can return a variant the seed already has, and firing it twice would
    just double-count one payload."""
    seen, out = set(), []
    for v in variants:
        if v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
    return out


def run(
    num_waves: int | None = None,
    wave_size: int | None = None,
    pause_seconds: int | None = None,
    label: str | None = None,
    defend: bool = False,
) -> str:
    """Fire `num_waves` waves of `wave_size` payloads each at the WAF,
    writing one row per fired payload to a fresh metrics CSV. Returns the
    CSV path. Arguments default to config.py's values when omitted — the
    explicit-override path exists for `run.py`'s CLI flags (smoke testing,
    or a `label="demo"` run that should never be mistaken for baseline data).

    With `defend=True`, the defensive agent runs after every wave, the last
    included (harness/defender.py), so each later wave hits the patched WAF; its
    results go to a paired `_agent.csv`. Without it, this is the original
    attacker-only baseline run.
    """
    num_waves = config.NUM_WAVES if num_waves is None else num_waves
    wave_size = config.WAVE_SIZE if wave_size is None else wave_size
    pause_seconds = config.WAVE_PAUSE_SECONDS if pause_seconds is None else pause_seconds

    log_reader = LogReader()
    metrics = MetricsWriter(label=label)
    agent_runs = defender.AgentRunWriter(metrics.path) if defend else None

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
            if len(wave) < wave_size:
                # build_wave's top-up rounds couldn't fill the wave (the model
                # kept returning junk or timing out). Fire it short and say
                # so, rather than hiding it - α compares waves, so a smaller
                # one needs to be visible. The CSV row count shows the real size.
                print(f"WARNING: wave {wave_id} is short: {len(wave)}/{wave_size} payloads")

            if agent_runs is not None:
                # Runs after every wave, the last one included, so no wave's
                # breaches go unanswered and the WAF is left patched at the
                # end. The last wave's response gets an MTTM like any other,
                # but no later wave exists to measure its effect on bypasses.
                # The agent call replaces the idle pause: it's the thing the
                # pause was originally reserved for.
                agent_runs.append(defender.run_agent(wave_id, time.time()))
            elif wave_id != num_waves and pause_seconds > 0:
                time.sleep(pause_seconds)
    finally:
        metrics.close()
        if agent_runs is not None:
            agent_runs.close()

    print(f"metrics written to {metrics.path}")
    if agent_runs is not None:
        print(f"agent runs written to {agent_runs.path}")
    return metrics.path
