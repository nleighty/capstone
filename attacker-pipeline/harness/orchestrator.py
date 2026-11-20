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
               generate=None, feedback: dict[str, mutate.SeedFeedback] | None = None) -> list[dict]:
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
    `seeds`/`generate` are injectable for offline tests. `feedback` (adaptive
    attacker only) maps seed id -> SeedFeedback from the previous wave; it's
    forwarded verbatim to `generate` per seed, and None (the default) reproduces
    the fixed attacker exactly.
    """
    seeds = SEEDS if seeds is None else seeds
    generate = mutate.generate_variants if generate is None else generate
    variants_per_seed = math.ceil(wave_size / len(seeds))

    def _feedback_for(seed: dict) -> mutate.SeedFeedback | None:
        return feedback.get(seed["id"]) if feedback else None

    pools: list[list[str]] = []
    for seed in seeds:
        variants = generate(seed["payload"], seed["type"], variants_per_seed,
                            feedback=_feedback_for(seed))
        pools.append(_dedupe(variants)[:variants_per_seed])

    for _ in range(config.WAVE_TOPUP_ROUNDS):
        short = [i for i, pool in enumerate(pools) if len(pool) < variants_per_seed]
        if not short or sum(len(p) for p in pools) >= wave_size:
            break
        for i in short:
            seed = seeds[i]
            # Same feedback as the initial call: a top-up is still the same seed
            # chasing the same previous-wave signal.
            extra = generate(seed["payload"], seed["type"], variants_per_seed - len(pools[i]),
                            feedback=_feedback_for(seed))
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


def _feedback_from_results(
    results: list[tuple[str, str, int]], limit: int
) -> dict[str, mutate.SeedFeedback]:
    """Turn one wave's fired results into per-seed feedback for the next wave.

    `results` is a list of (seed_id, mutated_payload, status_code) — the ONLY
    inputs the adaptive attacker is allowed to learn from. A 403 is a block,
    anything else is a bypass (the same "403 = blocked" convention the metrics
    writer uses); nothing about *why* a request was blocked enters here. Each
    seed's two buckets are capped to `limit` examples, kept in fire order so a
    run is reproducible and tests are stable.

    Pure and side-effect free, so the collection logic can be unit-tested
    without a live wave.
    """
    feedback: dict[str, mutate.SeedFeedback] = {}
    for seed_id, mutated, status_code in results:
        fb = feedback.setdefault(seed_id, mutate.SeedFeedback())
        bucket = fb.blocked if status_code == 403 else fb.bypassed
        if len(bucket) < limit:
            bucket.append(mutated)
    return feedback


def run(
    num_waves: int | None = None,
    wave_size: int | None = None,
    pause_seconds: int | None = None,
    label: str | None = None,
    defend: bool = False,
    adaptive: bool = False,
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

    With `adaptive=True`, each wave's per-seed results (which variants got a 403
    and which didn't) are fed back into the next wave's mutation prompt — "make
    more like these, avoid those". Wave 1 runs open-loop (no prior results yet).
    The attacker learns only from its own status codes, never from the WAF's
    rules or logs, so it stays a black box. Off by default, so the fixed
    attacker is still available for comparison runs.
    """
    num_waves = config.NUM_WAVES if num_waves is None else num_waves
    wave_size = config.WAVE_SIZE if wave_size is None else wave_size
    pause_seconds = config.WAVE_PAUSE_SECONDS if pause_seconds is None else pause_seconds

    log_reader = LogReader()
    metrics = MetricsWriter(label=label)
    agent_runs = defender.AgentRunWriter(metrics.path) if defend else None

    # Previous wave's per-seed feedback, carried into the next build_wave. Stays
    # None in non-adaptive runs and for wave 1 (nothing has been fired yet).
    feedback: dict[str, mutate.SeedFeedback] | None = None

    try:
        for wave_id in range(1, num_waves + 1):
            wave = build_wave(wave_id, wave_size, feedback=feedback)
            blocked_count = 0
            # (seed_id, mutated, status) for this wave, only collected when
            # adaptive — the raw material for next wave's feedback.
            wave_results: list[tuple[str, str, int]] = []

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

                if adaptive:
                    wave_results.append((seed["id"], item["mutated"], result.status_code))

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

            if adaptive:
                # Build this wave's feedback for the next build_wave. Done
                # before the agent runs: the attacker reacts to what the WAF did
                # to *this* wave, not to a patch the agent is about to write.
                feedback = _feedback_from_results(wave_results, config.ADAPTIVE_EXAMPLES_PER_SEED)

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
