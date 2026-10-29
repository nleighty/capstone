"""CLI for bypass-pattern analysis over the harness's metrics CSVs.

Sibling to run.py (which *produces* the metrics); this *reads* them back and
reports what got through the WAF and which obfuscation techniques correlate
with bypassing. See harness/bypass_analysis.py for the method and its
deliberate test-harness-only scope.

Usage:
  python analyze.py                 # analyze the newest CSV in metrics/
  python analyze.py path/to.csv ... # analyze specific CSV(s), merged
"""

import csv
import glob
import os
import sys

import config
from harness import bypass_analysis


def _latest_csv() -> str | None:
    candidates = sorted(glob.glob(os.path.join(config.METRICS_DIR, "*.csv")))
    return candidates[-1] if candidates else None


def _load_rows(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for path in paths:
        with open(path, newline="") as f:
            rows.extend(csv.DictReader(f))
    return rows


def _fmt_pct(x: float) -> str:
    return f"{x * 100:5.1f}%"


def _print_report(report: dict, paths: list[str]) -> None:
    o = report["overall"]
    print(f"\nBypass-pattern analysis over {len(paths)} file(s):")
    for p in paths:
        print(f"  - {p}")
    print(
        f"\nOverall: {o['bypassed']}/{o['total']} bypassed "
        f"({_fmt_pct(o['bypass_rate'])}), {o['blocked']} blocked."
    )
    print(
        f"Avg decoded length: {o['avg_decoded_len_bypassed']:.1f} (bypassed) "
        f"vs {o['avg_decoded_len_blocked']:.1f} (blocked)."
    )

    print("\nBypass rate by attack type + endpoint:")
    for name, s in report["by_group"].items():
        print(f"  {_fmt_pct(s['bypass_rate'])}  {s['bypassed']:>4}/{s['total']:<4}  {name}")

    print("\nObfuscation technique — how much more common among bypasses than blocks:")
    print("  (lift = %-of-bypasses minus %-of-blocked; positive = correlated with getting through)")
    ranked = sorted(report["feature_lift"].items(), key=lambda kv: kv[1]["lift"], reverse=True)
    for name, f in ranked:
        print(
            f"  lift {f['lift'] * 100:+6.1f}pp   "
            f"bypass {_fmt_pct(f['pct_of_bypasses'])}  blocked {_fmt_pct(f['pct_of_blocked'])}  "
            f"({f['count_in_bypasses']} bypasses)   {name}"
        )

    print("\nSeeds producing the most bypasses:")
    for seed, n in list(report["top_bypass_seeds"].items())[:10]:
        print(f"  {n:>4}  {seed!r}")
    print()


def main(argv: list[str]) -> int:
    paths = argv[1:] if len(argv) > 1 else [p for p in (_latest_csv(),) if p]
    if not paths:
        print(f"No metrics CSVs found in {config.METRICS_DIR}. Run run.py first.", file=sys.stderr)
        return 1
    rows = _load_rows(paths)
    if not rows:
        print("No rows to analyze.", file=sys.stderr)
        return 1
    _print_report(bypass_analysis.analyze(rows), paths)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
