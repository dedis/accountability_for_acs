#!/usr/bin/env python3
"""Convert a raw pet_mpc sweep CSV into mpc-decrypt_{runs,summary,fit}.csv.

  python3 summarize.py <sweep/results.csv> [out_dir]

out_dir defaults to <workspace>/.work/revocation/out/mpc.
"""

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path


BENCHMARK = "mpc-decrypt"
RUNS_FIELDS = [
    "benchmark",
    "set_size",
    "recurring_pct",
    "run",
    "pid_threshold",
    "n_recurring_expected",
    "n_after_filter",
    "t_total_ms",
    "t_link_ms",
    "t_decrypt_ms",
    "t_per_input_cft_ms",
    "t_ngo_ms",
    "t_judge_ms",
    "t_police_ms",
]
SUMMARY_FIELDS = [
    "benchmark",
    "set_size",
    "runs",
    "n_after_filter_mean",
    "t_total_mean_ms",
    "t_total_std_ms",
    "t_link_mean_ms",
    "t_decrypt_mean_ms",
    "t_per_input_cft_mean_ms",
]
FIT_FIELDS = ["benchmark", "k_ms_per_pair", "formula", "r2", "n_samples"]


def to_float(v):
    try:
        return float(v) if v else 0.0
    except ValueError:
        return 0.0


def sample_std(values: list[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def n_pairs(n: int) -> float:
    return n * (n - 1) / 2


def fit_pairwise_model(rows: list[dict]) -> tuple[float, float]:
    """Through-origin regression: t_total_ms ≈ k · n(n-1)/2."""
    xs = [n_pairs(int(r["set_size"])) for r in rows]
    ys = [float(r["t_total_ms"]) for r in rows]
    denom = sum(x * x for x in xs)
    if denom == 0:
        return 0.0, 0.0
    k = sum(x * y for x, y in zip(xs, ys)) / denom
    ss_res = sum((y - k * x) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum(y * y for y in ys)
    r2 = 1.0 - ss_res / ss_tot if ss_tot else 0.0
    return k, r2


def parse_raw_rows(in_path: Path) -> list[dict]:
    rows = []
    with in_path.open(newline="") as f:
        for r in csv.DictReader(f):
            try:
                run = int(r["iter"])
                set_size = int(r["n_cfts"])
            except (KeyError, ValueError):
                continue

            pet = to_float(r.get("pet_phase_ms"))
            mpc = to_float(r.get("mpc_wall_ms")) or to_float(r.get("mpc_total_ms"))
            integ = to_float(r.get("integrity_phase_ms"))
            t_total = pet + mpc + integ

            rows.append(
                {
                    "benchmark": BENCHMARK,
                    "set_size": set_size,
                    "recurring_pct": "",
                    "run": run,
                    "pid_threshold": r.get("tau", ""),
                    "n_recurring_expected": r.get("n_recurring_expected", ""),
                    "n_after_filter": set_size,
                    "t_total_ms": round(t_total, 3),
                    "t_link_ms": 0.0,
                    "t_decrypt_ms": round(t_total, 3),
                    "t_per_input_cft_ms": round(t_total / set_size, 7),
                    "t_ngo_ms": "",
                    "t_judge_ms": "",
                    "t_police_ms": "",
                }
            )
    return rows


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def summarize_runs(rows: list[dict]) -> list[dict]:
    groups: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        groups[int(row["set_size"])].append(row)

    summary = []
    for set_size, group in sorted(groups.items()):
        total = [float(r["t_total_ms"]) for r in group]
        per_input = [float(r["t_per_input_cft_ms"]) for r in group]
        summary.append(
            {
                "benchmark": BENCHMARK,
                "set_size": set_size,
                "runs": len(group),
                "n_after_filter_mean": set_size,
                "t_total_mean_ms": f"{statistics.fmean(total):.3f}",
                "t_total_std_ms": f"{sample_std(total):.3f}",
                "t_link_mean_ms": "0.000",
                "t_decrypt_mean_ms": f"{statistics.fmean(total):.3f}",
                "t_per_input_cft_mean_ms": f"{statistics.fmean(per_input):.4f}",
            }
        )
    return summary


def main() -> None:
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: python3 summarize.py <sweep/results.csv> [out_dir]")

    in_path = Path(sys.argv[1]).resolve()
    if not in_path.is_file():
        sys.exit(f"input not found: {in_path}")

    runs = parse_raw_rows(in_path)
    if not runs:
        sys.exit("no rows after parsing")

    runs.sort(key=lambda r: (int(r["set_size"]), int(r["run"])))
    summary = summarize_runs(runs)
    k, r2 = fit_pairwise_model(runs)
    formula = f"t_total_ms ≈ {k:.4f}·set_size·(set_size - 1)/2"

    workspace = Path(__file__).resolve().parents[3]
    out_dir = (
        Path(sys.argv[2]).resolve()
        if len(sys.argv) == 3
        else workspace / ".work" / "revocation" / "out" / "mpc"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    runs_path = out_dir / "mpc-decrypt_runs.csv"
    summary_path = out_dir / "mpc-decrypt_summary.csv"
    fit_path = out_dir / "mpc-decrypt_fit.csv"

    write_csv(runs_path, RUNS_FIELDS, runs)
    write_csv(summary_path, SUMMARY_FIELDS, summary)
    write_csv(
        fit_path,
        FIT_FIELDS,
        [
            {
                "benchmark": BENCHMARK,
                "k_ms_per_pair": f"{k:.6f}",
                "formula": formula,
                "r2": f"{r2:.6f}",
                "n_samples": len(runs),
            }
        ],
    )

    print(f"wrote {len(runs)} rows to {runs_path}")
    print(f"wrote {len(summary)} rows to {summary_path}")
    print(f"wrote fit to {fit_path}")
    print(formula)


if __name__ == "__main__":
    main()
