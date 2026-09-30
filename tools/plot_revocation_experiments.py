#!/usr/bin/env python3
"""Plot total time vs set size from experiment *_runs.csv files.

  python3 tools/plot_revocation_experiments.py [--results-dir DIR] [--plots-dir DIR]

Defaults: results/revocation/recorded -> results/revocation/plots.
"""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = Path(__file__).resolve().parents[1] / "results" / "revocation" / "recorded"
PLOTS_DIR = RESULTS_DIR.parent / "plots"
FIGSIZE = (5, 4)
FIGSIZE_COMBINED = (6, 4)
RECURRING_PCTS = [10, 50]
COLOR_DIRECT = "#d62728"   # red — full decrypt (leaky)
COLOR_LINK_10 = "#008000"  # green
COLOR_LINK_50 = "#17becf"  # lighter teal/cyan (contrasts with green)
COLOR_MPC = "#ff7f0e"      # orange
COLORS = {10: COLOR_LINK_10, 50: COLOR_LINK_50}
COMBINED_COLORS = {10: COLOR_LINK_10, 50: COLOR_LINK_50}
MIN_SET_SIZE = 10
PLOT_SIZES = [10, 20, 50, 100, 200, 500, 1000, 2000, 4000, 8000]


def at_least_min_size(rows: list[dict]) -> list[dict]:
    return [r for r in rows if int(r["set_size"]) >= MIN_SET_SIZE]


def setup_thesis_style() -> None:
    plt.style.use(
        {
            "axes.spines.left": True,
            "axes.spines.bottom": True,
            "axes.spines.top": True,
            "axes.spines.right": True,
            "xtick.bottom": True,
            "ytick.left": True,
            "axes.grid": True,
            "grid.linestyle": ":",
            "grid.linewidth": 0.5,
            "grid.alpha": 0.5,
            "grid.color": "k",
            "axes.edgecolor": "k",
            "axes.linewidth": 0.5,
        }
    )
    plt.rcParams["font.family"] = "serif"
    plt.rcParams["font.serif"] = ["Times New Roman"] + plt.rcParams["font.serif"]
    plt.rcParams["font.size"] = 14
    plt.rcParams["axes.labelsize"] = 16
    plt.rcParams["xtick.labelsize"] = 14
    plt.rcParams["ytick.labelsize"] = 14
    plt.rcParams["legend.fontsize"] = 14


def load_runs(path: Path) -> list[dict]:
    """Aggregate per-run CSV rows into the summary shape expected by the plots."""
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))

    groups: dict[tuple[int, int], list[dict]] = defaultdict(list)
    for row in rows:
        groups[(int(row["set_size"]), int(row["recurring_pct"]))].append(row)

    summary_rows = []
    for (set_size, recurring_pct), group in sorted(groups.items()):
        total_ms = [float(r["t_total_ms"]) for r in group]
        link_ms = [float(r["t_link_ms"]) for r in group]
        decrypt_ms = [float(r["t_decrypt_ms"]) for r in group]
        per_input_ms = [float(r["t_per_input_cft_ms"]) for r in group]
        after_filter = [float(r["n_after_filter"]) for r in group]

        summary_rows.append(
            {
                "benchmark": group[0]["benchmark"],
                "set_size": str(set_size),
                "recurring_pct": str(recurring_pct),
                "runs": str(len(group)),
                "pid_threshold": group[0]["pid_threshold"],
                "n_after_filter_mean": f"{statistics.fmean(after_filter):.3f}",
                "t_total_mean_ms": f"{statistics.fmean(total_ms):.3f}",
                "t_total_std_ms": f"{sample_std(total_ms):.3f}",
                "t_link_mean_ms": f"{statistics.fmean(link_ms):.3f}",
                "t_decrypt_mean_ms": f"{statistics.fmean(decrypt_ms):.3f}",
                "t_per_input_cft_mean_ms": f"{statistics.fmean(per_input_ms):.4f}",
            }
        )

    return summary_rows


def load_mpc_runs(path: Path) -> list[dict]:
    """Aggregate mpc-decrypt runs (no recurring_pct dimension)."""
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))

    groups: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        groups[int(row["set_size"])].append(row)

    summary_rows = []
    for set_size, group in sorted(groups.items()):
        total_ms = [float(r["t_total_ms"]) for r in group]
        per_input_ms = [float(r["t_per_input_cft_ms"]) for r in group]

        summary_rows.append(
            {
                "benchmark": group[0]["benchmark"],
                "set_size": str(set_size),
                "runs": str(len(group)),
                "t_total_mean_ms": f"{statistics.fmean(total_ms):.3f}",
                "t_total_std_ms": f"{sample_std(total_ms):.3f}",
                "t_per_input_cft_mean_ms": f"{statistics.fmean(per_input_ms):.4f}",
            }
        )

    return summary_rows


def load_mpc_fit(path: Path) -> float:
    with path.open(newline="") as f:
        row = next(csv.DictReader(f))
    return float(row["k_ms_per_pair"])


def mpc_predict(n: float, k_ms_per_pair: float) -> float:
    return k_ms_per_pair * n * (n - 1) / 2


def sample_std(values: list[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0



def apply_log_axes(ax: plt.Axes, rows: list[dict]) -> None:
    sizes = sorted({int(r["set_size"]) for r in rows})
    apply_log_axes_sizes(ax, sizes)


def apply_log_axes_sizes(ax: plt.Axes, sizes: list[int]) -> None:
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(sizes)
    ax.set_xticklabels([str(s) for s in sizes])


def plot_direct_decrypt(rows: list[dict], out_base: Path) -> None:
    """Direct decrypt: recurring % does not affect total time — one line (10% series)."""
    rows = at_least_min_size(rows)
    subset = sorted(
        (r for r in rows if int(r["recurring_pct"]) == 10),
        key=lambda r: int(r["set_size"]),
    )
    x = [int(r["set_size"]) for r in subset]
    y = [float(r["t_total_mean_ms"]) for r in subset]
    yerr = [float(r["t_total_std_ms"]) for r in subset]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.errorbar(
        x,
        y,
        yerr=yerr,
        marker="o",
        capsize=3,
        linewidth=1.5,
        color=COLOR_DIRECT,
        label="Direct decrypt",
    )
    ax.set_xlabel("CFT set size")
    ax.set_ylabel("Total time (ms)")
    apply_log_axes(ax, subset)
    fig.tight_layout()
    save_figure(fig, out_base)


def plot_link_decrypt(rows: list[dict], out_base: Path) -> None:
    rows = at_least_min_size(rows)
    fig, ax = plt.subplots(figsize=FIGSIZE)

    for pct in RECURRING_PCTS:
        subset = sorted(
            (r for r in rows if int(r["recurring_pct"]) == pct),
            key=lambda r: int(r["set_size"]),
        )
        x = [int(r["set_size"]) for r in subset]
        y = [float(r["t_total_mean_ms"]) for r in subset]
        yerr = [float(r["t_total_std_ms"]) for r in subset]
        ax.errorbar(
            x,
            y,
            yerr=yerr,
            marker="o",
            capsize=3,
            linewidth=1.5,
            label=f"{pct}% recurring ID",
            color=COLORS[pct],
        )

    ax.set_xlabel("CFT set size")
    ax.set_ylabel("Total time (ms)")
    ax.legend(loc="best")
    apply_log_axes(ax, rows)
    fig.tight_layout()
    save_figure(fig, out_base)


def series_by_recurring(rows: list[dict], recurring_pct: int) -> list[dict]:
    return sorted(
        (r for r in rows if int(r["recurring_pct"]) == recurring_pct),
        key=lambda r: int(r["set_size"]),
    )


def plot_combined(
    direct_rows: list[dict],
    link_rows: list[dict],
    mpc_rows: list[dict],
    k_ms_per_pair: float,
    out_base: Path,
) -> None:
    """Four curves: direct-decrypt, link-decrypt 10%/50%, mpc (measured + fit)."""
    direct_rows = at_least_min_size(direct_rows)
    link_rows = at_least_min_size(link_rows)
    mpc_rows = at_least_min_size(mpc_rows)

    fig, ax = plt.subplots(figsize=FIGSIZE_COMBINED)

    for label, rows, color in [
        ("Direct decrypt", series_by_recurring(direct_rows, 10), COLOR_DIRECT),
        ("Link-decrypt (10% recurring)", series_by_recurring(link_rows, 10), COMBINED_COLORS[10]),
        ("Link-decrypt (50% recurring)", series_by_recurring(link_rows, 50), COMBINED_COLORS[50]),
    ]:
        x = [int(r["set_size"]) for r in rows]
        y = [float(r["t_total_mean_ms"]) for r in rows]
        yerr = [float(r["t_total_std_ms"]) for r in rows]
        ax.errorbar(
            x,
            y,
            yerr=yerr,
            marker="o",
            capsize=3,
            linewidth=1.5,
            color=color,
            label=label,
        )

    mpc_rows = sorted(mpc_rows, key=lambda r: int(r["set_size"]))
    mpc_x = [int(r["set_size"]) for r in mpc_rows]
    mpc_y = [float(r["t_total_mean_ms"]) for r in mpc_rows]
    mpc_yerr = [float(r["t_total_std_ms"]) for r in mpc_rows]
    last_measured_n = mpc_x[-1]

    # Measured range: solid line through real data points.
    ax.errorbar(
        mpc_x,
        mpc_y,
        yerr=mpc_yerr,
        marker="o",
        capsize=3,
        linewidth=1.5,
        linestyle="-",
        color=COLOR_MPC,
        label="MPC decrypt",
    )

    # Beyond last measurement: dashed pairwise extrapolation t = k·n(n-1)/2.
    extrap_x = np.geomspace(last_measured_n, PLOT_SIZES[-1], 150)
    extrap_y = mpc_predict(extrap_x, k_ms_per_pair)
    ax.plot(
        extrap_x,
        extrap_y,
        linestyle="--",
        linewidth=1.5,
        color=COLOR_MPC,
    )

    ax.set_xlabel("CFT set size")
    ax.set_ylabel("Total time (ms)")
    ax.legend(loc="best")
    apply_log_axes_sizes(ax, PLOT_SIZES)
    fig.tight_layout()
    save_figure(fig, out_base)


def save_figure(fig: plt.Figure, out_base: Path) -> None:
    path = out_base.with_suffix(".pdf")
    fig.savefig(path, dpi=150)
    print(f"Wrote {path}")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=RESULTS_DIR,
        help="Directory containing *_runs.csv files",
    )
    parser.add_argument(
        "--plots-dir",
        type=Path,
        default=PLOTS_DIR,
        help="Directory for output PDFs",
    )
    args = parser.parse_args()
    setup_thesis_style()
    results_dir = args.results_dir
    plots_dir = args.plots_dir
    plots_dir.mkdir(parents=True, exist_ok=True)

    direct_path = results_dir / "direct-decrypt_runs.csv"
    link_path = results_dir / "link-decrypt_runs.csv"
    if not direct_path.is_file():
        raise SystemExit(f"Missing {direct_path}")
    if not link_path.is_file():
        raise SystemExit(f"Missing {link_path}")

    direct_rows = load_runs(direct_path)
    link_rows = load_runs(link_path)

    plot_direct_decrypt(direct_rows, plots_dir / "direct-decrypt_total_time")
    plot_link_decrypt(link_rows, plots_dir / "link-decrypt_total_time")

    mpc_runs_path = results_dir / "mpc-decrypt_runs.csv"
    mpc_fit_path = results_dir / "mpc-decrypt_fit.csv"
    if mpc_runs_path.is_file() and mpc_fit_path.is_file():
        mpc_rows = load_mpc_runs(mpc_runs_path)
        k_ms_per_pair = load_mpc_fit(mpc_fit_path)
        plot_combined(
            direct_rows,
            link_rows,
            mpc_rows,
            k_ms_per_pair,
            plots_dir / "revocation_combined_total_time",
        )
    else:
        print("Skipping combined plot (missing mpc-decrypt_runs.csv or mpc-decrypt_fit.csv)")


if __name__ == "__main__":
    main()
