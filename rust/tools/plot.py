#!/usr/bin/env python3
"""Local runs of the benchmarks against the recorded results.

Reads results/<stack>/<env>/<benchmark>.json (env: server, local-2cpu,
local-12cpu) and results/revocation/{recorded,local}/*.csv; writes vector PDFs
into results/<stack>/plots/:

  local_vs_server_presentation_<stack>.pdf   witness / prove / verify
  local_vs_server_revocation_<stack>.pdf     prover and verify vs log2 N
  local_vs_server_merkle_vs_flat_<stack>.pdf prover time vs k, one panel per n
  local_vs_server_revocation_cft.pdf         Rust vs Node, direct and link decrypt

  python3 rust/tools/plot.py [--results DIR]

--results moves the local runs and the PDFs; the recorded results are always
read from rust/results/.

A figure is skipped when its local results are missing; a series is dropped
when only its file is missing (e.g. no 12-CPU run).
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# Recorded results (server, mobile, Node.js runs) always come from here.
RECORDED = Path(__file__).resolve().parents[1] / "results"
# Local runs and the PDFs; --results overrides it.
RESULTS = RECORDED
# Figure stem suffix -> results/ folder.
STACK_DIRS = {"zkfriendly": "zk-friendly", "standard": "standard", "revocation": "revocation"}

# One color and marker per environment, in fixed order (validated palette;
# markers carry identity where color alone is weak).
ENVS = {
    "server": {"label": "Server (recorded)", "color": "#2a78d6", "marker": "o"},
    "local": {"label": "Local, 2 CPU", "color": "#eb6834", "marker": "s"},
    "local12": {"label": "Local, 12 CPU", "color": "#1baf7a", "marker": "^"},
}
INK = "#3b3b38"

FONT_LABEL = 12
FONT_TICK = 10
FONT_TITLE = 12
FONT_LEGEND = 10


def configure_mpl() -> None:
    # Same thesis style as plot_revocation_scaling.py.
    mpl.rcParams.update(
        {
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "Nimbus Roman", "DejaVu Serif"],
            "mathtext.fontset": "stix",
            "axes.linewidth": 0.8,
            "axes.edgecolor": INK,
            "axes.labelcolor": INK,
            "xtick.color": INK,
            "ytick.color": INK,
            "text.color": INK,
            "lines.solid_capstyle": "round",
            "savefig.pad_inches": 0.02,
        }
    )


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def style(ax, ylabel: str | None = None) -> None:
    ax.grid(True, axis="y", alpha=0.28, lw=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(labelsize=FONT_TICK, width=0.8, length=3.5)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=FONT_LABEL)


def legend_below(fig, envs: list[str], extra: list[tuple] = ()) -> None:
    handles = [
        mpl.lines.Line2D([], [], color=ENVS[e]["color"], marker=ENVS[e]["marker"],
                         lw=2, ms=7, mec="white", mew=0.8)
        for e in envs
    ] + [h for h, _ in extra]
    labels = [ENVS[e]["label"] for e in envs] + [lab for _, lab in extra]
    fig.legend(handles, labels, loc="lower center", ncol=len(labels),
               frameon=False, fontsize=FONT_LEGEND, handlelength=2.2)


def available(envs: dict[str, Path], variants: tuple[str, ...] = ("",)) -> dict[str, Path]:
    """The environments whose result files all exist; empty if the local run is missing."""
    found = {
        env: path for env, path in envs.items()
        if all(Path(str(path).format(v=v)).is_file() for v in variants)
    }
    return found if "local" in found else {}


def skipped(stem: str) -> None:
    print(f"Skip {stem} (no local results)")


def save(fig, stem: str) -> None:
    """Writes `stem`.pdf into the plots folder of the stack it names."""
    # Every figure plots durations.
    fig.text(0.01, 0.99, r"$\downarrow$ Lower is better", ha="left", va="top",
             fontsize=FONT_LEGEND, style="italic")
    out_dir = RESULTS / STACK_DIRS[stem.rsplit("_", 1)[1]] / "plots"
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf = out_dir / f"{stem}.pdf"
    fig.savefig(pdf, format="pdf")
    plt.close(fig)
    print(f"Wrote {pdf}")


# ─── presentation: grouped bars, one panel per phase ────────────────────────


def presentation(stack: str, envs: dict[str, Path], phases: list[str],
                 titles: list[str]) -> None:
    variants = [("prove_verify", "With CFT"), ("prove_verify_no_cft", "Without CFT")]
    envs = available(envs, tuple(v for v, _ in variants))
    if not envs:
        return skipped(f"local_vs_server_presentation_{stack}")
    data = {
        env: {v: load(Path(str(path).format(v=v)))["statsMs"] for v, _ in variants}
        for env, path in envs.items()
    }

    width_in = 3.2 * len(phases)
    fig, axes = plt.subplots(1, len(phases), figsize=(width_in, 3.6))
    width = 0.8 / len(envs)
    for ax, phase, title in zip(np.atleast_1d(axes), phases, titles):
        for i, env in enumerate(envs):
            xs = np.arange(len(variants)) + (i - (len(envs) - 1) / 2) * width
            ys = [data[env][v][phase]["avgMs"] for v, _ in variants]
            bars = ax.bar(xs, ys, width * 0.92, color=ENVS[env]["color"],
                          edgecolor="white", linewidth=1.0)
            ax.bar_label(bars, fmt="%.0f" if max(ys) >= 10 else "%.1f",
                         fontsize=FONT_TICK - 2, padding=2)
        ax.set_xticks(np.arange(len(variants)), [lab for _, lab in variants])
        ax.set_title(title, fontsize=FONT_TITLE)
        ax.margins(y=0.15)
        style(ax, "Time (ms)" if ax is np.atleast_1d(axes)[0] else None)
    legend_below(fig, list(envs))
    fig.subplots_adjust(left=0.7 / width_in, right=0.99, top=0.88, bottom=0.2, wspace=0.3)
    save(fig, f"local_vs_server_presentation_{stack}")


# ─── revocation scaling: lines vs log2 N ────────────────────────────────────


def scale_series(path: Path, key: str):
    rows = load(path)["byScale"]
    return [r["revocLog2"] for r in rows], [r[key]["avg"] for r in rows]


def revocation(stack: str, envs: dict[str, Path]) -> None:
    envs = available(envs)
    if not envs:
        return skipped(f"local_vs_server_revocation_{stack}")
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.6))
    for ax, key, title in zip(axes, ("proverTotal", "verify"), ("Prover", "Verifier")):
        for env, path in envs.items():
            xs, ys = scale_series(path, key)
            ax.plot(xs, ys, color=ENVS[env]["color"], marker=ENVS[env]["marker"],
                    lw=2, ms=7, mec="white", mew=0.8)
        ax.set_xticks([12, 16, 20, 24])
        ax.set_xlabel(r"$\log_2 N$ (users)", fontsize=FONT_LABEL)
        ax.set_title(title, fontsize=FONT_TITLE)
        ax.set_ylim(bottom=0)
        ax.margins(y=0.12)
        style(ax, "Time (ms)" if ax is axes[0] else None)
    legend_below(fig, list(envs))
    fig.subplots_adjust(left=0.1, right=0.98, top=0.9, bottom=0.27, wspace=0.28)
    save(fig, f"local_vs_server_revocation_{stack}")


# ─── merkle vs flat: prover time vs k, one panel per n ──────────────────────


def merkle_vs_flat(stack: str, envs: dict[str, Path]) -> None:
    envs = available(envs)
    if not envs:
        return skipped(f"local_vs_server_merkle_vs_flat_{stack}")
    data = {env: load(path) for env, path in envs.items()}
    # One panel per n the local run measured; each series plots what it has.
    totals = sorted(int(n) for n in data["local"]["merkle"])
    width_in = max(2.6 * len(totals), 7.2)  # the legend needs about 7 in
    fig, axes = plt.subplots(1, len(totals), figsize=(width_in, 3.4), sharey=True,
                             squeeze=False)
    axes = axes[0]
    for ax, n in zip(axes, totals):
        for env in envs:
            for mode, ls in (("flat", "-"), ("merkle", "--")):
                cells = data[env][mode].get(str(n), {})
                ks = sorted(int(k) for k in cells)
                ys = [cells[str(k)]["avgProverMs"] for k in ks]
                ax.plot(ks, ys, color=ENVS[env]["color"], marker=ENVS[env]["marker"],
                        ls=ls, lw=1.8, ms=6, mec="white", mew=0.8)
        ax.set_xscale("log", base=2)
        ax.set_xticks([1, 2, 4, 8, 16])
        ax.get_xaxis().set_major_formatter(mpl.ticker.ScalarFormatter())
        ax.set_xlabel("Disclosed attributes $k$", fontsize=FONT_LABEL)
        ax.set_title(f"$n = {n}$ attributes", fontsize=FONT_TITLE)
        style(ax, "Prover time (ms)" if ax is axes[0] else None)
    # Shared y: fix the floor once, after every panel has autoscaled.
    axes[0].set_ylim(bottom=0)
    modes = [(mpl.lines.Line2D([], [], color=INK, ls="-", lw=1.8), "Flat hash"),
             (mpl.lines.Line2D([], [], color=INK, ls="--", lw=1.8), "Merkle")]
    legend_below(fig, list(envs), modes)
    fig.subplots_adjust(left=0.7 / width_in, right=0.99, top=0.9, bottom=0.3, wspace=0.12)
    save(fig, f"local_vs_server_merkle_vs_flat_{stack}")


# ─── revocation CFT: Rust (local, native) vs Node (recorded) ───────────────


def read_summary(path: Path) -> dict[int, list[tuple[int, float]]]:
    by_pct: dict[int, list[tuple[int, float]]] = {}
    with path.open() as f:
        for row in csv.DictReader(f):
            by_pct.setdefault(int(row["recurring_pct"]), []).append(
                (int(row["set_size"]), float(row["t_total_mean_ms"])))
    return by_pct


def revocation_cft() -> None:
    sources = {"server": RECORDED / "revocation" / "recorded",
               "local": RESULTS / "revocation" / "local"}
    labels = {"server": "Node.js (recorded)", "local": "Rust (local, native)"}
    if not (sources["local"] / "direct-decrypt_summary.csv").is_file():
        return skipped("local_vs_server_cft_revocation")
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.6), sharey=True)
    for ax, bench, title in zip(axes, ("direct-decrypt", "link-decrypt"),
                                ("Direct decrypt", "Link then decrypt")):
        for env, root in sources.items():
            for pct, rows in read_summary(root / f"{bench}_summary.csv").items():
                rows.sort()
                ax.plot([r[0] for r in rows], [r[1] for r in rows],
                        color=ENVS[env]["color"], marker=ENVS[env]["marker"],
                        ls="-" if pct == 10 else "--", lw=1.8, ms=6, mec="white", mew=0.8)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("CFTs in the batch", fontsize=FONT_LABEL)
        ax.set_title(title, fontsize=FONT_TITLE)
        ax.grid(True, which="major", axis="both", alpha=0.28, lw=0.6)
        style(ax, "Total time (ms)" if ax is axes[0] else None)
    handles = [mpl.lines.Line2D([], [], color=ENVS[e]["color"], marker=ENVS[e]["marker"],
                                lw=2, ms=7, mec="white", mew=0.8) for e in sources]
    handles += [mpl.lines.Line2D([], [], color=INK, ls="-", lw=1.8),
                mpl.lines.Line2D([], [], color=INK, ls="--", lw=1.8)]
    fig.legend(handles, [labels[e] for e in sources] + ["10 % recurring", "50 % recurring"],
               loc="lower center", ncol=4, frameon=False, fontsize=FONT_LEGEND)
    fig.subplots_adjust(left=0.1, right=0.98, top=0.9, bottom=0.27, wspace=0.12)
    save(fig, "local_vs_server_cft_revocation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--results", type=Path, default=RESULTS, help="results root")
    RESULTS = parser.parse_args().results.resolve()
    configure_mpl()
    for stack, name in (("zkfriendly", "zk-friendly"), ("standard", "standard")):
        root = RESULTS / name
        envs = {"server": RECORDED / name / "server", "local": root / "local-2cpu",
                "local12": root / "local-12cpu"}
        if stack == "standard":
            del envs["local12"]
        phases = (["witness", "prove", "verify"], ["Witness", "Prove (rapidsnark)", "Verify"]) \
            if stack == "zkfriendly" else (["proverTotal", "verify"], ["Prover", "Verifier"])
        presentation(stack, {e: d / "{v}.json" for e, d in envs.items()}, *phases)
        revocation(stack, {e: d / "prove_verify_revocation.json" for e, d in envs.items()})
        merkle_vs_flat(stack, {e: envs[e] / "merkle_vs_flat.json" for e in ("server", "local")})
    revocation_cft()
