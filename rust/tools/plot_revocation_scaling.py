#!/usr/bin/env python3
"""Revocation scaling plots (ProveVerify + CFT + packed revocation).

Vector PDFs for thesis.

  python3 rust/tools/plot_revocation_scaling.py

Reads results/<stack>/{mobile,server}/prove_verify_revocation.json and writes
results/<stack>/plots/revocation_scaling_<stack>.pdf.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import MaxNLocator

# ─── edit colors here ───────────────────────────────────────────────────────
COLORS = {
    "prover_mobile": "#1f77b4",  # vibrant blue  (most likely prover case)
    "prover_server": "#9ecae1",  # dimmer blue
    "verifier_server": "#f6651d",  # bright orange (most likely verifier case)
    "verifier_mobile": "#fdae6b",  # dimmer orange
}
# ────────────────────────────────────────────────────────────────────────────

RESULTS = Path(__file__).resolve().parents[1] / "results"
THESIS_IMG = (
    Path(__file__).resolve().parents[2]
    / "report"
    / "thesis_template"
    / "images"
    / "evaluations"
)

FILES = {
    (stack, env): RESULTS / stack / env / "prove_verify_revocation.json"
    for stack in ("standard", "zk-friendly")
    for env in ("mobile", "server")
}

MEAS_LOG2 = np.array([12, 16, 20, 24], dtype=float)
EXT_MAX = 29

# Sized for side-by-side thesis figures (~0.48\linewidth each).
FIGSIZE = (6.5, 4.8)
FONT_LABEL = 21
FONT_TICK = 19
FONT_LEGEND = 18


def configure_mpl() -> None:
    # Match tools/plot_revocation_experiments.py (thesis style).
    mpl.rcParams.update(
        {
            "pdf.fonttype": 42,  # TrueType in PDF (sharp in viewers)
            "ps.fonttype": 42,
            "font.family": "serif",
            "font.serif": [
                "Times New Roman",
                "Times",
                "Nimbus Roman",
                "DejaVu Serif",
            ],
            "mathtext.fontset": "stix",  # serif-like math for $\log_2 N$
            "axes.linewidth": 0.9,
            "lines.solid_capstyle": "round",
            "lines.solid_joinstyle": "round",
            "figure.dpi": 120,
            "savefig.bbox": None,
            "savefig.pad_inches": 0.02,
        }
    )


def load_series(path: Path):
    d = json.loads(path.read_text())
    xs, prove, verify = [], [], []
    for r in d["byScale"]:
        xs.append(r["revocLog2"])
        # Prefer proverTotal (zk: witness+prove; longfellow: prove_ns). Fallback: prove.
        if r.get("proverTotal") and r["proverTotal"].get("avg") is not None:
            prove.append(r["proverTotal"]["avg"])
        else:
            prove.append(r["prove"]["avg"])
        verify.append(r["verify"]["avg"])
    return np.array(xs, dtype=float), np.array(prove), np.array(verify)


def fit_lin(x, y):
    return np.polyfit(x, y, 1)


def plot_stack(stack_name: str, stem: str) -> Path:
    series = {env: load_series(FILES[(stack_name, env)]) for env in ("mobile", "server")}

    fits = {}
    for env in ("mobile", "server"):
        x, p, v = series[env]
        sp, ip = fit_lin(x, p)
        if stack_name == "zk-friendly":
            v_use = v[1:] if len(v) > 1 else v
            fits[env] = {"prove": (sp, ip), "verify": ("const", float(np.mean(v_use)))}
        else:
            sv, iv = fit_lin(x, v)
            fits[env] = {"prove": (sp, ip), "verify": (sv, iv)}

    def y_prove(env, xs):
        a, b = fits[env]["prove"]
        return a * xs + b

    def y_verify(env, xs):
        f = fits[env]["verify"]
        if f[0] == "const":
            return np.full_like(xs, f[1], dtype=float)
        a, b = f
        return a * xs + b

    x_ext = np.arange(MEAS_LOG2[-1], EXT_MAX + 1, 1, dtype=float)

    # Draw order: dimmer lines under brighter ones.
    specs = [
        ("server", "prove", "prover_server", "Prover (server)", 2.4),
        ("mobile", "verify", "verifier_mobile", "Verifier (mobile)", 2.4),
        ("mobile", "prove", "prover_mobile", "Prover (mobile)", 2.8),
        ("server", "verify", "verifier_server", "Verifier (server)", 2.8),
    ]

    fig, ax = plt.subplots(figsize=FIGSIZE)

    for env, kind, ckey, label, lw in specs:
        x, p, v = series[env]
        y_pts = p if kind == "prove" else v
        yfun = y_prove if kind == "prove" else y_verify
        color = COLORS[ckey]
        ax.plot(MEAS_LOG2, yfun(env, MEAS_LOG2), color=color, lw=lw, ls="-", zorder=2)
        ax.plot(x_ext, yfun(env, x_ext), color=color, lw=lw, ls="--", zorder=2)
        ax.plot(
            x,
            y_pts,
            "o",
            color=color,
            ms=9.0,
            mew=0.8,
            mec="white",
            zorder=3,
            label=label,
        )

    ax.set_xlabel(r"$\log_2 N$ (users)", fontsize=FONT_LABEL, labelpad=8)
    ax.set_ylabel("Time (ms)", fontsize=FONT_LABEL, labelpad=8)
    ax.set_xticks([12, 16, 20, 24, 29])
    ax.set_xlim(11.5, 29.5)
    ax.tick_params(axis="both", labelsize=FONT_TICK, pad=4, width=0.9, length=4.5)
    ax.yaxis.set_major_locator(MaxNLocator(nbins=6, min_n_ticks=5))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.grid(True, which="major", alpha=0.28, lw=0.6)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    y_max = 0.0
    for env in ("mobile", "server"):
        y_max = max(
            y_max,
            float(np.max(y_prove(env, x_ext))),
            float(np.max(y_verify(env, x_ext))),
        )
    # Modest headroom only (legend sits below the axes).
    y_top = y_max * 1.08
    if stack_name == "standard":
        y_top = min(y_top, 9800.0)
    ax.set_ylim(0, y_top)

    desired = [
        "Prover (mobile)",
        "Prover (server)",
        "Verifier (server)",
        "Verifier (mobile)",
    ]
    handles, labels = ax.get_legend_handles_labels()
    hmap = dict(zip(labels, handles))
    ax.legend(
        [hmap[n] for n in desired],
        desired,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.20),
        ncol=2,
        frameon=False,
        fontsize=FONT_LEGEND,
        borderaxespad=0.0,
        labelspacing=0.45,
        columnspacing=1.4,
        handletextpad=0.5,
        handlelength=1.8,
    )

    fig.subplots_adjust(left=0.17, right=0.98, top=0.97, bottom=0.28)

    out_dir = RESULTS / stack_name / "plots"
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf = out_dir / f"{stem}.pdf"
    fig.savefig(pdf, format="pdf")
    plt.close(fig)
    print(f"Wrote {pdf}")
    return pdf


def copy_to_thesis(pdfs: list[Path]) -> None:
    if not THESIS_IMG.is_dir():
        print(f"Skip thesis copy (missing {THESIS_IMG})")
        return
    for pdf in pdfs:
        dest = THESIS_IMG / pdf.name
        dest.write_bytes(pdf.read_bytes())
        print(f"Copied → {dest}")


if __name__ == "__main__":
    configure_mpl()
    pdfs = [
        plot_stack("standard", "revocation_scaling_standard"),
        plot_stack("zk-friendly", "revocation_scaling_zkfriendly"),
    ]
    copy_to_thesis(pdfs)
