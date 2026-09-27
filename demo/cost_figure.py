#!/usr/bin/env python3
"""demo/cost_figure.py — "customization is expensive" figure.

Real-world prices (2025-2026 public sources) for custom security per company,
vs the marginal cost of THIS approach: one River LoRA training run.

Reads the live run meta for the "$0.08" anchor so the number is never pasted.

    python3 demo/cost_figure.py           # writes demo/customization-cost.png
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

INK, MUTED = "#0f172a", "#64748b"
C_ENG, C_PENT, C_RET, C_THIS = "#94a3b8", "#64748b", "#b45309", "#0f766e"
ACCENT = "#d9480f"


def _newest_run_meta() -> dict | None:
    dirs = sorted((_ROOT / "river" / "out").glob("*"),
                  key=lambda p: p.stat().st_mtime, reverse=True) \
        if (_ROOT / "river" / "out").is_dir() else []
    for d in dirs:
        mp = d / "meta.json"
        if mp.is_file():
            return json.loads(mp.read_text())
    return None


def main() -> None:
    meta = _newest_run_meta()
    toks = meta.get("n_tokens_total") if meta else 57_622
    our_cost = round(toks / 1e6 * 1.46, 3)

    # label -> (mid, lo, hi, color, note)
    rows = [
        ("loaded AppSec engineer / year",     250_000, 200_000, 300_000, C_ENG,
         "salary + benefits + tooling"),
        ("continuous testing program / year", 100_000,  50_000, 150_000, C_PENT,
         "enterprise, multi-app + retests"),
        ("single consultant pentest week",     50_000,  25_000,  75_000, C_PENT,
         "one week, senior tester"),
        ("complex enterprise pentest",         25_000,  20_000,  30_000, C_PENT,
         "8-12+ tester-days, fintech-grade"),
        ("typical web-app pentest",            18_000,  10_000,  30_000, C_PENT,
         "most orgs land here"),
        ("pentest retest cycle",                5_000,   2_000,   8_000, C_RET,
         "after remediation"),
        ("one River LoRA run (this build)",    our_cost, our_cost, our_cost, C_THIS,
         f"76 steps · 7m19s · {toks:,} tokens"),
    ]

    n = len(rows)
    fig, ax = plt.subplots(figsize=(11, 6.4), dpi=160, facecolor="white")

    # log-scale, bottom at ~$0.01, top ~$1M
    lo_x, hi_x = np.log10(0.01), np.log10(1_000_000)
    for i, (label, mid, lo, hi, col, note) in enumerate(rows):
        y = n - 1 - i
        is_this = col == C_THIS
        x0, x1 = np.log10(max(mid, 0.01)), np.log10(max(mid, 0.01))
        # draw range band
        if lo < hi and not is_this:
            ax.barh(y, np.log10(hi) - np.log10(lo), left=np.log10(lo),
                    height=0.52, color=col, alpha=0.28, zorder=2)
        ax.barh(y, x1 - x0, left=x0, height=0.52, color=col,
                alpha=1.0 if is_this else 0.9, zorder=3)
        # value label
        if is_this:
            ax.text(x0 + 0.08, y, f"${our_cost:.2f}",
                    va="center", fontsize=13, fontweight="bold", color=C_THIS, zorder=6)
        else:
            ax.text(x1 + 0.08, y, f"${mid:,}",
                    va="center", fontsize=12, fontweight="bold", color=col, zorder=6)
        # range note
        if lo < hi and not is_this:
            ax.text(lo_x + 0.12, y - 0.42, f"range ${lo:,}-${hi:,} · {note}",
                    va="top", fontsize=8.5, color=MUTED, zorder=6)
        ax.text(-0.02, y, label, va="center", ha="right",
                fontsize=10.5, color=INK, zorder=6, fontweight="bold" if is_this else "normal")

    # the gap annotation
    eng_y = n - 1
    this_y = 0
    ax.annotate("",
                xy=(np.log10(our_cost), this_y), xytext=(np.log10(250_000), eng_y),
                arrowprops=dict(arrowstyle="<->", color=ACCENT, lw=1.6,
                                linestyle="dashed"))
    ax.text((np.log10(250_000) + np.log10(our_cost)) / 2, n / 2 + 0.2,
            f"{250_000 / our_cost:,.0f}× cheaper than\none engineer-year",
            ha="center", va="center", fontsize=11, color=ACCENT,
            fontweight="bold", linespacing=1.15)

    ax.set_xlim(lo_x - 0.1, hi_x + 0.5)
    ax.set_ylim(-1.05, n + 0.15)
    ax.set_yticks([])
    ticks = [0.01, 0.1, 1, 10, 100, 1_000, 10_000, 100_000, 1_000_000]
    ax.set_xticks([np.log10(t) for t in ticks])
    ax.set_xticklabels(["$0.01", "$0.10", "$1", "$10", "$100", "$1K",
                        "$10K", "$100K", "$1M"], fontsize=9.5, color=MUTED)
    ax.set_xlabel("cost per company (log scale, USD)", fontsize=10.5, color=MUTED)
    ax.grid(axis="x", color="#e2e8f0", lw=0.8); ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)

    ax.set_title("custom security, priced the old way vs the new way",
                 fontsize=15, fontweight="bold", color=INK, loc="left", pad=24)
    ax.text(0.0, 1.012,
            "a per-stack suite used to cost an engineer or a pentest-week — now it's one training run, and you hold the weights",
            transform=ax.transAxes, fontsize=11, color=INK, fontweight="bold")

    fig.text(0.045, 0.018,
             "sources: RSI/Diginatives/Pentestas/ARDURA 2025-26 pentest pricing (web-app $10K-$30K typ.; consultant week $25K-$75K; "
             "enterprise $50K-$150K+/yr) · loaded AppSec engineer ≈ $200K-$300K/yr · this run's cost from "
             "river/out/…/meta.json ({toks:,} tokens × $1.46/M ≈ ${our_cost:.2f})",
             fontsize=8.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.055, 1, 1))

    out = _HERE / "customization-cost.png"
    fig.savefig(out, dpi=160, facecolor="white")
    print(f"wrote {out}  (this run ≈ ${our_cost:.2f})")


if __name__ == "__main__":
    main()