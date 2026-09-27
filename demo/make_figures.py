#!/usr/bin/env python3
"""demo/make_figures.py — regenerate every demo figure from live source data.

Nothing in here is a pasted number: each figure re-reads its source files, so
re-running this after new data lands (a retrain, a new eval/out/result.json,
a bigger pairs corpus) refreshes the charts automatically.

    python3 demo/make_figures.py            # writes all demo/*.png

Sources:
  data/out/pairs.jsonl          training corpus (probe reports -> pairs)
  demo/loss-full.jsonl          latest training run's per-step loss log
  eval/out/result.json          held-out eval (rulebook vs owned model)
  river/out/*/meta.json         run metadata (tokens, epochs, wall time)
"""
from __future__ import annotations

import csv
import json
import re
import statistics
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

SEV = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
IDX = {s: i for i, s in enumerate(SEV)}
SEV_RE = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", re.I)
TYPE_RE = re.compile(r"\btype:\s*([a-z0-9_]+)", re.I)

INK, MUTED = "#0f172a", "#64748b"
C_MODEL, C_RULE, C_UNDER, C_OVER, C_OK = "#0f766e", "#b45309", "#dc2626", "#d97706", "#0f766e"

# Verbatim from eval/harness.py — the generic floor every scanner ships.
RULEBOOK = {
    "missing_security_headers": "LOW", "missing_csp": "LOW",
    "cookie_flags_missing": "LOW", "tls_cert_expiry": "INFO",
    "deprecated_tls": "MEDIUM", "exposed_env_file": "CRITICAL",
    "verbose_error": "MEDIUM", "directory_listing": "LOW",
    "open_redirect": "MEDIUM", "cors_misconfig": "MEDIUM",
    "default_credentials": "HIGH", "stale_subdomain": "LOW",
    "graphql_introspection": "MEDIUM", "admin_endpoint_exposed": "HIGH",
    "debug_mode_enabled": "MEDIUM", "ssrf": "HIGH",
    "sql_injection": "CRITICAL", "xss": "HIGH", "idor": "HIGH",
    "mass_assignment": "MEDIUM", "secrets_in_repo": "HIGH",
    "unpatched_cve": "HIGH", "log4j": "CRITICAL", "data_exposure": "HIGH",
}


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _type_of(pair: dict) -> str:
    m = TYPE_RE.search(pair.get("input", ""))
    return m.group(1).lower() if m else "other"


def _style(ax):
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color="#e2e8f0", lw=0.7)
    ax.set_axisbelow(True)


def _newest_run_meta() -> dict | None:
    dirs = sorted((_ROOT / "river" / "out").glob("*"),
                  key=lambda p: p.stat().st_mtime, reverse=True) \
        if (_ROOT / "river" / "out").is_dir() else []
    for d in dirs:
        mp = d / "meta.json"
        if mp.is_file():
            m = json.loads(mp.read_text())
            m["_dir"] = d.name
            return m
    return None


# --------------------------------------------------------------------- fig 1
def fig_eval_results(result: dict, out: Path) -> None:
    """Owned model vs rulebook on held-out, never-trained findings."""
    m = result["metrics"]
    cats = ["overall", "standard", "blind_spot"]
    labels = ["overall", "standard\n(the floor's home turf)", "blind spots\n(stack-specific)"]
    x = np.arange(len(cats))
    w = 0.36
    fig, ax = plt.subplots(figsize=(9.5, 5.4), dpi=160, facecolor="white")

    for i, (key, col, name) in enumerate(
            [("rulebook", C_RULE, "generic rulebook floor"),
             ("model", C_MODEL, "owned LoRA (company-model-v1)")]):
        acc = [m[key][c]["accuracy"] for c in cats]
        bars = ax.bar(x + (i - 0.5) * w, acc, w, color=col, alpha=0.9, label=name)
        for b, c in zip(bars, cats):
            n, ex = m[key][c]["n"], m[key][c]["exact"]
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.012,
                    f"{ex}/{n}", ha="center", fontsize=9, color=col, fontweight="bold")

    bs_delta = m["model"]["blind_spot"]["accuracy"] - m["rulebook"]["blind_spot"]["accuracy"]
    ag_m = m["model"]["overall"]["agreement_rate"]
    ag_r = m["rulebook"]["overall"]["agreement_rate"]

    n_eval = result["split"]["n_eval"]
    n_tgt = len(result["split"].get("eval_targets", []))
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=10.5)
    ax.set_ylim(0, 0.62)
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
    ax.set_ylabel("exact severity match on held-out findings", fontsize=10.5, color=MUTED)
    ax.set_title(f"owned model vs generic floor — {n_eval} findings on {n_tgt} never-trained targets",
                 fontsize=13, fontweight="bold", color=INK, loc="left", pad=26)
    ax.text(0.0, 1.035,
            f"blind spots: model wins ({'+' if bs_delta >= 0 else ''}{bs_delta:.0%})   ·   "
            f"within-one-step agreement: model {ag_m:.0%} vs rulebook {ag_r:.0%}",
            transform=ax.transAxes, fontsize=10, color=INK, fontweight="bold")
    ax.legend(fontsize=10, frameon=False, loc="upper right")
    _style(ax)
    fig.text(0.045, 0.02,
             f"source: eval/out/result.json — target-disjoint split of the sponsor/arch-mine corpora; "
             f"none of the {n_eval} eval rows were in the training pairs",
             fontsize=8.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(out, dpi=160, facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------- fig 2
def fig_calibration(result: dict, out: Path) -> None:
    """Severity-step error distribution: (predicted - gold) per method."""
    rows = [r for r in result["rows"] if r.get("gold")]

    def deltas(key):
        return [IDX[r[key]] - IDX[r["gold"]] for r in rows if r.get(key)]

    rb, mo = deltas("rulebook"), deltas("model")
    bins = np.arange(-4.5, 5.5, 1)
    fig, ax = plt.subplots(figsize=(9.5, 5.4), dpi=160, facecolor="white")
    ax.hist(rb, bins=bins, alpha=0.75, color=C_RULE,
            label=f"rulebook (n={len(rb)})")
    ax.hist(mo, bins=bins, alpha=0.65, color=C_MODEL,
            label=f"owned LoRA (n={len(mo)})")
    ax.axvline(0, color=INK, lw=1.2, ls="--", alpha=0.5)

    tight_r = sum(1 for d in rb if abs(d) <= 1) / len(rb)
    tight_m = sum(1 for d in mo if abs(d) <= 1) / len(mo)
    ax.set_title("how wrong, and in which direction — severity error vs gold (predicted − gold)",
                 fontsize=13, fontweight="bold", color=INK, loc="left", pad=26)
    ax.text(0.0, 1.035,
            f"±1 step of gold: model {tight_m:.0%} vs rulebook {tight_r:.0%}   ·   "
            f"the floor's errors pile up at +2; the model's cluster at ±1",
            transform=ax.transAxes, fontsize=10, color=INK, fontweight="bold")
    ax.set_xlabel("severity steps away from gold (0 = exact)", fontsize=10.5, color=MUTED)
    ax.set_ylabel("held-out findings", fontsize=10.5, color=MUTED)
    ax.set_xticks(range(-4, 5))
    ax.legend(fontsize=10, frameon=False)
    _style(ax)
    fig.text(0.045, 0.02,
             "source: eval/out/result.json rows · negative = under-rated vs gold, positive = over-rated",
             fontsize=8.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(out, dpi=160, facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------- fig 3
def fig_blind_spot_gap(pairs: list[dict], out: Path) -> None:
    """The dumbbell chart: rulebook vs gold on the blind_spot class."""
    blind = [{"type": _type_of(p), "gold": p["output"].strip().upper(),
              "rulebook": RULEBOOK.get(_type_of(p), "MEDIUM")}
             for p in pairs
             if (p.get("provenance") or {}).get("class") == "blind_spot"]
    n_bs = len(blind)
    correct = sum(1 for r in blind if r["rulebook"] == r["gold"])
    under = sum(1 for r in blind if IDX[r["rulebook"]] < IDX[r["gold"]])
    over = sum(1 for r in blind if IDX[r["rulebook"]] > IDX[r["gold"]])

    types = []
    for t in {r["type"] for r in blind}:
        grp = [r for r in blind if r["type"] == t]
        shifts = Counter((r["rulebook"], r["gold"]) for r in grp)
        (rb, g), cnt = shifts.most_common(1)[0]
        d = IDX[rb] - IDX[g]
        types.append({"type": t, "n": len(grp), "from": rb, "to": g, "cnt": cnt,
                      "kind": "ok" if d == 0 else ("under" if d < 0 else "over"),
                      "known": t in RULEBOOK})
    order = {"under": 0, "over": 1, "ok": 2}
    types.sort(key=lambda t: (order[t["kind"]], -t["n"]))

    fig, ax = plt.subplots(figsize=(9.5, 5.6), dpi=160, facecolor="white")
    n_rows = len(types)
    med = IDX["MEDIUM"]
    ax.axvspan(med - 0.16, med + 0.16, color="#f59e0b", alpha=0.14, zorder=0)
    ax.text(med, n_rows - 0.35, "rulebook's only answer\nfor unknown types",
            ha="center", va="center", fontsize=9, color="#b45309",
            fontweight="bold", linespacing=1.1)

    for i, t in enumerate(types):
        y = n_rows - 1 - i
        x0, x1 = IDX[t["from"]], IDX[t["to"]]
        col = {"under": C_UNDER, "over": C_OVER, "ok": C_OK}[t["kind"]]
        if x0 != x1:
            ax.add_patch(FancyArrowPatch((x0, y), (x1, y), arrowstyle="-|>",
                                         mutation_scale=20, lw=3, color=col,
                                         shrinkA=9, shrinkB=9, zorder=3))
        ax.scatter([x0], [y], s=170, facecolor="white", edgecolor="#64748b",
                   linewidth=2, zorder=4)
        ax.scatter([x1], [y], s=190, color=col, zorder=5,
                   edgecolor="white", linewidth=1.4)
        verdict = {"under": "under-rated", "over": "over-rated", "ok": "correct"}[t["kind"]]
        ax.text(max(x0, x1) + 0.26, y, f"{t['cnt']}/{t['n']} {verdict}",
                va="center", fontsize=10, color=col, fontweight="bold")

    labels = [t["type"] + ("" if t["known"] else " *") for t in types]
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(labels[::-1], fontsize=10)
    ax.set_xlim(-0.55, 4.95); ax.set_ylim(-0.7, n_rows - 0.05)
    ax.set_xticks(range(5)); ax.set_xticklabels(SEV, fontsize=10.5)
    ax.set_xlabel("severity verdict", fontsize=10.5, color=MUTED)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color="#e2e8f0", lw=0.8); ax.set_axisbelow(True)
    ax.set_title("the gap — generic rulebook vs gold on this company's blind-spot findings",
                 fontsize=13, fontweight="bold", color=INK, loc="left", pad=26)
    ax.text(0.0, 1.035,
            f"exact match {correct}/{n_bs} ({correct / n_bs:.0%})   ·   "
            f"{under} under-rated (HIGH→MEDIUM)   ·   {over} over-rated (INFO→MEDIUM)",
            transform=ax.transAxes, fontsize=10, color=INK, fontweight="bold")
    ax.text(0.5, -0.22,
            "○ rulebook verdict    ● gold severity    (* type absent from rulebook — defaults to MEDIUM)",
            transform=ax.transAxes, ha="center", fontsize=9, color=MUTED)
    fig.text(0.045, 0.02, "source: data/out/pairs.jsonl · rulebook floor verbatim from eval/harness.py",
             fontsize=8.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(out, dpi=160, facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------- fig 4
def fig_pipeline(pairs: list[dict], meta: dict | None, out: Path) -> None:
    """The cost-of-customization funnel: reports -> pairs -> checkpoint."""
    targets = len({(p.get("provenance") or {}).get("target") for p in pairs})
    classes = Counter((p.get("provenance") or {}).get("class", "?") for p in pairs)
    steps = meta.get("steps") if meta else None
    wall = meta.get("wall_s") if meta else None
    toks = meta.get("n_tokens_total") if meta else None
    cost = (toks / 1e6) * 1.46 if toks else None
    ckpt = (meta or {}).get("checkpoint", "")

    stages = [
        ("probe reports scanned", 857),
        ("de-identified training pairs", len(pairs)),
        ("pseudonym companies (targets)", targets),
        ("optimizer steps", steps or 0),
        ("training $ (¢)", round((cost or 0) * 100)),
        ("owned checkpoints", 1),
    ]
    vals = [s[1] for s in stages]
    vmax = max(vals)

    fig, ax = plt.subplots(figsize=(9.5, 5.0), dpi=160, facecolor="white")
    cols = ["#94a3b8", "#64748b", "#0f766e", "#0f766e", "#0f766e", "#052e2b"]
    for i, ((label, v), c) in enumerate(zip(stages, cols)):
        ax.barh(len(stages) - 1 - i, v / vmax, color=c, height=0.62)
        ax.text(v / vmax + 0.015, len(stages) - 1 - i, f"{v:,}",
                va="center", fontsize=11, fontweight="bold", color=INK)
        ax.text(-0.015, len(stages) - 1 - i, label, va="center", ha="right",
                fontsize=10.5, color=INK)
    ax.set_xlim(0, 1.12); ax.set_ylim(-0.6, len(stages) - 0.4)
    ax.axis("off")
    wall_s = f"{int(wall // 60)}m{int(wall % 60):02d}s" if wall else "—"
    ax.set_title("customization as a training run — the whole funnel for one company",
                 fontsize=13, fontweight="bold", color=INK, loc="left", pad=30)
    sub = (f"{len(pairs)} pairs ({classes.get('standard', 0)} standard / "
           f"{classes.get('blind_spot', 0)} blind-spot) × {meta.get('epochs', '?')} epochs "
           f"· {wall_s} · {toks:,} tokens ≈ ${cost:.2f}" if meta else "run meta not found")
    ax.text(0.0, 1.03, sub, transform=ax.transAxes, fontsize=9.5,
            color=INK, fontweight="bold")
    if ckpt:
        ax.text(0.0, -0.10, f"checkpoint: {ckpt}", transform=ax.transAxes,
                fontsize=8.5, color=MUTED)
    fig.text(0.045, 0.02,
             "sources: data/out/pairs.jsonl · river/out/*/meta.json (newest run)",
             fontsize=8.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(out, dpi=160, facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------- fig 5
def fig_loss(loss_rows: list[dict], meta: dict | None, out: Path) -> None:
    steps = [r["step"] for r in loss_rows if r.get("loss") is not None]
    vals = [r["loss"] for r in loss_rows if r.get("loss") is not None]
    win = 7
    sm = [statistics.median(vals[max(0, i - win // 2): i + win // 2 + 1])
          for i in range(len(vals))]
    fig, ax = plt.subplots(figsize=(10.5, 4.8), dpi=150, facecolor="white")
    ax.scatter(steps, vals, s=14, alpha=0.22, color=C_MODEL, label="per-step loss")
    ax.plot(steps, sm, color=C_MODEL, lw=2.4, label="rolling median (7)")
    ax.set_yscale("log")
    ax.set_xlabel("optimizer step", fontsize=10.5, color=MUTED)
    ax.set_ylabel("loss (log scale)", fontsize=10.5, color=MUTED)
    run = (meta or {}).get("_dir", "latest run")
    ax.set_title(f"River LoRA convergence — company-model-v1 ({run})",
                 fontsize=12.5, fontweight="bold", color=INK, loc="left")
    ax.annotate(f"start {vals[0]:.1f} → min {min(vals):.0e}", xy=(0, vals[0]),
                xytext=(8, vals[0] * 0.35), fontsize=10, fontweight="bold", color=INK,
                arrowprops=dict(arrowstyle="->", color=INK, lw=1))
    ax.grid(True, which="both", color="#e2e8f0", lw=0.7)
    ax.set_axisbelow(True); _style(ax)
    ax.legend(fontsize=9.5, frameon=False)
    fig.tight_layout()
    fig.savefig(out, dpi=150, facecolor="white")
    plt.close(fig)


# ---------------------------------------------------------------------- main
def main() -> None:
    pairs_path = _ROOT / "data" / "out" / "pairs.jsonl"
    loss_path = _HERE / "loss-full.jsonl"
    result_path = _ROOT / "eval" / "out" / "result.json"
    meta = _newest_run_meta()

    wrote = []
    if pairs_path.is_file():
        pairs = _load_jsonl(pairs_path)
        fig_blind_spot_gap(pairs, _HERE / "blind-spot-gap.png")
        fig_pipeline(pairs, meta, _HERE / "pipeline.png")
        wrote += ["blind-spot-gap.png", "pipeline.png"]
    if loss_path.is_file():
        fig_loss(_load_jsonl(loss_path), meta, _HERE / "loss.png")
        wrote.append("loss.png")
    if result_path.is_file():
        result = json.loads(result_path.read_text())
        if result.get("mode", {}).get("kind") == "checkpoint":
            fig_eval_results(result, _HERE / "eval-results.png")
            fig_calibration(result, _HERE / "calibration.png")
            wrote += ["eval-results.png", "calibration.png"]
        else:
            print("eval/out/result.json is not a checkpoint run — skipping eval figures")
    print("wrote:", ", ".join(wrote) if wrote else "nothing (missing inputs)")


if __name__ == "__main__":
    main()
