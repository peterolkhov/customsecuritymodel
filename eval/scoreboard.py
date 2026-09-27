#!/usr/bin/env python3
"""eval/scoreboard.py — render eval results into a self-contained scoreboard.html.

Takes the result dict produced by eval/harness.py (or a JSON file) and emits a
single self-contained HTML file: inline CSS, no network assets, judge-facing.

    python3 eval/scoreboard.py --result eval/out/result.json --out eval/scoreboard.html
    python3 eval/scoreboard.py --result - < eval/out/result.json   # read stdin
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent

_SEV_STEPS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_COLORS = {
    "model": "#0f766e",      # teal-700
    "rulebook": "#64748b",   # slate-500
    "tie": "#475569",
    "stub": "#b45309",       # amber-700
    "ok": "#166534",         # green-800
    "no": "#991b1b",         # red-800
}


def _fmt_pct(x: float) -> str:
    return f"{x:.0%}"


def _bar(acc: float, width: int = 120) -> str:
    w = max(2, round(acc * width))
    return (f'<span class="bar"><span class="fill" style="width:{w}px"></span></span>'
            f'<span class="num">{_fmt_pct(acc)}</span>')


def _mode_banner(mode: dict) -> str:
    kind = mode.get("kind")
    if kind == "stub":
        return (f'<div class="banner stub"><strong>STUB MODE</strong> — '
                f'{html.escape(mode.get("note", ""))} '
                f'Scoreboard shows the pipeline, not the owned model.</div>')
    if kind == "checkpoint":
        ck = html.escape(mode.get("checkpoint", "") or "")
        return (f'<div class="banner live"><strong>OWNED MODEL</strong> — scored via '
                f'checkpoint <code>{ck}</code></div>')
    return (f'<div class="banner live"><strong>MODEL</strong> — {html.escape(mode.get("note", ""))}</div>')


def _method_row(name: str, m: dict, color: str) -> str:
    cells = []
    for key in ("overall", "standard", "blind_spot"):
        b = m[key]
        cells.append(f'<td><span class="n">{b["exact"]}/{b["n"]}</span> {_bar(b["accuracy"])}</td>')
        cells.append(f'<td><span class="n">{b["agreement"]}/{b["n"]}</span> {_bar(b["agreement_rate"])}</td>')
    return (f'<tr class="{name}"><th>{html.escape(name)}</th>' + "".join(cells) + "</tr>")


def _winner_line(winner: dict) -> str:
    o, bs = winner["overall"], winner["blind_spot"]
    def label(w):
        return {"model": "owned model", "rulebook": "rulebook floor", "tie": "tie"}[w]
    return (f'<div class="winner">Overall winner: <b>{label(o)}</b> &middot; '
            f'Blind-spot winner: <b>{label(bs)}</b></div>')


def _detail_table(rows: list[dict]) -> str:
    out = ["<table class='detail'><thead><tr>"
           "<th>target</th><th>class</th><th>type</th><th>gold</th>"
           "<th>rulebook</th><th>hit?</th><th>model</th><th>hit?</th></tr></thead><tbody>"]
    for r in rows:
        g = html.escape(r["gold"] or "?")
        rb = html.escape(r["rulebook"] or "?")
        mdl = html.escape(r["model"] or "?")
        rb_ok = "ok" if r["gold"] is not None and r["rulebook"] == r["gold"] else "no"
        m_ok = "ok" if r["gold"] is not None and r["model"] == r["gold"] else "no"
        out.append(
            f'<tr><td>{html.escape(str(r["target"]))}</td>'
            f'<td>{html.escape(str(r["class"]))}</td>'
            f'<td><code>{html.escape(str(r["type"]))}</code></td>'
            f'<td><b>{g}</b></td>'
            f'<td>{rb}</td><td class="dot {rb_ok}"></td>'
            f'<td>{mdl}</td><td class="dot {m_ok}"></td></tr>')
    out.append("</tbody></table>")
    return "".join(out)


def _split_card(split: dict) -> str:
    train_t = ", ".join(html.escape(t) for t in split.get("train_targets", [])) or "—"
    eval_t = ", ".join(html.escape(t) for t in split.get("eval_targets", [])) or "—"
    badge = ('<span class="badge ok">disjoint: true</span>' if split.get("disjoint")
             else '<span class="badge no">overlap!</span>')
    return (f'<div class="card"><h3>Split — {html.escape(str(split.get("method", "target-disjoint")))}</h3>'
            f'<p>{split.get("n_pairs")} pairs &rarr; <b>{split.get("n_train")} train</b> / '
            f'<b>{split.get("n_eval")} eval</b> &nbsp; {badge} &nbsp; '
            f'<span class="muted">seed={split.get("seed")}, held-out frac={split.get("held_out_frac")}</span></p>'
            f'<p><span class="muted">train targets:</span> {train_t}<br>'
            f'<span class="muted">eval targets (unseen):</span> <b>{eval_t}</b></p></div>')


def render(result: dict) -> str:
    """-> self-contained scoreboard.html string."""
    mode = result.get("mode", {})
    split = result.get("split", {})
    metrics = result.get("metrics", {})
    winner = result.get("winner", {"overall": "tie", "blind_spot": "tie"})
    rows = result.get("rows", [])

    summary = _method_row("model", metrics["model"], _COLORS["model"]) + \
        _method_row("rulebook", metrics["rulebook"], _COLORS["rulebook"])

    n_eval = split.get("n_eval", 0)
    m_acc = metrics["model"]["overall"]["accuracy"]
    r_acc = metrics["rulebook"]["overall"]["accuracy"]
    m_bs = metrics["model"]["blind_spot"]["accuracy"]
    r_bs = metrics["rulebook"]["blind_spot"]["accuracy"]

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(result.get("title", "Scoreboard"))}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font: 15px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         color: #0f172a; background: #f1f5f9; }}
  main {{ max-width: 1000px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }}
  h2 {{ font-size: 18px; margin: 28px 0 10px; }}
  h3 {{ font-size: 15px; margin: 0 0 8px; }}
  .sub {{ color: #64748b; font-size: 13px; margin-bottom: 16px; }}
  .banner {{ padding: 10px 14px; border-radius: 8px; margin: 12px 0; font-size: 14px; }}
  .banner.stub {{ background: #fef3c7; border: 1px solid #f59e0b; color: #78350f; }}
  .banner.live {{ background: #ccfbf1; border: 1px solid #14b8a6; color: #134e4a; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px 18px; margin: 12px 0; }}
  .muted {{ color: #64748b; }}
  code {{ background: #f1f5f9; border-radius: 4px; padding: 1px 5px; font-size: 13px; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; }}
  .summary th, .summary td {{ border: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; }}
  .summary th {{ background: #f8fafc; }}
  .summary td {{ font-size: 13px; }}
  .summary tr.model th {{ color: {_COLORS["model"]}; }}
  .summary tr.rulebook th {{ color: {_COLORS["rulebook"]}; }}
  .bar {{ display: inline-block; vertical-align: middle; width: 124px; height: 10px;
         background: #e2e8f0; border-radius: 5px; overflow: hidden; }}
  .fill {{ display: block; height: 100%; border-radius: 5px; }}
  tr.model .fill {{ background: {_COLORS["model"]}; }}
  tr.rulebook .fill {{ background: {_COLORS["rulebook"]}; }}
  .num {{ margin-left: 6px; font-weight: 600; color: #334155; }}
  .n {{ color: #64748b; font-weight: 500; margin-right: 8px; }}
  .winner {{ font-size: 15px; padding: 10px 14px; border-radius: 8px; background: #eef2ff;
             border: 1px solid #c7d2fe; color: #312e81; margin: 12px 0; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; font-weight: 700; }}
  .badge.ok {{ background: #dcfce7; color: {_COLORS["ok"]}; }}
  .badge.no {{ background: #fee2e2; color: {_COLORS["no"]}; }}
  table.detail {{ font-size: 13px; }}
  table.detail th, table.detail td {{ border: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; }}
  table.detail th {{ background: #f8fafc; }}
  .dot {{ width: 10px; }}
  .dot.ok {{ background: {_COLORS["ok"]}; }}
  .dot.no {{ background: {_COLORS["no"]}; }}
  .foot {{ color: #94a3b8; font-size: 12px; margin-top: 24px; }}
</style>
</head>
<body>
<main>
  <h1>{html.escape(result.get("title", "Scoreboard"))}</h1>
  <div class="sub">generated {html.escape(str(result.get("generated_at", "")))} &middot;
      {html.escape(str(result.get("command", "")))}</div>

  {_mode_banner(mode)}

  <div class="card">
    <h3>Held-out result</h3>
    <p>Evaluated on <b>{n_eval}</b> unseen findings ({html.escape(str(split.get("method", "")))} split —
       training examples never overlap eval examples). The model matches the gold label on
       {metrics["model"]["overall"]["exact"]}/{n_eval}; the rulebook floor on
       {metrics["rulebook"]["overall"]["exact"]}/{n_eval}.</p>
    {_winner_line(winner)}
  </div>

  <h2>Summary — accuracy &amp; agreement per class</h2>
  <div class="card" style="padding:0">
  <table class="summary">
    <thead><tr>
      <th>method</th>
      <th>overall acc</th><th>overall agree</th>
      <th>standard acc</th><th>standard agree</th>
      <th>blind-spot acc</th><th>blind-spot agree</th>
    </tr></thead>
    <tbody>{summary}</tbody>
  </table>
  </div>
  <p class="muted" style="font-size:12px">agree = prediction within one severity step of gold.
     Blind spots are where the stack-specific model earns its keep:
     {_fmt_pct(m_bs)} vs {_fmt_pct(r_bs)} on unseen targets.</p>

  <h2>Split</h2>
  {_split_card(split)}

  <h2>Per-finding detail</h2>
  <div class="card" style="padding:0">{_detail_table(rows)}</div>

  <div class="foot">eval/harness.py + eval/scoreboard.py &middot; self-contained, no external assets</div>
</main>
</body>
</html>
"""
    return doc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="eval/scoreboard.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--result", default=str(_HERE / "out" / "result.json"),
                    help="result JSON (or '-' for stdin)")
    ap.add_argument("--out", default=str(_HERE / "scoreboard.html"))
    a = ap.parse_args(argv)

    if a.result == "-":
        result = json.load(sys.stdin)
    else:
        result = json.loads(Path(a.result).read_text(encoding="utf-8"))
    Path(a.out).write_text(render(result), encoding="utf-8")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())