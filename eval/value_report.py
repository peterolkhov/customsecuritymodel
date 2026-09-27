#!/usr/bin/env python3
"""eval/value_report.py — the structural "why it's worth it" proof.

Pulls together: the training run (meta.json + log.jsonl: cost, tokens, timing,
loss curve) and the before/after bench (bench.json: correctness + latency) into
one self-contained report.html that a judge can read top to bottom.

    python3 eval/value_report.py \
        --run river/out/<ts>-company-model-v<N> \
        --bench eval/out/bench.json --out eval/out/value_report.html
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import statistics
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_RATES = {"Qwen/Qwen3.5-9B": {"prompt": 0.66, "completion": 1.99, "training": 1.46}}
_SEV = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_run(run_dir: Path) -> dict:
    meta = json.loads((run_dir / "meta.json").read_text())
    rows = [json.loads(l) for l in (run_dir / "log.jsonl").read_text().splitlines() if l.strip()]
    losses = [r["loss"] for r in rows if r.get("loss") is not None]
    toks = meta.get("n_tokens_epoch")
    if not toks:
        toks = _count_tokens(meta)
    return {
        "meta": meta,
        "rows": rows,
        "loss_min": min(losses) if losses else None,
        "loss_last": losses[-1] if losses else None,
        "loss_first": losses[0] if losses else None,
        "steps": len(rows),
        "n_tokens_total": (toks or 0) * meta.get("epochs", 1),
        "train_cost_usd": ((toks or 0) * meta.get("epochs", 1) / 1e6) * _RATES.get(
            meta.get("base_model", "Qwen/Qwen3.5-9B"), {"training": 1.46})["training"],
    }


def _count_tokens(meta: dict) -> int | None:
    """Fallback: estimate tokens from the pairs file path recorded in meta."""
    pairs = meta.get("pairs")
    if not pairs or not Path(pairs).is_file():
        return None
    try:
        from transformers import AutoTokenizer
        tok = AutoTokenizer.from_pretrained(meta.get("base_model", "Qwen/Qwen3.5-9B"))
    except Exception:
        return None
    n = 0
    for line in Path(pairs).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        n += len(tok.encode(r.get("input", ""))) + len(tok.encode(r.get("output", "")))
    return n


def _duration(start: str, end: str) -> str:
    try:
        t0 = dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
        t1 = dt.datetime.fromisoformat(end.replace("Z", "+00:00"))
        return str(t1 - t0)
    except Exception:
        return "—"


def render(run: dict, bench: dict, generated_at: str) -> str:
    meta = run["meta"]
    m = bench["metrics"]
    mo, bo, ro = m["model"]["overall"], m["base"]["overall"], m["rulebook"]["overall"]
    mb, bb = m["model"]["blind_spot"], m["base"]["blind_spot"]
    train_cost = run["train_cost_usd"]
    infer_model = mo["total_cost_usd"]
    acc_delta = mo["accuracy"] - bo["accuracy"]
    bs_delta = mb["accuracy"] - bb["accuracy"]
    speedup = bo["latency_p50"] / mo["latency_p50"] if (mo["latency_p50"] and bo["latency_p50"]) else None
    # confusion matrix (gold x model)
    conf = {}
    for r in bench["rows"]:
        conf.setdefault(r["gold"], {}).setdefault(r["model"], 0)
        conf[r["gold"]][r["model"]] = conf[r["gold"]].get(r["model"], 0) + 1
    conf_rows = "".join(
        "<tr><th>%s</th>%s</tr>" % (
            html.escape(g),
            "".join("<td>%d</td>" % conf.get(g, {}).get(p, 0)
                    for p in _SEV))
        for g in _SEV)
    sev_heads = "".join(f"<th>{s}</th>" for s in _SEV)

    loss_last_20 = run["rows"][-20:]
    spark = "".join(
        f'<div class="tick" style="height:{max(2, int(2 + (1 - min(1, r["loss"] / 20)) * 46))}px" '
        f'title="step {r["step"]} loss {r["loss"]:.3f}"></div>' for r in loss_last_20)

    duration = _duration(meta.get("started_at", ""), meta.get("ended_at", ""))

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Why training is worth it — value report</title>
<style>
  body {{ font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         color:#0f172a; background:#f1f5f9; margin:0; }}
  main {{ max-width:1080px; margin:0 auto; padding:32px 20px 64px; }}
  h1 {{ font-size:24px; margin:0 0 4px; }} h2 {{ font-size:18px; margin:28px 0 10px; }}
  .sub {{ color:#64748b; font-size:13px; margin-bottom:16px; }}
  .card {{ background:#fff; border:1px solid #e2e8f0; border-radius:10px; padding:16px 18px; margin:12px 0; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; }}
  .stat {{ background:#fff; border:1px solid #e2e8f0; border-radius:10px; padding:12px 14px; }}
  .stat .k {{ font-size:12px; color:#64748b; text-transform:uppercase; letter-spacing:.03em; }}
  .stat .v {{ font-size:22px; font-weight:700; margin-top:2px; }}
  .stat .d {{ font-size:12px; color:#334155; margin-top:2px; }}
  .winner {{ padding:10px 14px; border-radius:8px; background:#eef2ff; border:1px solid #c7d2fe;
             color:#312e81; margin:12px 0; }}
  table {{ border-collapse:collapse; width:100%; background:#fff; font-size:13px; }}
  th,td {{ border:1px solid #e2e8f0; padding:6px 8px; text-align:left; }}
  th {{ background:#f8fafc; }}
  .spark {{ display:flex; align-items:flex-end; gap:2px; height:50px; margin-top:8px; }}
  .tick {{ width:6px; background:#0f766e; border-radius:2px; }}
  .muted {{ color:#64748b; }} .foot {{ color:#94a3b8; font-size:12px; margin-top:24px; }}
  code {{ background:#f1f5f9; border-radius:4px; padding:1px 5px; font-size:12px; }}
  .bar {{ display:inline-block; vertical-align:middle; width:120px; height:10px; background:#e2e8f0;
         border-radius:5px; overflow:hidden; }}
  .fill {{ display:block; height:100%; border-radius:5px; }}
  .fill.m {{ background:#0f766e; }} .fill.b {{ background:#64748b; }} .fill.r {{ background:#b45309; }}
  .num {{ margin-left:6px; font-weight:600; color:#334155; }}
</style></head><body><main>
  <h1>Why training is worth it</h1>
  <div class="sub">generated {html.escape(generated_at)} &middot; run
      <code>{html.escape(str(meta.get('checkpoint', '')))}</code></div>

  <h2>The one-line case</h2>
  <div class="card">
    <p>For <b>${train_cost:.2f}</b> of training and <b>{duration}</b> of wall time, the owned LoRA
       (<code>{html.escape(meta.get('base_model', ''))}</code>, rank {meta.get('rank')},
       {meta.get('n_pairs')} pairs &times; {meta.get('epochs')} epochs)
       went from <b>{bo['accuracy']:.0%} → {mo['accuracy']:.0%}</b> overall accuracy on unseen targets
       ({'+' if acc_delta >= 0 else ''}{acc_delta:.0%}), and
       <b>{bb['accuracy']:.0%} → {mb['accuracy']:.0%}</b> on blind spots — the findings standard
       rulebooks miss.</p>
    <div class="winner">Winner: <b>{bench['winner']['overall']}</b> overall,
        <b>{bench['winner']['blind_spot']}</b> on blind spots</div>
  </div>

  <h2>Numbers</h2>
  <div class="grid">
    <div class="stat"><div class="k">training cost</div><div class="v">${train_cost:.2f}</div>
        <div class="d">{run['n_tokens_total']:,} tokens &times; ${_RATES[meta.get('base_model','Qwen/Qwen3.5-9B')]['training']:.2f}/1M</div></div>
    <div class="stat"><div class="k">wall time</div><div class="v">{duration}</div>
        <div class="d">{run['steps']} steps, {meta.get('epochs')} epochs</div></div>
    <div class="stat"><div class="k">loss drop</div><div class="v">{run['loss_first']:.1f} → {run['loss_last']:.2f}</div>
        <div class="d">min {run['loss_min']:.3f}</div></div>
    <div class="stat"><div class="k">overall acc</div><div class="v">{mo['accuracy']:.0%}</div>
        <div class="d">base {bo['accuracy']:.0%} · rulebook {ro['accuracy']:.0%}</div></div>
    <div class="stat"><div class="k">blind-spot acc</div><div class="v">{mb['accuracy']:.0%}</div>
        <div class="d">base {bb['accuracy']:.0%}</div></div>
    <div class="stat"><div class="k">latency p50</div><div class="v">{mo['latency_p50']:.2f}s</div>
        <div class="d">base {bo['latency_p50']:.2f}s{f' · {speedup:.2f}&times;' if speedup else ''}</div></div>
    <div class="stat"><div class="k">eval inference $</div><div class="v">${infer_model:.4f}</div>
        <div class="d">{mo['n']} held-out calls</div></div>
  </div>

  <h2>Accuracy per class</h2>
  <div class="card" style="padding:0">
  <table><thead><tr><th>method</th><th>overall</th><th>standard</th><th>blind-spot</th></tr></thead><tbody>
    {_row("owned LoRA", m["model"], "m")}{_row("base model", m["base"], "b")}{_row("rulebook floor", m["rulebook"], "r")}
  </tbody></table>
  </div>

  <h2>Confusion matrix — owned model (gold × predicted)</h2>
  <div class="card" style="padding:0">
  <table><thead><tr><th>gold \\ pred</th>{sev_heads}</tr></thead><tbody>{conf_rows}</tbody></table>
  </div>

  <h2>Loss curve (last {len(loss_last_20)} steps)</h2>
  <div class="card"><div class="spark">{spark}</div>
      <p class="muted" style="font-size:12px">start {run['loss_first']:.1f} &rarr; last {run['loss_last']:.2f},
          min {run['loss_min']:.3f} over {run['steps']} steps.</p></div>

  <div class="foot">eval/value_report.py &middot; run meta + log.jsonl + eval/bench.json</div>
</main></body></html>"""
    return doc


def _row(name: str, metric: dict, cls: str) -> str:
    def bar(acc: float) -> str:
        w = max(2, round(acc * 120))
        return (f'<span class="bar"><span class="fill {cls}" style="width:{w}px"></span></span>'
                f'<span class="num">{acc:.0%}</span>')
    return (f'<tr><th>{name}</th>'
            + "".join(f"<td>{bar(metric[k]['accuracy'])}<span class='muted'>&nbsp;({metric[k]['exact']}/{metric[k]['n']})</span></td>"
                      for k in ("overall", "standard", "blind_spot"))
            + "</tr>")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="eval/value_report.py", description=__doc__)
    ap.add_argument("--run", required=True, help="river/out/<ts>-<name> dir")
    ap.add_argument("--bench", default=str(_HERE / "out" / "bench.json"))
    ap.add_argument("--out", default=str(_HERE / "out" / "value_report.html"))
    a = ap.parse_args(argv)

    run = load_run(Path(a.run))
    bench = json.loads(Path(a.bench).read_text())
    html_out = render(run, bench, _now())
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(html_out, encoding="utf-8")
    print(f"wrote {a.out} ({len(html_out)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())