#!/usr/bin/env python3
"""eval/bench.py — before(base) vs after(owned checkpoint): correctness AND speed.

The "is this worth it" receipt, measured head-to-head on the same held-out
pairs: the base model before training vs the LoRA checkpoint after, scored on
exact + within-one-step severity accuracy AND latency + token cost per call.
The rulebook floor is kept as a third column so the scoreboard shows all three
against the same unseen targets.

    python3 eval/bench.py --pairs data/out/pairs.jsonl --checkpoint river/out/<ts>/meta.json
    python3 eval/bench.py --pairs data/out/pairs.jsonl --checkpoint <ckpt-uri> --base-model Qwen/Qwen3.5-9B
    python3 eval/bench.py --pairs data/out/pairs.jsonl --self-test   # no network

Outputs eval/out/bench.json + eval/out/bench.html (self-contained).
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import statistics
import sys
import time
from pathlib import Path

from harness import (SEVERITY_ORDER, SEVERITY_IDX, _extract_type,
                     load_pairs, parse_severity, rulebook_severity,
                     split_by_target)

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_RATES = {"Qwen/Qwen3.5-9B": {"prompt": 0.66, "completion": 1.99, "training": 1.46}}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _exact(pred, gold) -> bool:
    return gold is not None and pred == gold


def _agree(pred, gold) -> bool:
    if gold is None or pred is None:
        return False
    return abs(SEVERITY_IDX[pred] - SEVERITY_IDX[gold]) <= 1


def _make_prompt(pair: dict) -> list[dict]:
    return [{"role": "user",
             "content": pair["instruction"].rstrip() + "\n\n" + pair["input"].strip()}]


class Predictor:
    """Call river chat_complete; measure latency + token usage per call."""

    def __init__(self, client, base_model: str, checkpoint: str | None, name: str):
        self.client = client
        self.base_model = base_model
        self.checkpoint = checkpoint
        self.name = name
        self.calls: list[dict] = []
        self.rate = _RATES.get(base_model, {"prompt": 0.66, "completion": 1.99})

    def predict(self, pair: dict) -> tuple[str | None, dict]:
        t0 = time.time()
        kw = dict(messages=_make_prompt(pair), base_model=self.base_model, timeout=60)
        if self.checkpoint:
            out = self.client.chat_complete_from_checkpoint(
                messages=kw.pop("messages"), checkpoint_path=self.checkpoint,
                base_model=self.base_model, timeout=60)
        else:
            out = self.client.chat_complete(**kw)
        dt_s = time.time() - t0

        # dig the text + usage out of whatever the SDK returned
        text = None
        usage = None
        rj = None
        if isinstance(out, dict):
            rj = out.get("response_json")
        elif hasattr(out, "response_json"):
            rj = out.response_json
        if isinstance(rj, str):
            try:
                rj = json.loads(rj)
            except Exception:
                rj = None
        if isinstance(rj, dict):
            out = rj
        if isinstance(out, dict):
            usage = out.get("usage")
            if not text:
                text = out.get("content") or out.get("output") or out.get("text")
            if text is None:
                choices = out.get("choices")
                if choices:
                    c = choices[0]
                    msg = c.get("message") if isinstance(c, dict) else None
                    if isinstance(msg, dict):
                        text = msg.get("content") or msg.get("reasoning_content")
            if text is None and isinstance(out.get("message"), dict):
                text = out["message"].get("content") or out["message"].get("reasoning_content")
        elif hasattr(out, "content"):
            text = out.content
        elif hasattr(out, "text"):
            text = out.text
        else:
            text = str(out)

        if usage is None and hasattr(out, "usage"):
            usage = out.usage
        u = {}
        if isinstance(usage, dict):
            u = {k: v for k, v in usage.items() if isinstance(v, int)}
        elif hasattr(usage, "prompt_tokens"):
            u = {"prompt_tokens": usage.prompt_tokens,
                 "completion_tokens": getattr(usage, "completion_tokens", 0),
                 "total_tokens": getattr(usage, "total_tokens", 0)}

        p_tok = u.get("prompt_tokens", 0)
        c_tok = u.get("completion_tokens", 0)
        cost = (p_tok / 1e6) * self.rate["prompt"] + (c_tok / 1e6) * self.rate["completion"]
        rec = {"latency_s": round(dt_s, 3), "prompt_tokens": p_tok,
               "completion_tokens": c_tok, "cost_usd": round(cost, 6)}
        self.calls.append(rec)
        return parse_severity(text), rec


def _metrics(rows: list[dict], key: str) -> dict:
    def calc(sub: list[dict]) -> dict:
        n = len(sub)
        exact = sum(1 for r in sub if _exact(r[key], r["gold"]))
        agree = sum(1 for r in sub if _agree(r[key], r["gold"]))
        if key == "rulebook":  # deterministic — no latency/cost
            return {"n": n, "exact": exact, "agreement": agree,
                    "accuracy": exact / n if n else 0.0,
                    "agreement_rate": agree / n if n else 0.0,
                    "latency_p50": None, "latency_p95": None, "total_cost_usd": 0.0}
        lat = [r[f"{key}_latency"] for r in sub]
        return {"n": n, "exact": exact, "agreement": agree,
                "accuracy": exact / n if n else 0.0,
                "agreement_rate": agree / n if n else 0.0,
                "latency_p50": statistics.median(lat) if lat else None,
                "latency_p95": sorted(lat)[int(len(lat) * 0.95) - 1] if len(lat) >= 20 else
                               (max(lat) if lat else None),
                "total_cost_usd": round(sum(r[f"{key}_cost"] for r in sub), 4)}
    return {"overall": calc(rows),
            "standard": calc([r for r in rows if r["class"] == "standard"]),
            "blind_spot": calc([r for r in rows if r["class"] == "blind_spot"])}


def run_bench(pairs: list[dict], args) -> dict:
    train, ev, split = split_by_target(
        pairs, held_out_frac=args.held_out_frac, seed=args.seed,
        held_out_targets=args.held_out_targets)

    if args.max_eval and len(ev) > args.max_eval:
        import random
        rng = random.Random(args.seed)
        # keep targets spread: shuffle, take a stratified slice by class
        ev = sorted(ev, key=lambda p: p["provenance"]["target"])
        per_class = {}
        for p in ev:
            per_class.setdefault(p.get("provenance", {}).get("class", "standard"), []).append(p)
        picked = []
        for cl, pool in per_class.items():
            rng.shuffle(pool)
            picked.extend(pool[: max(1, args.max_eval // max(1, len(per_class)))])
        ev = picked[: args.max_eval]
        split = dict(split, n_eval=len(ev),
                     eval_targets=sorted({p["provenance"]["target"] for p in ev}))

    import river_client as river
    client = river.Client(api_key=os.environ["RIVER_API_KEY"])
    client.health_check()
    base = args.base_model or os.environ.get("RIVER_BASE_MODEL") or "Qwen/Qwen3.5-9B"
    ckpt = args.checkpoint if args.checkpoint != "none" else None

    before = Predictor(client, base, None, "base")
    after = Predictor(client, base, ckpt, "owned")

    rows = []
    for i, p in enumerate(ev):
        gold = parse_severity(p.get("output", ""))
        rb = rulebook_severity(p)
        b_raw, b_meta = before.predict(p)
        a_raw, a_meta = after.predict(p)
        rows.append({
            "target": p["provenance"]["target"],
            "class": p.get("provenance", {}).get("class", "standard"),
            "type": _extract_type(p) or "unknown",
            "gold": gold, "gold_raw": p.get("output", ""),
            "rulebook": rb,
            "base": b_raw, "base_raw": str(b_raw), "base_latency": b_meta["latency_s"],
            "base_cost": b_meta["cost_usd"],
            "model": a_raw, "model_raw": str(a_raw), "model_latency": a_meta["latency_s"],
            "model_cost": a_meta["cost_usd"],
        })

    metrics = {"rulebook": _metrics(rows, "rulebook"),
               "base": _metrics(rows, "base"),
               "model": _metrics(rows, "model")}

    def winner(a, b):
        if a["accuracy"] > b["accuracy"]:
            return "model"
        if b["accuracy"] > a["accuracy"]:
            return "before"
        return "tie"

    result = {
        "title": "Before/After — base model vs owned LoRA (correctness + speed)",
        "generated_at": _now(),
        "command": " ".join(sys.argv),
        "base_model": base,
        "checkpoint": ckpt or None,
        "split": split,
        "metrics": metrics,
        "winner": {"overall": winner(metrics["model"]["overall"], metrics["base"]["overall"]),
                   "blind_spot": winner(metrics["model"]["blind_spot"], metrics["base"]["blind_spot"])},
        "rows": rows,
        "call_stats": {"before": before.calls, "after": after.calls},
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "bench.json").write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    return result


# ---------------------------------------------------------------- html render

def _pct(x):
    return f"{x:.0%}" if x is not None else "—"


def _num(x, fmt="{:.2f}"):
    return fmt.format(x) if x is not None else "—"


def _bar(acc: float) -> str:
    w = max(2, round(acc * 120))
    return (f'<span class="bar"><span class="fill" style="width:{w}px"></span></span>'
            f'<span class="num">{_pct(acc)}</span>')


def _rows(m: dict, color: str) -> str:
    cells = []
    for k in ("overall", "standard", "blind_spot"):
        b = m[k]
        cells.append(f'<td><span class="n">{b["exact"]}/{b["n"]}</span> {_bar(b["accuracy"])}</td>')
        cells.append(f'<td><span class="n">{b["agreement"]}/{b["n"]}</span> {_bar(b["agreement_rate"])}</td>')
        cells.append(f'<td>{_num(b["latency_p50"])}s</td><td>{_num(b["latency_p95"])}s</td>'
                     f'<td>${_num(b["total_cost_usd"], "{:.4f}")}</td>')
    return '<tr><th>' + color + '</th>' + "".join(cells) + "</tr>"


def render(result: dict) -> str:
    m = result["metrics"]
    header = ("<th></th>" + "<th colspan=2>overall</th><th></th><th></th><th></th>"
              + "<th colspan=2>standard</th><th></th><th></th><th></th>"
              + "<th colspan=2>blind-spot</th><th></th><th></th><th></th>"
              + "<th></th>")
    sub = ("<tr><th>method</th>"
           + "".join(f"<th>{h}</th>" for h in
                     ["acc", "agree", "p50", "p95", "cost"]
                     for _ in range(1)) * 3
           + "<th></th></tr>")
    rows = _rows(m["model"], "owned LoRA") + _rows(m["base"], "base model") + _rows(m["rulebook"], "rulebook")
    w = result["winner"]
    lat_speedup = None
    ml, bl = m["model"]["overall"]["latency_p50"], m["base"]["overall"]["latency_p50"]
    if ml and bl:
        lat_speedup = bl / ml
    acc_delta = (m["model"]["overall"]["accuracy"] - m["base"]["overall"]["accuracy"])
    bs_delta = (m["model"]["blind_spot"]["accuracy"] - m["base"]["blind_spot"]["accuracy"])
    ckpt = html.escape(result.get("checkpoint") or "none")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{html.escape(result['title'])}</title>
<style>
  body {{ font: 15px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         color:#0f172a; background:#f1f5f9; margin:0; }}
  main {{ max-width: 1200px; margin:0 auto; padding:32px 20px 64px; }}
  h1 {{ font-size:23px; margin:0 0 4px; }}
  .sub {{ color:#64748b; font-size:13px; margin-bottom:16px; }}
  .banner {{ padding:10px 14px; border-radius:8px; margin:12px 0; font-size:14px; }}
  .banner.live {{ background:#ccfbf1; border:1px solid #14b8a6; color:#134e4a; }}
  .card {{ background:#fff; border:1px solid #e2e8f0; border-radius:10px; padding:16px 18px; margin:12px 0; }}
  .winner {{ font-size:15px; padding:10px 14px; border-radius:8px; background:#eef2ff;
             border:1px solid #c7d2fe; color:#312e81; margin:12px 0; }}
  table {{ border-collapse:collapse; width:100%; background:#fff; font-size:13px; }}
  th, td {{ border:1px solid #e2e8f0; padding:6px 8px; text-align:left; }}
  th {{ background:#f8fafc; }}
  .bar {{ display:inline-block; vertical-align:middle; width:124px; height:10px;
         background:#e2e8f0; border-radius:5px; overflow:hidden; }}
  .fill {{ display:block; height:100%; background:#0f766e; border-radius:5px; }}
  tr:first-of-type .fill {{ background:#0f766e; }}
  tr:nth-of-type(2) .fill {{ background:#64748b; }}
  tr:nth-of-type(3) .fill {{ background:#b45309; }}
  .num {{ margin-left:6px; font-weight:600; color:#334155; }}
  .n {{ color:#64748b; font-weight:500; margin-right:6px; }}
  .muted {{ color:#64748b; }}
  .foot {{ color:#94a3b8; font-size:12px; margin-top:24px; }}
  .big {{ font-size:20px; font-weight:700; }}
  code {{ background:#f1f5f9; border-radius:4px; padding:1px 5px; font-size:12px; }}
</style></head><body><main>
  <h1>{html.escape(result['title'])}</h1>
  <div class="sub">generated {html.escape(str(result['generated_at']))} &middot;
      {html.escape(str(result['command']))}</div>
  <div class="banner live"><strong>OWNED MODEL</strong> — {result['split']['n_eval']} held-out pairs across
      {len(set(r['target'] for r in result['rows']))} unseen targets; checkpoint <code>{ckpt}</code></div>

  <div class="card">
    <h3>Headline</h3>
    <p class="big">owned vs base: overall <b>{_pct(m['model']['overall']['accuracy'])}</b> vs <b>{_pct(m['base']['overall']['accuracy'])}</b>
       ({'+' if acc_delta >= 0 else ''}{_pct(acc_delta)}) &middot;
       blind-spot <b>{_pct(m['model']['blind_spot']['accuracy'])}</b> vs <b>{_pct(m['base']['blind_spot']['accuracy'])}</b>
       ({'+' if bs_delta >= 0 else ''}{_pct(bs_delta)})</p>
    <p>latency p50: owned <b>{_num(ml)}s</b> vs base <b>{_num(bl)}s</b>
       {f'&rarr; <b>{lat_speedup:.2f}&times;</b> change' if lat_speedup else ''}</p>
    {("<div class='winner'>Overall winner: <b>" + w['overall'] +
      "</b> &middot; blind-spot winner: <b>" + w['blind_spot'] + "</b></div>")}
  </div>

  <div class="card" style="padding:0">
    <table><thead><tr><th>method</th>
      <th colspan=2>overall acc/agree</th><th>lat p50</th><th>lat p95</th><th>cost</th>
      <th colspan=2>standard</th><th>lat p50</th><th>lat p95</th><th>cost</th>
      <th colspan=2>blind-spot</th><th>lat p50</th><th>lat p95</th><th>cost</th>
    </tr></thead><tbody>{rows}</tbody></table>
  </div>
  <p class="muted" style="font-size:12px">agree = within one severity step. cost = inference $ on this eval set
     (prompt $0.66/1M, completion $1.99/1M, Qwen3.5-9B). Training cost is reported separately.</p>

  <div class="card" style="padding:0"><table><thead><tr>
    <th>target</th><th>class</th><th>type</th><th>gold</th><th>rulebook</th><th>base</th>
    <th>hit?</th><th>owned</th><th>hit?</th><th>base lat</th><th>owned lat</th></tr></thead><tbody>
    {''.join(
      '<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%ss</td><td>%ss</td></tr>' % (
        html.escape(str(r['target'])), html.escape(str(r['class'])),
        html.escape(str(r['type'])), html.escape(str(r['gold'] or '?')),
        html.escape(str(r['rulebook'])), html.escape(str(r['base'] or '?')),
        '✓' if r['gold'] is not None and r['base'] == r['gold'] else '✗',
        html.escape(str(r['model'] or '?')),
        '✓' if r['gold'] is not None and r['model'] == r['gold'] else '✗',
        _num(r['base_latency']), _num(r['model_latency']))
      for r in result['rows'])}
  </tbody></table></div>

  <div class="foot">eval/bench.py &middot; before(base) vs after(owned checkpoint) &middot; correctness + latency + cost</div>
</main></body></html>"""


def _self_test() -> int:
    pairs = load_pairs(_ROOT / "data" / "example.pairs.jsonl")
    train, ev, split = split_by_target(pairs, held_out_frac=0.4, seed=4)
    assert split["disjoint"] and ev and train
    rb = rulebook_severity(ev[0])
    assert rb in SEVERITY_ORDER
    print(f"self-test OK: {len(ev)} eval pairs, rulebook sample={rb}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="eval/bench.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--pairs", default=str(_ROOT / "data" / "out" / "pairs.jsonl"))
    ap.add_argument("--checkpoint", default=None, help="owned checkpoint URI/path; 'none' = base only")
    ap.add_argument("--base-model", default=None)
    ap.add_argument("--held-out-frac", type=float, default=0.15)
    ap.add_argument("--held-out-targets", default=None)
    ap.add_argument("--max-eval", type=int, default=0, help="cap on eval pairs (0 = all)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out-dir", default=str(_HERE / "out"))
    ap.add_argument("--out", default=str(_HERE / "out" / "bench.html"))
    a = ap.parse_args(argv)

    if a.self_test:
        return _self_test()
    if not os.environ.get("RIVER_API_KEY"):
        print("RIVER_API_KEY not set", file=sys.stderr)
        return 2

    held_out_targets = [t.strip() for t in a.held_out_targets.split(",") if t.strip()] \
        if a.held_out_targets else None
    a.held_out_targets = held_out_targets
    pairs = load_pairs(Path(a.pairs))
    result = run_bench(pairs, a)
    html_out = render(result)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(html_out, encoding="utf-8")

    mo, bo = result["metrics"]["model"]["overall"], result["metrics"]["base"]["overall"]
    mb, bb = result["metrics"]["model"]["blind_spot"], result["metrics"]["base"]["blind_spot"]
    print(f"wrote {a.out}")
    print(f"held-out: {result['split']['n_eval']} pairs / {len(set(r['target'] for r in result['rows']))} targets")
    print(f"overall acc: owned {mo['accuracy']:.0%} vs base {bo['accuracy']:.0%} "
          f"(winner {result['winner']['overall']})")
    print(f"blind-spot acc: owned {mb['accuracy']:.0%} vs base {bb['accuracy']:.0%} "
          f"(winner {result['winner']['blind_spot']})")
    print(f"latency p50: owned {mo['latency_p50']}s vs base {bo['latency_p50']}s")
    print(f"inference cost: owned ${mo['total_cost_usd']} vs base ${bo['total_cost_usd']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())