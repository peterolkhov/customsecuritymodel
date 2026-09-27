#!/usr/bin/env python3
"""demo/build_page.py — emit the self-contained Superset page.

Reads the page template, base64-inlines every generated PNG (no external
fetch), and writes customsecuritymodel.html.

    python3 demo/build_page.py
"""
from __future__ import annotations

import base64
from pathlib import Path

_HERE = Path(__file__).resolve().parent
ROOT = _HERE.parent
OUT = Path.home() / ".superset" / "sessions" / "bubble-boater" / "customsecuritymodel.html"


def b64(name: str) -> str:
    data = (_HERE / name).read_bytes()
    return base64.b64encode(data).decode()


IMG = {n: b64(n) for n in [
    "blind-spot-gap.png",
    "customization-cost.png",
    "pipeline.png",
    "loss.png",
]}

HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>customsecuritymodel — own your security judgment</title>
    <style>
      :root {
        --bg: #ffffff;
        --ink: #16181c;
        --muted: #5b6470;
        --hair: #e3e6ea;
        --hair-strong: #c8cdd4;
        --accent: #2456a6;
        --accent-soft: #eef3fb;
        --code: #f5f6f8;
        --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        --mono: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
      }
      * { box-sizing: border-box; }
      html { scroll-behavior: smooth; }
      body { margin: 0; background: var(--bg); color: var(--ink); font-family: var(--sans); font-size: 16px; line-height: 1.6; -webkit-font-smoothing: antialiased; }
      main { max-width: 920px; margin: 0 auto; padding: 0 24px 80px; }
      a { color: var(--accent); text-decoration: none; }

      header.mast { padding: 72px 0 8px; }
      .kicker { font-family: var(--mono); font-size: 12px; color: var(--muted); margin: 0 0 22px; }
      .kicker b { color: var(--accent); font-weight: 500; }
      h1 { font-size: clamp(2rem, 5vw, 3.4rem); line-height: 1.08; letter-spacing: -.02em; font-weight: 700; margin: 0 0 20px; max-width: 20ch; }
      .lede { font-size: clamp(1.05rem, 1.5vw, 1.2rem); color: var(--muted); max-width: 60ch; margin: 0; }
      .lede b { color: var(--ink); font-weight: 600; }

      table.head { border-collapse: collapse; width: 100%; margin: 44px 0 0; border-top: 2px solid var(--ink); }
      table.head th, table.head td { text-align: left; vertical-align: top; }
      table.head th { font-family: var(--mono); font-size: 11px; letter-spacing: .03em; color: var(--muted); font-weight: 500; padding: 12px 18px 6px 0; }
      table.head td { padding: 0 18px 18px 0; }
      table.head td:last-child, table.head th:last-child { padding-right: 0; }
      table.head .n { font-size: clamp(1.5rem, 2.6vw, 2rem); font-weight: 700; letter-spacing: -.02em; line-height: 1.05; }
      table.head .k { font-size: 13px; color: var(--muted); margin-top: 4px; line-height: 1.5; }

      section { margin-top: 72px; border-top: 2px solid var(--ink); padding-top: 22px; }
      h2 { font-size: clamp(1.4rem, 2.8vw, 2rem); line-height: 1.15; letter-spacing: -.015em; font-weight: 700; margin: 0 0 12px; max-width: 32ch; }
      h3 { font-size: 1.05rem; font-weight: 600; margin: 26px 0 8px; }
      p.sec-sub { color: var(--muted); max-width: 64ch; margin: 0; font-size: 15px; }
      p.sec-sub b { color: var(--ink); font-weight: 600; }

      figure { margin: 24px 0 0; }
      figure.fig { border: 1px solid var(--hair-strong); padding: 10px 10px 12px; }
      figure.fig img { width: 100%; height: auto; display: block; }
      figcaption { font-size: 12.5px; color: var(--muted); margin-top: 10px; line-height: 1.55; }
      figcaption b { color: var(--ink); font-weight: 600; }

      figure.shot { border: 2px dashed var(--hair-strong); border-radius: 6px; padding: 0; background: var(--code); }
      figure.shot .shot-label { font-family: var(--mono); font-size: 11px; letter-spacing: .05em; text-transform: uppercase; color: var(--accent); padding: 10px 14px 0; }
      figure.shot .shot-body { display: flex; align-items: center; justify-content: center; min-height: 200px; color: var(--muted); font-family: var(--mono); font-size: 13px; padding: 12px; text-align: center; }
      figure.shot img { width: 100%; height: auto; display: block; }

      .pair { margin: 22px 0 0; border: 1px solid var(--hair); border-radius: 6px; overflow: hidden; }
      .pair .p-head { display: flex; gap: 12px; align-items: baseline; padding: 10px 16px; background: var(--code); border-bottom: 1px solid var(--hair); font-family: var(--mono); font-size: 12px; }
      .pair .p-head .sev { font-weight: 600; }
      .pair .p-body { padding: 14px 16px; font-size: 14px; color: var(--ink); }
      .pair .p-body .instr { color: var(--muted); font-style: italic; margin-bottom: 6px; }

      table.data { border-collapse: collapse; width: 100%; font-size: 13.5px; margin-top: 22px; }
      table.data th, table.data td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--hair); }
      table.data th { font-family: var(--mono); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); font-weight: 500; }
      table.data td.mono, table.data .mono { font-family: var(--mono); font-size: 12.5px; }
      table.data tr:last-child td { border-bottom: none; }

      .cmd { font-family: var(--mono); font-size: 12.5px; line-height: 1.8; background: var(--code); border: 1px solid var(--hair); border-radius: 4px; padding: 14px 18px; margin-top: 16px; overflow-x: auto; white-space: pre; }
      .cmd b { color: var(--accent); font-weight: 500; }

      .close { border-top: 2px solid var(--ink); padding-top: 40px; margin-top: 80px; }
      .close h2 { font-size: clamp(1.6rem, 3.4vw, 2.4rem); max-width: 26ch; }
      .repo { font-family: var(--mono); font-size: 13px; color: var(--accent); margin-top: 18px; }
      footer { margin-top: 56px; color: var(--muted); font-family: var(--mono); font-size: 11px; border-top: 1px solid var(--hair); padding-top: 18px; display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; }

      @media (max-width: 720px) {
        header.mast { padding-top: 48px; }
        section { margin-top: 56px; }
      }
    </style>
  </head>
  <body>
    <main>

      <header class="mast">
        <p class="kicker">Own Your Intelligence · YC SF · 09.27.26 · <b>hackathon build</b></p>
        <h1>Stop renting security judgment.</h1>
        <p class="lede">Every scanner sells the same generic checklist. It never reads your code, it forgets between runs, and it costs real money each time. <b>We turn your architecture into a custom, owned security model.</b></p>
        <table class="head">
          <thead>
            <tr>
              <th>a custom suite used to cost</th>
              <th>now it costs</th>
              <th>trained in</th>
              <th>shipped by</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><div class="n">$10K–$250K</div><div class="k">pentests + engineer-weeks, per company, per year</div></td>
              <td><div class="n">$0.08</div><div class="k">one training run on your own findings</div></td>
              <td><div class="n">7.3 min</div><div class="k">76 steps · loss 20 → 1.8e-4</div></td>
              <td><div class="n">12 agents</div><div class="k">60 commits, all pushed, all logged</div></td>
            </tr>
          </tbody>
        </table>
      </header>

      <section id="problem">
        <h2>Everyone ships the same checklist. Your stack is the blind spot.</h2>
        <p class="sec-sub">Scanners build rules against one open standard (OWASP), so the same coverage, and the same misses, go to every company. On the findings that define your stack, the generic rulebook is wrong <b>54% of the time</b>.</p>
        <figure class="fig">
          <img src="data:image/png;base64,{IMG_blind_spot_gap}" alt="Generic rulebook verdict vs gold severity on blind-spot findings" />
          <figcaption><b>Figure 1.</b> What the generic rulebook says vs what each finding really is. Unknown types get stamped MEDIUM, so real HIGHs get buried.<span style="font-family:var(--mono);font-size:11px;color:var(--muted)"> · source: data/out/pairs.jsonl</span></figcaption>
        </figure>
      </section>

      <section id="cost">
        <h2>Customization was priced like a hiring decision.</h2>
        <p class="sec-sub">Tailoring a suite meant hand-writing tests, so it only happened at companies that could afford it. The industry price for that judgment, per company, per year:</p>
        <figure class="fig">
          <img src="data:image/png;base64,{IMG_customization_cost}" alt="Industry cost of custom security vs one training run" />
          <figcaption><b>Figure 2.</b> A web-app pentest runs $10K–$30K, a consultant week $25K–$75K, a loaded engineer $200K–$300K a year. One owned training run: $0.08.<span style="font-family:var(--mono);font-size:11px;color:var(--muted)"> · sources: RSI · Diginatives · Pentestas</span></figcaption>
        </figure>
      </section>

      <section id="solve">
        <h2>How we solved it.</h2>
        <p class="sec-sub">Customization stopped being about writing rules and became a training problem. We take a company's real scan output, turn it into labeled training data, and train a small model on it. The company holds the weights.</p>

        <h3>What the model actually learns on</h3>
        <p class="sec-sub">Each training pair is one real finding plus the severity that company's stack should assign. The standard half teaches the floor every suite ships; the blind-spot half teaches what the floor gets wrong.</p>
        <div class="pair">
          <div class="p-head">
            <span class="instr">training pair · blind-spot</span>
            <span style="margin-left:auto">gold: <span class="sev" style="color:#c2410c">HIGH</span></span>
          </div>
          <div class="p-body">
            <span class="instr">"Given this finding, assign a severity for THIS company's stack."</span><br />
            type: js_hardcoded_api_key · host: cdn.ledgerway.example<br />
            detail: hardcoded 40-char API key in the production JS bundle for the merchant portal login
          </div>
        </div>
        <div class="pair">
          <div class="p-head">
            <span class="instr">training pair · blind-spot</span>
            <span style="margin-left:auto">gold: <span class="sev" style="color:#15803d">MEDIUM</span></span>
          </div>
          <div class="p-body">
            <span class="instr">"Given this finding, assign a severity for THIS company's stack."</span><br />
            type: graphql_introspection · host: api.gbrain-oss.example<br />
            detail: full schema exposed over the wire on the BFF
          </div>
        </div>

        <h3>The pipeline</h3>
        <figure class="fig">
          <img src="data:image/png;base64,{IMG_pipeline}" alt="Funnel: 857 probe reports, 300 training pairs, 191 companies, 76 steps, 8 cents, 1 checkpoint" />
          <figcaption><b>Figure 3.</b> The whole funnel for one company: 857 probe reports → 300 de-identified pairs → one training run → one checkpoint the company holds. The last bar is the product.<span style="font-family:var(--mono);font-size:11px;color:var(--muted)"> · source: data/out/pairs.jsonl · river/out/…/meta.json</span></figcaption>
        </figure>

        <h3>How a company runs it</h3>
        <div class="cmd"># adapt your probe output into de-identified pairs
python3 data/build_pairs.py --corpus <b>&lt;your probe output&gt;</b>

# one River call trains the owned model
python3 river/train.py --pairs data/out/pairs.jsonl --live

# your suite, ranked by the owned model
python3 suite/build_suite.py --company <b>&lt;your domain&gt;</b> --input data/out/pairs.jsonl</div>
        <p class="sec-sub" style="margin-top:14px">River hosts the weights and serves severity via <b>chat_complete_from_checkpoint</b>. Findings never leave your side; the checkpoint is yours.</p>
      </section>

      <section id="runs">
        <h2>The runs, on the record.</h2>

        <figure class="shot">
          <div class="shot-label">screenshot 1 · training run</div>
          <div class="shot-body">paste capture of the River training run here</div>
        </figure>

        <figure class="fig" style="margin-top:16px">
          <img src="data:image/png;base64,{IMG_loss}" alt="Training loss vs optimizer step, log scale" />
          <figcaption><b>Figure 4.</b> The live training run: loss 20 → 1.8e-4 in 76 steps, 7.3 minutes, ≈$0.08.<span style="font-family:var(--mono);font-size:11px;color:var(--muted)"> · source: demo/loss-full.jsonl</span></figcaption>
        </figure>

        <figure class="shot">
          <div class="shot-label">screenshot 2 · eval receipt</div>
          <div class="shot-body">paste capture of the held-out eval / scoreboard here</div>
        </figure>

        <figure class="shot">
          <div class="shot-label">screenshot 3 · deploy</div>
          <div class="shot-body">paste capture of the 3-command deploy or the infer CLI here</div>
        </figure>
      </section>

      <section id="tools">
        <h2>Built on River, GBrain, Superset, Memorable.</h2>
        <table class="data">
          <thead><tr><th>tool</th><th>role here</th></tr></thead>
          <tbody>
            <tr><td class="mono">River</td><td>hosts the checkpoint · serves severity via chat_complete_from_checkpoint</td></tr>
            <tr><td class="mono">GBrain</td><td>per-company memory · every scan remembered, suites compound</td></tr>
            <tr><td class="mono">Superset</td><td>12 parallel agents · this page</td></tr>
            <tr><td class="mono">Memorable</td><td>scan-to-train procedures, recorded and replayable</td></tr>
          </tbody>
        </table>
      </section>

      <div class="close">
        <h2>Customization was a hiring problem. Now it's a training run.</h2>
        <div class="repo">github.com/peterolkhov/customsecuritymodel</div>
      </div>

      <footer>
        <span>customsecuritymodel · Own Your Intelligence</span>
        <span>github.com/peterolkhov/customsecuritymodel</span>
      </footer>

    </main>
  </body>
</html>"""


def main() -> None:
    html = HTML
    for key, data in IMG.items():
        html = html.replace("{IMG_" + key[:-4].replace("-", "_") + "}", data)
    if "{IMG_" in html:
        raise SystemExit(f"missing image placeholders: {html[html.find('{IMG_'):html.find('{IMG_')+60]}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html)
    print(f"wrote {OUT} ({len(html) / 1e6:.2f} MB)")


if __name__ == "__main__":
    main()