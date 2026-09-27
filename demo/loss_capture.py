#!/usr/bin/env python3
"""demo/loss_capture.py — append every training loss tick to demo/loss-full.{jsonl,csv}

Watches the newest river/out/*/log.jsonl and mirrors new lines into the demo
assets so the Loom + table expo show the live loss curve. Idempotent by offset.

    python3 demo/loss_capture.py --watch  # poll every 5s
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent


def _newest_run() -> Path | None:
    dirs = sorted(glob.glob(str(_ROOT / "river" / "out" / "*")),
                  key=os.path.getmtime, reverse=True)
    for d in dirs:
        lp = Path(d) / "log.jsonl"
        if lp.is_file():
            return Path(d)
    return None


def _offset(path: Path) -> int:
    return len(path.read_text().splitlines()) if path.is_file() else 0


def _run_tag(run: Path | None) -> str:
    return run.name if run else ""


def _append(path: Path, lines: list[str]) -> None:
    if not lines:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write("\n".join(lines) + "\n")


def _append_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.is_file() or path.stat().st_size == 0
    with path.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ts", "epoch", "step", "loss"])
        if new:
            w.writeheader()
        for r in rows:
            w.writerow(r)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--watch", action="store_true", help="poll loop (default one pass)")
    ap.add_argument("--interval", type=float, default=5.0)
    a = ap.parse_args(argv)

    js = _HERE / "loss-full.jsonl"
    cs = _HERE / "loss-full.csv"
    js_off = _offset(js)
    cs_off = _offset(cs)
    cur_run = ""

    while True:
        run = _newest_run()
        tag = _run_tag(run)
        # A new run is a new series: reset offsets to its own line counts.
        if run and tag != cur_run:
            cur_run = tag
            js_off = 0
            cs_off = 0
            print(f"watching run {tag}", flush=True)
        if run:
            lp = run / "log.jsonl"
            lines = lp.read_text().splitlines()
            rows = [json.loads(l) for l in lines if l.strip()]
            new_j = rows[js_off:]
            new_c = rows[cs_off:]
            if new_j:
                _append(js, [json.dumps(r) for r in new_j])
                js_off += len(new_j)
            if new_c:
                _append_csv(cs, new_c)
                cs_off += len(new_c)
            if new_j and not a.watch:
                print(f"captured {len(new_j)} ticks from {run.name}")
        if not a.watch:
            break
        time.sleep(a.interval)


if __name__ == "__main__":
    raise SystemExit(main())