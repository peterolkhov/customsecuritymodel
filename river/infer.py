#!/usr/bin/env python3
"""river/infer.py — paste a finding, get the company's severity.

Thin checkpoint wrapper for the demo/video. Reads a single finding
(host + type + detail) and returns the severity the *owned* per-company
model assigns — using the same prompt/format it was trained on.

    echo 'type: exposed_env_file; host: static.target-02.example; detail: /.env returns 200 with DATABASE_URL' | \
        python3 river/infer.py --checkpoint <path>

    python3 river/infer.py --checkpoint <path> --file finding.txt
    python3 river/infer.py --checkpoint <path> --finding 'type: tls_cert_expiry; host: api.target-01.example; ...'
    python3 river/infer.py --checkpoint <path> --finding '...' --dry-run    # offline: show the exact messages

    # no --checkpoint: the newest owned checkpoint in river/out/ is auto-discovered
    echo 'type: exposed_env_file; host: static.target-02.example; detail: /.env returns 200' | \
        python3 river/infer.py

    python3 river/infer.py --finding 'type: graphql_introspection; host: api.target-01.example; ...'

The finding may also be a full JSONL pair row (from data/*.pairs.jsonl); it is
then sent as-is, preserving its own instruction/input.

Needs env RIVER_API_KEY (free credits from the River booth — they expire end of
day). Without it the script exits with a clear message and never makes a call.
Helpers (render_messages, encode_example) are imported from river/train.py so
infer and train can never drift apart.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

try:  # repo-root invocation: python3 -m river.infer
    from river.train import render_messages
except ImportError:  # script invocation: python3 river/infer.py
    from train import render_messages

DEFAULT_INSTRUCTION = "Given this finding, assign a severity for THIS company's stack."
_OUT = Path(__file__).resolve().parent / "out"


def latest_checkpoint() -> tuple[str | None, dict]:
    """Newest owned checkpoint in river/out/, else (None, {}).

    Reads checkpoint.txt (the river:// URI) + meta.json (base_model) from the
    most recent run dir — the same discovery suite/build_suite.py uses, so
    infer and the suite generator always agree on which model is "owned".
    """
    if not _OUT.is_dir():
        return None, {}
    runs = sorted((d for d in _OUT.iterdir()
                   if (d / "checkpoint.txt").is_file()),
                  key=lambda d: d.stat().st_mtime, reverse=True)
    if not runs:
        return None, {}
    ck = (runs[0] / "checkpoint.txt").read_text(encoding="utf-8").strip()
    meta: dict = {}
    mp = runs[0] / "meta.json"
    if mp.is_file():
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
    return (ck or meta.get("checkpoint")), meta


def _parse(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="river/infer.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--checkpoint",
                    help="checkpoint path/URI from a river/train.py run "
                         "(river/out/<ts>/checkpoint.txt)")
    ap.add_argument("--base-model", default=None,
                    help="base model the checkpoint was trained on "
                         "(default: RIVER_BASE_MODEL env)")
    ap.add_argument("--finding", default=None,
                    help="finding text inline (type/host/detail) instead of stdin")
    ap.add_argument("--file", default=None,
                    help="read the finding from a file instead of stdin")
    ap.add_argument("--instruction", default=DEFAULT_INSTRUCTION,
                    help="severity prompt (must match what the model was trained on)")
    ap.add_argument("--dry-run", action="store_true",
                    help="offline: print the exact messages that would be sent")
    ap.add_argument("--json", action="store_true",
                    help="print the raw API response object, not just the text")
    return ap.parse_args(argv)


def _read_finding(a) -> str:
    if a.finding:
        text = a.finding
    elif a.file:
        text = Path(a.file).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()
    text = text.strip()
    if not text:
        raise SystemExit(
            "no finding supplied (stdin was empty) — pass --finding '...' or --file finding.txt")
    return text


def _build_messages(a, finding: str) -> list[dict]:
    """-> [{role: user, content: ...}] — one-turn, same shape as training.

    Reuses render_messages() from river/train.py (the exact
    instruction.rstrip() + \"\\n\\n\" + input.strip() join). A JSONL pair row
    keeps its own instruction/input.
    """
    pair = None
    if finding.lstrip().startswith("{"):
        try:
            row = json.loads(finding)
            if isinstance(row, dict) and row.get("input"):
                pair = {"instruction": row.get("instruction") or a.instruction,
                        "input": row["input"], "output": ""}
        except json.JSONDecodeError:
            pair = None
    if pair is None:
        pair = {"instruction": a.instruction, "input": finding, "output": ""}
    return render_messages(pair)[:-1]  # user turn only; no assistant echo


def _extract_text(resp) -> str:
    """Best-effort pull of the model's text out of whatever the SDK returned."""
    if hasattr(resp, "response_json"):           # ChatCompleteResult (river_client 0.12+)
        resp = resp.response_json
    if isinstance(resp, str):
        # Some river_client builds return response_json as a JSON-encoded
        # string — decode it before extracting the text.
        stripped = resp.strip()
        if stripped.startswith("{"):
            try:
                resp = json.loads(stripped)
            except json.JSONDecodeError:
                return stripped
        else:
            return stripped
    if isinstance(resp, (list, tuple)) and resp:
        resp = resp[0]
    if hasattr(resp, "get"):
        for key in ("content", "text", "output", "response", "answer", "completion"):
            v = resp.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        choices = resp.get("choices")
        if choices:
            c = choices[0]
            if isinstance(c, dict):
                msg = c.get("message") or c.get("delta")
                if isinstance(msg, dict) and msg.get("content"):
                    return msg["content"].strip()
                if c.get("text"):
                    return c["text"].strip()
        msg = resp.get("message")
        if isinstance(msg, dict) and msg.get("content"):
            return msg["content"].strip()
    return json.dumps(resp, default=str)


def _river_sdk():
    """river-client installs as `river_client`; `import river` inside this repo
    resolves to the local river/ directory (a namespace package with no Client)."""
    try:
        import river
        if hasattr(river, "Client"):
            return river
    except ImportError:
        pass
    import river_client
    return river_client


def _infer(a, api_key: str, messages: list[dict]) -> int:
    try:
        river = _river_sdk()
        client = river.Client(api_key=api_key)
        base = a.base_model or os.environ.get("RIVER_BASE_MODEL")
        resp = client.chat_complete_from_checkpoint(
            messages=messages, checkpoint_path=a.checkpoint, base_model=base)
    except Exception as e:
        print(f"infer failed: {e} (the checkpoint may lag the serving layer — "
              "the weights still exist)", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(resp, indent=2, default=str))
    else:
        print(_extract_text(resp))
    return 0


def main(argv=None) -> int:
    a = _parse(argv)

    api_key = os.environ.get("RIVER_API_KEY")
    if not api_key and not a.dry_run:
        print("RIVER_API_KEY not set. To use the checkpoint: set RIVER_API_KEY=<key> "
              "(free credits from the River booth, they expire end of day). "
              "Offline preview without a key: --dry-run.", file=sys.stderr)
        return 2

    if not a.checkpoint and not a.dry_run:
        ck, meta = latest_checkpoint()
        if ck:
            a.checkpoint = ck
            if not a.base_model and meta.get("base_model"):
                a.base_model = meta["base_model"]
            print(f"using owned checkpoint: {ck} "
                  f"(base {a.base_model or 'default'}, auto-discovered from river/out/)",
                  file=sys.stderr)
        else:
            print("missing --checkpoint: pass the path from river/out/<ts>/checkpoint.txt "
                  "(none auto-discovered in river/out/)", file=sys.stderr)
            return 2

    finding = _read_finding(a)
    messages = _build_messages(a, finding)

    if a.dry_run:
        print(json.dumps(messages, indent=2))
        return 0

    return _infer(a, api_key, messages)


if __name__ == "__main__":
    raise SystemExit(main())