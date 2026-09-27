#!/usr/bin/env python3
"""river/train.py — pairs JSONL -> owned LoRA checkpoint on River.

This is the hero module: "customization per company stack is expensive" ->
a per-company security model is a ~15-minute LoRA on that company's own
de-identified findings. The company holds the weights.

    python3 river/train.py --self-test                       # offline, zero deps
    python3 river/train.py --pairs data/example.pairs.jsonl --dry-run
    python3 river/train.py --pairs data/out/pairs.jsonl --live

--live needs env RIVER_API_KEY (and optionally RIVER_BASE_MODEL; otherwise
the smallest model get_capabilities() reports is used). Every run writes
river/out/<utc-ts>-<name>/{meta.json,log.jsonl,checkpoint.txt,smoke.json}.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_OUT = _HERE / "out"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_pairs(path: Path) -> list[dict]:
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        r = json.loads(line)
        for k in ("instruction", "input", "output"):
            if k not in r:
                raise ValueError(f"{path}:{i + 1} missing {k!r}")
        rows.append(r)
    if not rows:
        raise ValueError(f"{path}: no pairs")
    return rows


def render_messages(pair: dict) -> list[dict]:
    user = pair["instruction"].rstrip() + "\n\n" + pair["input"].strip()
    return [{"role": "user", "content": user},
            {"role": "assistant", "content": pair["output"].strip()}]


class DummyTokenizer:
    """Byte-level stand-in so --self-test exercises batch math with no HF install."""

    def __call__(self, text: str) -> list[int]:
        return list(text.encode("utf-8"))


def _as_ids(x) -> list[int]:
    """Normalize tokenizer output -> flat list[int].

    Handles BatchEncoding (newer transformers), tensors, and batch dims.
    """
    from collections.abc import Mapping
    if isinstance(x, Mapping):
        x = x["input_ids"]                      # BatchEncoding
    if hasattr(x, "tolist"):
        x = x.tolist()
    if isinstance(x, (list, tuple)) and x and isinstance(x[0], (list, tuple)):
        x = x[0]                                # batch dim
    ids = [int(i) for i in x]
    if not ids:
        raise ValueError("tokenizer produced no ids")
    return ids


def encode_example(pair: dict, tok, max_len: int = 2048) -> dict | None:
    """-> River forward_backward row: {input_ids, target_tokens, weights}.

    Prompt tokens get weight 0 (we don't learn to ask), completion gets 1.
    """
    msgs = render_messages(pair)
    if hasattr(tok, "apply_chat_template"):
        prompt_ids = _as_ids(tok.apply_chat_template(msgs[:-1], add_generation_prompt=True))
        full_ids = _as_ids(tok.apply_chat_template(msgs))
    else:
        prompt_ids = tok(msgs[0]["content"] + "\n")
        full_ids = tok(msgs[0]["content"] + "\n" + msgs[1]["content"])
    full_ids = full_ids[:max_len]
    n_prompt = min(len(prompt_ids), len(full_ids))
    n_comp = len(full_ids) - n_prompt
    if n_comp <= 0 or len(full_ids) < 2:
        return None
    return {
        "input_ids": full_ids[:-1],
        "target_tokens": full_ids[1:],
        "weights": [0.0] * max(0, n_prompt - 1) + [1.0] * n_comp,
    }


def build_batches(pairs: list[dict], tok, batch_size: int, max_len: int) -> list[list[dict]]:
    examples = [e for e in (encode_example(p, tok, max_len) for p in pairs) if e]
    if not examples:
        raise ValueError("no usable pairs after tokenization")
    return [examples[i:i + batch_size] for i in range(0, len(examples), batch_size)]


def get_tokenizer(base_model: str | None):
    from transformers import AutoTokenizer
    return AutoTokenizer.from_pretrained(base_model or os.environ.get("RIVER_BASE_MODEL", "Qwen/Qwen3.5-9B"))


def _pick_base(caps) -> str:
    """Smallest model the key can see — cheapest, fastest to train."""
    names = []
    for c in caps if isinstance(caps, list) else getattr(caps, "models", []):
        n = c if isinstance(c, str) else getattr(c, "name", None) or getattr(c, "id", None)
        if n:
            names.append(str(n))
    if not names:
        raise RuntimeError("get_capabilities() returned no usable model names; set RIVER_BASE_MODEL")
    def size_key(n: str) -> float:
        import re
        m = re.search(r"(\d+(?:\.\d+)?)B", n)
        return float(m.group(1)) if m else 1e9
    return min(names, key=size_key)


def _next_name() -> str:
    """Next free `company-model-v<N>` name based on existing run dirs."""
    import re
    nxt = 1
    if _OUT.is_dir():
        seen = [int(m.group(1)) for d in _OUT.iterdir()
                if (m := re.search(r"company-model-v(\d+)", d.name))]
        if seen:
            nxt = max(seen) + 1
    return f"company-model-v{nxt}"


def live_train(args) -> int:
    import river_client as river

    api_key = os.environ.get("RIVER_API_KEY")
    if not api_key:
        print("RIVER_API_KEY not set", file=sys.stderr)
        return 2

    pairs = load_pairs(Path(args.pairs))
    client = river.Client(api_key=api_key)
    client.health_check()
    base = args.base_model or os.environ.get("RIVER_BASE_MODEL") or _pick_base(client.get_capabilities())
    try:
        tok = get_tokenizer(base)
    except Exception as e:
        print(f"tokenizer for {base!r} not loadable from HF ({e}) — set "
              "RIVER_BASE_MODEL to a HF repo id or pass --base-model", file=sys.stderr)
        return 2
    batches = build_batches(pairs, tok, args.batch_size, args.max_len)

    name = args.name or _next_name()
    started = _now()
    run_dir = _OUT / f"{started.replace(':', '-')}-{name}"
    suffix = 1
    while run_dir.exists():          # same-second re-run of the same name
        suffix += 1
        run_dir = _OUT / f"{started.replace(':', '-')}-{name}-{suffix}"
    run_dir.mkdir(parents=True)
    log_path = run_dir / "log.jsonl"
    meta = {
        "kind": "river-train", "started_at": started, "pairs": str(args.pairs),
        "n_pairs": len(pairs), "n_examples": sum(len(b) for b in batches),
        "base_model": base, "rank": args.rank, "lr": args.lr,
        "epochs": args.epochs, "batch_size": args.batch_size,
    }

    with client.session(project="customsecuritymodel") as session:
        model = session.create_model(base_model=base, lora=river.LoraConfig(rank=args.rank))
        step = 0
        tokens_total = 0
        t_step0 = time.time()
        for epoch in range(args.epochs):
            random.shuffle(batches)
            for batch in batches:
                t0 = time.time()
                fb = model.forward_backward(batch, loss_fn="cross_entropy")
                model.optim_step(lr=args.lr, grad_clip_norm=1.0)
                dt_step = time.time() - t0
                n_tok = sum(len(e.get("target_tokens", [])) for e in batch)
                tokens_total += n_tok
                rec = {"ts": _now(), "epoch": epoch, "step": step,
                       "loss": (fb.metrics or {}).get("loss"),
                       "tokens": n_tok, "step_s": round(dt_step, 3),
                       "tokens_cum": tokens_total}
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
                print(f"[{rec['ts']}] epoch {epoch} step {step} loss {rec['loss']} "
                      f"tok {n_tok} {dt_step:.1f}s")
                step += 1
        ckpt = model.save_weights(name, mode="inference")

    meta.update(ended_at=_now(), checkpoint=str(getattr(ckpt, "path", ckpt)),
                steps=step, n_tokens_epoch=tokens_total // args.epochs,
                n_tokens_total=tokens_total, wall_s=time.time() - t_step0)
    (run_dir / "checkpoint.txt").write_text(meta["checkpoint"] + "\n")

    try:
        smoke = client.chat_complete_from_checkpoint(
            messages=render_messages(random.choice(pairs))[:-1],
            checkpoint_path=meta["checkpoint"], base_model=base)
        (run_dir / "smoke.json").write_text(json.dumps(
            getattr(smoke, "response_json", smoke), indent=2, default=str))
    except Exception as e:  # serve layer may lag checkpoint; the weights still exist
        meta["smoke_error"] = str(e)

    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    _snapshot_run(run_dir, meta, Path(args.pairs))
    print(f"checkpoint: {meta['checkpoint']}\nartifacts: {run_dir}")
    return 0


def _snapshot_run(run_dir: Path, meta: dict, pairs_path: Path) -> None:
    """Promote the run's provenance record into tracked runlogs/artifacts/ —
    river/out/ is gitignored, so without this the checkpoint record vanishes."""
    dest = _ROOT / "runlogs" / "artifacts" / run_dir.name
    try:
        dest.mkdir(parents=True, exist_ok=True)
        import shutil
        for name in ("meta.json", "checkpoint.txt", "smoke.json", "log.jsonl"):
            src = run_dir / name
            if src.exists():
                shutil.copy2(src, dest / name)
        manifest = pairs_path.parent / "manifest.json"
        if manifest.exists():
            shutil.copy2(manifest, dest / "pairs-manifest.json")
        index = dest.parent / "INDEX.md"
        if not index.exists():
            index.write_text("# Training-run artifacts\n\n"
                             "| ts | name | checkpoint | pairs | base |\n|---|---|---|---|---|\n",
                             encoding="utf-8")
        with index.open("a", encoding="utf-8") as f:
            f.write(f"| {meta.get('started_at','')} | {run_dir.name} | "
                    f"`{meta.get('checkpoint','')}` | {meta.get('n_pairs','')} "
                    f"| {meta.get('base_model','')} |\n")
        print(f"snapshot: {dest}")
    except Exception as e:  # never fail a successful train over bookkeeping
        print(f"note: artifact snapshot failed ({e})", file=sys.stderr)


def _self_test() -> int:
    pairs = load_pairs(_ROOT / "data" / "example.pairs.jsonl")
    batches = build_batches(pairs, DummyTokenizer(), batch_size=4, max_len=2048)
    ex = batches[0][0]
    n = len(ex["input_ids"])
    assert len(ex["target_tokens"]) == n and len(ex["weights"]) == n
    assert ex["weights"][-1] == 1.0 and 0.0 in ex["weights"]          # mask covers prompt
    assert sum(1 for w in ex["weights"] if w == 1.0) > 0             # completion survives
    total_w = sum(sum(e["weights"]) for b in batches for e in b)
    assert total_w > 0
    # meta.json round-trip on a fake run dir
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td) / "2026-09-27T00-00-00Z-test"
        rd.mkdir()
        meta = {"kind": "river-train", "started_at": _now(), "ended_at": _now(),
                "checkpoint": "river://x/sampler_weights/test", "steps": 3}
        (rd / "meta.json").write_text(json.dumps(meta))
        assert json.loads((rd / "meta.json").read_text())["steps"] == 3
    print(f"self-test OK: {len(pairs)} pairs -> {len(batches)} batches, "
          f"{n} tokens in ex[0], {total_w:.0f} supervised tokens")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="river/train.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--pairs", default=str(_ROOT / "data" / "example.pairs.jsonl"))
    ap.add_argument("--live", action="store_true", help="real River run")
    ap.add_argument("--dry-run", action="store_true", help="tokenize + batch, no training")
    ap.add_argument("--name", default=None,
                    help="run/checkpoint name; defaults to the next company-model-v<N>")
    ap.add_argument("--base-model", default=None)
    ap.add_argument("--rank", type=int, default=32)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--max-len", type=int, default=2048)
    a = ap.parse_args(argv)

    if a.self_test:
        return _self_test()
    if a.dry_run:
        pairs = load_pairs(Path(a.pairs))
        try:
            tok = get_tokenizer(a.base_model)
            tok_name = "hf"
        except Exception:
            tok, tok_name = DummyTokenizer(), "dummy (install transformers for real counts)"
        batches = build_batches(pairs, tok, a.batch_size, a.max_len)
        lens = [len(e["input_ids"]) for b in batches for e in b]
        print(f"{len(pairs)} pairs -> {len(batches)} batches/epoch "
              f"(batch={a.batch_size}, tok={tok_name}, len min/med/max "
              f"{min(lens)}/{sorted(lens)[len(lens)//2]}/{max(lens)})")
        return 0
    if a.live:
        return live_train(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
