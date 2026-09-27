#!/usr/bin/env python3
"""eval/harness.py — held-out eval: rulebook floor vs owned model (PLAN #4).

The spine's receipt: a target-disjoint held-out split (a company's findings are
either all-train or all-eval, so training examples never overlap eval examples),
then a scoreboard comparing the rulebook floor (a deterministic OWASP-style
heuristic) against the owned model on the unseen targets.

    python3 eval/harness.py --pairs data/example.pairs.jsonl --stub
    python3 eval/harness.py --pairs data/out/pairs.jsonl --checkpoint river/out/<ts>/meta.json
    python3 eval/harness.py --predict eval/custom_predictor.py:my_predict --pairs data/out/pairs.jsonl
    python3 eval/harness.py --self-test

    # owned checkpoint, single-target corpus: hold out the blind-spot slice
    python3 eval/harness.py --pairs data/out/pairs.jsonl \\
        --checkpoint river://<run-id>/sampler_weights/<name> \\
        --held-out-class blind_spot
    # no key on disk: same split, stub model, owned row marked pending
    python3 eval/harness.py --pairs data/out/pairs.jsonl --stub \\
        --held-out-class blind_spot --pending-checkpoint river://<run-id>/sampler_weights/<name>

Predictor selection (exactly one; defaults to --stub):
  --stub          offline placeholder — majority class of the train split. Runs
                  the whole pipeline with no checkpoint and no network. The
                  scoreboard is labelled STUB MODE whenever this is used.
  --predict fn    offline python predictor, "<path.py>:<function>". The function
                  is called with each pair dict and returns a severity text.
  --checkpoint p  live owned model via river chat_complete_from_checkpoint.
  --pending-checkpoint p  with --stub only: record the owned checkpoint that the
                  model row is waiting on (RIVER_API_KEY missing). The scoreboard
                  marks the owned-model row PENDING instead of presenting the stub
                  as the owned model.

Outputs (out dir, default eval/out/): train.jsonl, eval.jsonl, split.json,
result.json. Scoreboard is written to eval/scoreboard.html by default.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import importlib.util
import json
import os
import random
import re
import sys
from pathlib import Path

try:
    from scoreboard import render           # python3 eval/harness.py
except ImportError:
    from eval.scoreboard import render      # python3 -m eval.harness

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_IDX = {s: i for i, s in enumerate(SEVERITY_ORDER)}
_DEFAULT_FLOOR = "MEDIUM"

# The rulebook floor: the generic OWASP-style checklist every suite runs. It is
# deliberately type-driven and stack-blind — it does not know the company, which
# is exactly why stack-specific blind spots get underrated until the owned model.
_RULEBOOK_BASE = {
    "missing_security_headers": "LOW",
    "missing_csp": "LOW",
    "cookie_flags_missing": "LOW",
    "tls_cert_expiry": "INFO",
    "deprecated_tls": "MEDIUM",
    "exposed_env_file": "CRITICAL",
    "verbose_error": "MEDIUM",
    "directory_listing": "LOW",
    "open_redirect": "MEDIUM",
    "cors_misconfig": "MEDIUM",
    "default_credentials": "HIGH",
    "stale_subdomain": "LOW",
    "graphql_introspection": "MEDIUM",
    "admin_endpoint_exposed": "HIGH",
    "debug_mode_enabled": "MEDIUM",
    "ssrf": "HIGH",
    "sql_injection": "CRITICAL",
    "xss": "HIGH",
    "idor": "HIGH",
    "mass_assignment": "MEDIUM",
    "secrets_in_repo": "HIGH",
    "unpatched_cve": "HIGH",
    "log4j": "CRITICAL",
    "data_exposure": "HIGH",
}

_SEV_RE = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", re.IGNORECASE)
_TYPE_RE = re.compile(r"\btype:\s*([a-z0-9_]+)", re.IGNORECASE)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- data

def load_pairs(path: Path) -> list[dict]:
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        r = json.loads(line)
        for k in ("instruction", "input", "output"):
            if k not in r:
                raise ValueError(f"{path}:{i + 1} missing {k!r}")
        if "provenance" not in r or not r.get("provenance", {}).get("target"):
            raise ValueError(f"{path}:{i + 1} missing provenance.target (needed for target-disjoint split)")
        rows.append(r)
    if not rows:
        raise ValueError(f"{path}: no pairs")
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


# ----------------------------------------------------------------------- split

def split_by_class(pairs: list[dict], held_out_class: str) -> tuple:
    """Row-disjoint class slice for single-target corpora.

    The probe adapter collapses every company into target-01.example, so a
    target-disjoint split cannot isolate the blind-spot rows. Held-out is the
    class slice (e.g. blind_spot = the stack-specific rows the custom model
    must win); train is everything else. Rows are still disjoint: no training
    example is an eval example (the scoreboard's disjoint badge refers to rows).
    """
    train = [p for p in pairs if (p.get("provenance") or {}).get("class") != held_out_class]
    ev = [p for p in pairs if (p.get("provenance") or {}).get("class") == held_out_class]
    if not ev:
        raise ValueError(f"empty eval split — no rows of class {held_out_class!r} in the corpus")
    if not train:
        raise ValueError("empty train split — class-slice needs rows of the other class too")
    train_targets = sorted({p["provenance"]["target"] for p in train})
    eval_targets = sorted({p["provenance"]["target"] for p in ev})
    overlap = set(train_targets) & set(eval_targets)
    return train, ev, {
        "method": "class-slice", "held_out_class": held_out_class,
        "train_targets": train_targets, "eval_targets": eval_targets,
        # rows never overlap (classes partition the corpus); a single target may span both classes
        "disjoint": True,
        "note": ("single-target corpus — held-out is the blind_spot class slice; "
                 "no training row is an eval row"),
        "target_overlap": sorted(overlap),
    }


def split_by_target(pairs: list[dict], held_out_frac: float = 0.35,
                    seed: int = 0, held_out_targets: list[str] | None = None) -> tuple:
    """Target-disjoint held-out split: targets are either all-train or all-eval."""
    targets = sorted({p["provenance"]["target"] for p in pairs})
    if held_out_targets:
        hold = [t for t in held_out_targets if t in targets]
        unknown = [t for t in held_out_targets if t not in targets]
        if unknown:
            print(f"note: held-out targets not in corpus: {unknown}", file=sys.stderr)
        if not hold:
            raise ValueError("--held-out-targets matched no corpus targets")
    else:
        rng = random.Random(seed)
        ordered = list(targets)
        rng.shuffle(ordered)
        k = max(1, round(len(targets) * held_out_frac))
        if len(targets) > 1:
            k = min(k, len(targets) - 1)          # keep at least one train target
        hold = ordered[:k]

    hold = set(hold)
    train = [p for p in pairs if p["provenance"]["target"] not in hold]
    ev = [p for p in pairs if p["provenance"]["target"] in hold]
    if not ev:
        raise ValueError("empty eval split — need at least one held-out target")

    train_targets = sorted({p["provenance"]["target"] for p in train})
    eval_targets = sorted(hold)
    assert not (set(train_targets) & set(eval_targets)), "target overlap — split is not disjoint"
    return train, ev, {
        "method": "target-disjoint", "seed": seed, "held_out_frac": held_out_frac,
        "train_targets": train_targets, "eval_targets": eval_targets,
        "disjoint": True,
    }


# ------------------------------------------------------------------ predictions

def parse_severity(text: str | None) -> str | None:
    if not text:
        return None
    m = _SEV_RE.search(text)
    return m.group(1).upper() if m else None


def _extract_type(pair: dict) -> str | None:
    m = _TYPE_RE.search(pair.get("input", ""))
    if m:
        return m.group(1).lower()
    low = (pair.get("input", "") + " " + pair.get("type", "")).lower().replace("_", " ")
    for key in _RULEBOOK_BASE:
        if key.replace("_", " ") in low:
            return key
    return None


def rulebook_severity(pair: dict) -> str:
    """Deterministic stack-blind floor. Picks a per-type severity; only one
    narrow, well-known override: expiring certs that are NOT auto-renewing."""
    typ = _extract_type(pair)
    sev = _RULEBOOK_BASE.get(typ, _DEFAULT_FLOOR)
    if typ == "tls_cert_expiry":
        low = (pair.get("input", "") + " " + pair.get("detail", "")).lower()
        if ("not renewed" in low or "no renewal" in low or
                ("expires" in low and "auto-renew" not in low)):
            sev = "MEDIUM"
    return sev


def _majority_class_predictor(train_pairs: list[dict]) -> tuple:
    counts: dict[str, int] = {}
    for p in train_pairs:
        s = parse_severity(p.get("output", ""))
        if s:
            counts[s] = counts.get(s, 0) + 1
    if not counts:
        mode, n = "MEDIUM", 0
    else:
        mode = sorted(counts.items(), key=lambda kv: (-kv[1], SEVERITY_IDX[kv[0]]))[0][0]
        n = sum(counts.values())
    note = (f"placeholder — predicts the train split's majority class ({mode}, "
            f"{n} train labels); NOT the owned model")
    return (lambda pair: mode), {"kind": "stub", "note": note}


def _load_predict_fn(spec: str):
    path_s, _, fn_name = spec.partition(":")
    if not path_s or not fn_name:
        raise ValueError("--predict expects '<path.py>:<function>'")
    path = Path(path_s).resolve()
    if not path.exists():
        raise ValueError(f"--predict: no such file: {path}")
    mod = importlib.util.spec_from_file_location(f"eval_predict_{path.stem}", path)
    assert mod and mod.loader
    module = importlib.util.module_from_spec(mod)
    mod.loader.exec_module(module)
    fn = getattr(module, fn_name, None)
    if not callable(fn):
        raise ValueError(f"--predict: {fn_name!r} is not callable in {path}")
    return fn, {"kind": "predict", "note": f"custom offline predictor {spec}"}


def _base_from_latest_run() -> str | None:
    """Base model recorded by the newest river/out/<ts>/meta.json — the
    checkpoint's true base beats a hardcoded guess."""
    out = _ROOT / "river" / "out"
    metas = sorted(out.glob("*/meta.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for m in metas:
        try:
            b = json.loads(m.read_text(encoding="utf-8")).get("base_model")
            if b:
                return b
        except Exception:
            continue
    return None


def _checkpoint_predictor(checkpoint: str):
    api_key = os.environ.get("RIVER_API_KEY")
    if not api_key:
        raise RuntimeError("--checkpoint needs RIVER_API_KEY (or use --stub / --predict offline)")
    try:
        import river
        if not hasattr(river, "Client"):  # local river/ dir shadows the SDK
            raise ImportError
    except ImportError:
        try:
            import river_client as river
        except ModuleNotFoundError:
            raise RuntimeError("--checkpoint needs the `river-client` package installed "
                               "(or use --stub / --predict offline)")
    client = river.Client(api_key=api_key)
    base = os.environ.get("RIVER_BASE_MODEL") or _base_from_latest_run() \
        or "Qwen/Qwen3.5-9B"

    def predict(pair: dict) -> str:
        user = pair["instruction"].rstrip() + "\n\n" + pair["input"].strip()
        out = client.chat_complete_from_checkpoint(
            messages=[{"role": "user", "content": user}],
            checkpoint_path=checkpoint, base_model=base)
        if hasattr(out, "response_json"):        # ChatCompleteResult (river_client 0.12+)
            out = out.response_json
        if isinstance(out, dict):
            text = out.get("content") or out.get("output")
            if text is None:
                text = (out.get("message") or {}).get("content") if isinstance(out.get("message"), dict) else None
        else:
            text = str(out)
        return str(text or "")

    return predict, {"kind": "checkpoint", "checkpoint": checkpoint,
                     "note": f"owned model checkpoint {checkpoint}"}


def _build_predictor(args, train: list[dict]):
    given = [args.stub, bool(args.predict), bool(args.checkpoint)]
    if sum(1 for g in given if g) > 1:
        raise ValueError("pick exactly one of --stub / --predict / --checkpoint")
    if args.predict:
        return _load_predict_fn(args.predict)
    if args.checkpoint:
        return _checkpoint_predictor(args.checkpoint)
    return _majority_class_predictor(train)


# ----------------------------------------------------------------------- metrics

def _exact(pred: str | None, gold: str | None) -> bool:
    return gold is not None and pred == gold


def _agree(pred: str | None, gold: str | None) -> bool:
    if gold is None or pred is None:
        return False
    return abs(SEVERITY_IDX[pred] - SEVERITY_IDX[gold]) <= 1


def _metrics_for(rows: list[dict], pred_key: str) -> dict:
    def calc(sub: list[dict]) -> dict:
        n = len(sub)
        exact = sum(1 for r in sub if _exact(r[pred_key], r["gold"]))
        agree = sum(1 for r in sub if _agree(r[pred_key], r["gold"]))
        return {"n": n, "exact": exact, "agreement": agree,
                "accuracy": exact / n if n else 0.0,
                "agreement_rate": agree / n if n else 0.0}

    return {"overall": calc(rows),
            "standard": calc([r for r in rows if r["class"] == "standard"]),
            "blind_spot": calc([r for r in rows if r["class"] == "blind_spot"])}


def _pick_winner(rulebook: dict, model: dict) -> dict:
    def better(a: dict, b: dict) -> str:
        aa, bb = a["accuracy"], b["accuracy"]
        if aa > bb:
            return "model"
        if bb > aa:
            return "rulebook"
        return "tie"

    overall = better(model["overall"], rulebook["overall"])
    blind_spot = better(model["blind_spot"], rulebook["blind_spot"])
    return {"overall": overall, "blind_spot": blind_spot}


# ------------------------------------------------------------------------- main

def run_eval(pairs: list[dict], args) -> dict:
    if getattr(args, "held_out_class", None):
        train, ev, split_info = split_by_class(pairs, args.held_out_class)
    else:
        train, ev, split_info = split_by_target(
            pairs, held_out_frac=args.held_out_frac, seed=args.seed,
            held_out_targets=args.held_out_targets)

    out_dir = Path(args.out_dir)
    write_jsonl(out_dir / "train.jsonl", train)
    write_jsonl(out_dir / "eval.jsonl", ev)
    split_info.update(n_pairs=len(pairs), n_train=len(train), n_eval=len(ev))
    (out_dir / "split.json").write_text(json.dumps(split_info, indent=2, sort_keys=True) + "\n")

    predict, mode = _build_predictor(args, train)

    pending = getattr(args, "pending_checkpoint", None)
    if args.stub and pending:
        mode["pending"] = {
            "checkpoint": pending,
            "reason": "RIVER_API_KEY not set — the owned checkpoint exists but no key was "
                      "found (env, ~/.env, worktrees). Set RIVER_API_KEY and re-run with "
                      "--checkpoint <this path> to produce the real owned-model row.",
        }

    rows = []
    for p in ev:
        gold = parse_severity(p.get("output", ""))
        rb = rulebook_severity(p)
        raw = predict(p)
        model = parse_severity(raw)
        rows.append({
            "target": p["provenance"]["target"],
            "class": p.get("provenance", {}).get("class", "standard"),
            "type": _extract_type(p) or "unknown",
            "gold": gold, "gold_raw": p.get("output", ""),
            "rulebook": rb,
            "model": model, "model_raw": str(raw),
        })

    metrics = {
        "rulebook": _metrics_for(rows, "rulebook"),
        "model": _metrics_for(rows, "model"),
    }
    winner = _pick_winner(metrics["rulebook"], metrics["model"])

    result = {
        "title": "Severity scoreboard — owned model vs rulebook floor",
        "generated_at": _now(),
        "command": " ".join(sys.argv),
        "mode": mode,
        "split": split_info,
        "metrics": metrics,
        "winner": winner,
        "rows": rows,
    }
    (out_dir / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    return result


def _self_test() -> int:
    pairs = load_pairs(_ROOT / "data" / "example.pairs.jsonl")
    train, ev, split = split_by_target(pairs, held_out_frac=0.4, seed=4)
    assert split["disjoint"] and ev and train
    assert not (set(split["train_targets"]) & set(split["eval_targets"]))
    assert all(parse_severity(p.get("output")) in SEVERITY_ORDER for p in pairs)

    class _Args:
        pairs = None
        stub = True
        predict = None
        checkpoint = None
        held_out_frac = 0.4
        seed = 4
        held_out_targets = None
        out_dir = str(_ROOT / "eval" / "out")

    result = run_eval(pairs, _Args())
    m, r = result["metrics"]["model"], result["metrics"]["rulebook"]
    assert m["overall"]["n"] == result["split"]["n_eval"] > 0
    assert (m["overall"]["n"] == m["standard"]["n"] + m["blind_spot"]["n"])
    assert (r["overall"]["n"] == r["standard"]["n"] + r["blind_spot"]["n"])
    assert result["mode"]["kind"] == "stub"
    html_out = render(result)
    assert "STUB MODE" in html_out
    assert "scoreboard" in html_out.lower()
    print(f"self-test OK: {result['split']['n_pairs']} pairs -> "
          f"{result['split']['n_train']} train / {result['split']['n_eval']} eval "
          f"(targets {result['split']['eval_targets']}); model {m['overall']['accuracy']:.0%} vs "
          f"rulebook {r['overall']['accuracy']:.0%} overall; html {len(html_out)} bytes")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="eval/harness.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--pairs", default=str(_ROOT / "data" / "example.pairs.jsonl"))
    ap.add_argument("--stub", action="store_true", help="offline majority-class placeholder predictor")
    ap.add_argument("--predict", default=None, help="offline python predictor '<path.py>:<function>'")
    ap.add_argument("--checkpoint", default=None, help="owned river checkpoint (needs RIVER_API_KEY)")
    ap.add_argument("--pending-checkpoint", default=None,
                    help="with --stub only: owned checkpoint the model row is waiting on "
                         "(marks the scoreboard PENDING; no API call)")
    ap.add_argument("--held-out-frac", type=float, default=0.35, help="fraction of targets held out")
    ap.add_argument("--held-out-targets", default=None, help="comma-separated explicit eval targets")
    ap.add_argument("--held-out-class", default=None,
                    help="hold out one class slice instead of targets (e.g. blind_spot) — for "
                         "single-target corpora the probe adapter collapses to one target")
    ap.add_argument("--seed", type=int, default=4,
                    help="split seed (deterministic); 4 holds out the fixture's blind-spot targets")
    ap.add_argument("--out-dir", default=str(_HERE / "out"))
    ap.add_argument("--scoreboard", default=str(_HERE / "scoreboard.html"))
    a = ap.parse_args(argv)

    if a.self_test:
        return _self_test()

    if a.pending_checkpoint and not a.stub:
        print("error: --pending-checkpoint is only meaningful with --stub", file=sys.stderr)
        return 1

    held_out_targets = [t.strip() for t in a.held_out_targets.split(",") if t.strip()] \
        if a.held_out_targets else None
    a.held_out_targets = held_out_targets

    pairs = load_pairs(Path(a.pairs))
    try:
        result = run_eval(pairs, a)
    except (ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    html_out = render(result)
    Path(a.scoreboard).write_text(html_out, encoding="utf-8")

    print(f"wrote {a.scoreboard} ({len(html_out)} bytes)")
    print(f"split: {result['split']['n_train']} train / {result['split']['n_eval']} eval "
          f"(eval targets {result['split']['eval_targets']}, disjoint={result['split']['disjoint']})")
    if result["mode"]["kind"] == "stub":
        print(f"STUB MODE — {result['mode']['note']}")
        who = "model(stub)"
    else:
        print(f"predictor: {result['mode']['note']}")
        who = "model"
    print(f"overall accuracy — {who} {result['metrics']['model']['overall']['accuracy']:.0%} vs "
          f"rulebook {result['metrics']['rulebook']['overall']['accuracy']:.0%} "
          f"(winner: {result['winner']['overall']}; blind-spot winner: {result['winner']['blind_spot']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())