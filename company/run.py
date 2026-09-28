#!/usr/bin/env python3
"""company/run.py — company-facing orchestrator CLI.

How a company actually deploys/trains on their architecture: a security
engineer runs ONE command pointing at their probe scan report.json and this
tool (1) de-identifies the findings into training pairs, (2) trains THEIR
LoRA on THEIR stack via the River API, (3) ingests the findings into their
GBrain memory, and (4) generates their custom security suite.

    python3 company/run.py onboard --company <name> --scan <path/to/report.json> [--train] [--name <ckpt-name>] [--max-rows N]
    python3 company/run.py update  --company <name> --scan <path/to/report.json> [--train]
    python3 company/run.py infer   [--finding 'type: x; host: y; detail: z'] [--file <path>] [--company <name>]
    python3 company/run.py status  [--company <name>]
    python3 company/run.py selftest
    python3 company/run.py demo

Everything is OFFLINE by default: `river/train.py --dry-run` shows token/batch
stats and the suite reports "no owned model yet"; the GBrain sync only happens
if `gbrain` is on PATH (the local mirror memory/brain-local.jsonl is always the
fallback). Go live only with `--train` plus env RIVER_API_KEY — that lands a
checkpoint in river/out/ which infer and the suite auto-discover.

The pipeline is chained through the PAIRS JSONL so target ids/classes/
de-identification stay consistent end-to-end (the raw scan is never ingested
into the brain — only the de-identified pairs).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

_SCRATCH = _HERE / "out"
_SUITE_OUT = _HERE / "out" / "suites"   # per-company generated suites stay out of suite/ (reference stacks)
_DEFAULT_MAX_ROWS = 300
_BRAIN_INDEX = _ROOT / "memory" / "brain.json"

_EXIT_USAGE = 2
_EXIT_REFUSE = 3
_EXIT_STEP = 1

_DEMO_NARRATIVE = """\
HOW A COMPANY USES IT
=====================
A company security engineer runs ONE command to onboard their stack onto a
per-company custom security model. Point at a probe scan report.json and the
toolchain (1) de-identifies the findings into training pairs, (2) trains a
LoRA on THEIR stack via River, (3) ingests the findings into their GBrain
memory, and (4) generates their custom security suite.

    $ python3 company/run.py onboard --company acme --scan path/to/report.json

The flywheel: after every later scan, re-run memory + suite.

    $ python3 company/run.py update --company acme --scan path/to/report2.json

And paste a new finding to get the owned model's severity:

    $ python3 company/run.py infer --company acme \
        --finding 'type: exposed_env_file; host: static.acme-corp.com; detail: /.env returns 200'

This run below executes the first onboarding end-to-end, OFFLINE by default:
dry-run train (no River key) + the local GBrain mirror.
"""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _run(argv: list[str], extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run a repo script with this interpreter, capturing stdout/stderr."""
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    return subprocess.run([sys.executable, *argv], cwd=str(_ROOT),
                          capture_output=True, text=True, env=env)


def _step(label: str, argv: list[str], echo: bool = False) -> subprocess.CompletedProcess:
    """Run one pipeline script; echo=True shows the command + full output."""
    if echo:
        print(f"  $ python3 {' '.join(str(a) for a in argv)}")
    proc = _run(argv, extra_env={"HF_HUB_OFFLINE": "1"} if "train.py" in argv[0] else None)
    if echo:
        for line in (proc.stdout or "").rstrip().splitlines():
            print(f"    {line}")
    if proc.returncode != 0 and proc.stderr:
        for line in proc.stderr.rstrip().splitlines():
            print(f"    {line}", file=sys.stderr)
    return proc


def _read_pairs(path: Path) -> tuple[list[dict], str | None]:
    """Rows + the single distinct provenance.target pseudonym for this company."""
    rows: list[dict] = []
    targets: set[str] = set()
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            raise ValueError(f"{path}:{i + 1} not a JSON row")
        rows.append(r)
        t = (r.get("provenance") or {}).get("target")
        if t:
            targets.add(t)
    return rows, sorted(targets)[0] if targets else None


def _latest_checkpoint() -> tuple[str | None, dict]:
    """Newest owned checkpoint in river/out/ — same discovery as river/infer.py."""
    try:
        from river.infer import latest_checkpoint
        return latest_checkpoint()
    except Exception:
        pass
    out = _ROOT / "river" / "out"
    if not out.is_dir():
        return None, {}
    runs = sorted((d for d in out.iterdir()
                   if (d / "checkpoint.txt").is_file()),
                  key=lambda d: d.stat().st_mtime, reverse=True)
    if not runs:
        return None, {}
    ck = (runs[0] / "checkpoint.txt").read_text(encoding="utf-8").strip()
    meta = _load_json(runs[0] / "meta.json") or {}
    return (ck or meta.get("checkpoint")), meta


def _parse_brain_ingest(stdout: str) -> dict | None:
    """Pull the `ingested N findings -> M facts` line out of brain.py stdout."""
    m = re.search(r"ingested (\d+) findings -> (\d+) facts across (\d+) companies", stdout or "")
    if not m:
        return None
    backend = re.search(r"backend (\S+)\)", stdout or "")
    return {
        "findings": int(m.group(1)),
        "facts": int(m.group(2)),
        "companies": int(m.group(3)),
        "backend": backend.group(1) if backend else "?",
    }


def _recent_suites(n: int = 5) -> list[Path]:
    if not _SUITE_OUT.is_dir():
        return []
    return sorted(_SUITE_OUT.glob("*.md"),
                  key=lambda p: p.stat().st_mtime, reverse=True)[:n]


def _inline_scan() -> dict:
    """Small probe scan dict used by selftest/demo when demo/fixtures is absent."""
    return {
        "scope": "acme-corp.com",
        "generated": "2026-09-27 21:52 UTC",
        "probe": [{
            "host": "www.acme-corp.com",
            "findings": [{"type": "exposed_env_file", "severity": "CRITICAL",
                          "detail": "/.env on https://admin.acme-corp.com leaks "
                                    "DATABASE_URL=postgres://alice@db.internal:5432/app; "
                                    "contact security@acme-corp.com; origin 203.0.113.7"}],
        }],
        "findings": [
            {"type": "missing_csp", "severity": "MEDIUM",
             "location": "https://www.acme-corp.com",
             "detail": "CSP header absent on acme-corp.com marketing pages"},
            {"type": "stale_subdomain", "severity": "HIGH",
             "location": "https://status.acme-corp.com",
             "detail": "CNAME points to an unclaimed hosting endpoint"},
            {"type": "tls_cert_expiry", "severity": "LOW",
             "location": "https://api.acme-corp.com",
             "detail": "certificate expires in 9 days; auto-renew misconfigured"},
        ],
    }


def _demo_input() -> tuple[Path, str]:
    """(scan_path, company) — demo/fixtures first, else an inline scan in a tempdir."""
    fixtures_dir = _ROOT / "demo" / "fixtures"
    if fixtures_dir.is_dir():
        reports = sorted(fixtures_dir.glob("*/report.json"))
        if reports:
            return reports[0], reports[0].parent.name
    td = Path(tempfile.mkdtemp(prefix="company-selftest-"))
    scan = td / "report.json"
    scan.write_text(json.dumps(_inline_scan()), encoding="utf-8")
    return scan, "acme"


def _onboard(company: str, scan_path: str, name: str, max_rows: int,
             train: bool, echo: bool = False, train_default: bool = True) -> int:
    """Full pipeline: pairs -> (train) -> brain -> suite -> summary."""
    scan = Path(scan_path)
    if not scan.is_file():
        print(f"error: no such scan file: {scan}", file=sys.stderr)
        return _EXIT_USAGE

    scratch = _SCRATCH / company
    corpus = scratch / company
    corpus.mkdir(parents=True, exist_ok=True)
    pairs_path = scratch / "pairs.jsonl"
    manifest_path = scratch / "manifest.json"

    # STEP 1 — pairs: de-identify this company's scan into training pairs.
    print("STEP 1/5 — pairs (de-identify scan -> training pairs)")
    dest = corpus / "report.json"
    if scan.resolve() != dest.resolve():
        shutil.copy2(scan, dest)
    argv = [str(_ROOT / "data" / "build_pairs.py"),
            "--corpus", str(scratch), "--out", str(pairs_path),
            "--manifest", str(manifest_path),
            "--max-rows", str(max_rows)]
    # Stable per-company pseudonym (<company>.example) so onboard/update agree
    # and two companies never collide on target-001.example. Falls back to the
    # generated target when the display name doesn't slugify.
    slug = re.sub(r"[^a-z0-9]+", "-", company.lower()).strip("-")
    if slug:
        argv += ["--target-id", f"{slug}.example"]
    proc = _step("pairs", argv, echo)
    if proc.returncode != 0:
        print(f"error: pairs step failed (exit {proc.returncode})", file=sys.stderr)
        return _EXIT_STEP
    try:
        pairs, pseudonym = _read_pairs(pairs_path)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return _EXIT_STEP
    if not pairs or not pseudonym:
        print("error: pairs pipeline produced no training rows", file=sys.stderr)
        return _EXIT_STEP
    manifest = _load_json(manifest_path) or {}

    # STEP 2 — train: dry-run offline; live only with --train + RIVER_API_KEY.
    print("STEP 2/5 — train (dry-run offline; --train goes live via River)")
    train_mode = "dry-run"
    if train:
        if os.environ.get("RIVER_API_KEY"):
            proc = _step("train live", [str(_ROOT / "river" / "train.py"),
                                        "--pairs", str(pairs_path), "--live", "--name", name], echo)
            if proc.returncode == 0:
                train_mode = "live"
            else:
                print("note: live train failed — continuing with dry-run state "
                      "(infer/suite still discover any prior checkpoint)", file=sys.stderr)
        else:
            print("note: --train requested but RIVER_API_KEY is unset — "
                  "falling back to dry-run (no owned model yet)", file=sys.stderr)
    if train_mode != "live" and (train or train_default):
        _step("train dry-run", [str(_ROOT / "river" / "train.py"),
                                "--pairs", str(pairs_path), "--dry-run", "--name", name], echo)
    elif not train and not train_default:
        print("  (train skipped — use --train to train this company's LoRA)")

    # STEP 3 — brain: ingest the de-identified PAIRS, never the raw scan.
    print("STEP 3/5 — brain (ingest de-identified pairs -> GBrain memory)")
    proc = _step("brain ingest", [str(_ROOT / "memory" / "brain.py"), "ingest", str(pairs_path)], echo)
    if proc.returncode == _EXIT_REFUSE:
        print("error: brain REFUSED the de-identified input (exit 3) — nothing persisted", file=sys.stderr)
        return _EXIT_REFUSE
    if proc.returncode != 0:
        print(f"error: brain ingest failed (exit {proc.returncode})", file=sys.stderr)
        return _EXIT_STEP
    brain = _parse_brain_ingest(proc.stdout)

    # STEP 4 — suite: generate this company's custom security suite.
    print("STEP 4/5 — suite (generate per-company security suite)")
    proc = _step("suite", [str(_ROOT / "suite" / "build_suite.py"),
                           "--company", pseudonym, "--input", str(pairs_path),
                           "--out", str(_SUITE_OUT)], echo)
    if proc.returncode != 0:
        print(f"error: suite step failed (exit {proc.returncode})", file=sys.stderr)
        return _EXIT_STEP
    suite_path = _SUITE_OUT / f"{pseudonym}.md"

    # STEP 5 — summary.
    return _summary(company, pseudonym, pairs, manifest, train_mode, brain, suite_path, echo)


def _summary(company: str, pseudonym: str, pairs: list[dict], manifest: dict,
             train_mode: str, brain: dict | None, suite_path: Path, echo: bool) -> int:
    counts = manifest.get("counts", {}) or {}
    sev = counts.get("by_severity", {}) or {}
    sev_txt = ", ".join(f"{k}:{v}" for k, v in sev.items()) if sev else "n/a"
    ck, meta = _latest_checkpoint()
    if ck:
        ck_line = ck
        if meta.get("base_model"):
            ck_line += f" (base {meta['base_model']}, {meta.get('n_pairs', '?')} pairs)"
    elif train_mode == "live":
        ck_line = "live train ran but checkpoint not yet discoverable"
    else:
        ck_line = "none — dry-run (no owned model yet)"

    print("STEP 5/5 — summary")
    print(f"  company:   {company} (de-identified as {pseudonym})")
    print(f"  pairs:     {len(pairs)}  severity split: {sev_txt}")
    print(f"  checkpoint:{ck_line}")
    if brain:
        print(f"  brain:     ingested {brain['findings']} findings -> {brain['facts']} facts "
              f"(backend {brain['backend']})")
    else:
        print("  brain:     ingest line not parseable (see trace)")
    print(f"  suite:     {suite_path}")
    print("  commands:")
    print(f"    python3 company/run.py onboard --company {company} --scan report.json")
    print(f"    python3 company/run.py update  --company {company} --scan report.json")
    print(f"    python3 company/run.py infer   --company {company} "
          "--finding 'type: x; host: y; detail: z'")
    return 0


def _infer(args) -> int:
    """Paste a finding -> the owned checkpoint's severity (wraps river/infer.py)."""
    if args.company:
        print(f"company: {args.company}", file=sys.stderr)
    ck, meta = _latest_checkpoint()
    if not ck:
        print("no owned checkpoint in river/out/ — train one first "
              "(company/run.py onboard --train or river/train.py --live)", file=sys.stderr)
        return _EXIT_USAGE
    print(f"using owned checkpoint: {ck} "
          f"(base {meta.get('base_model') or 'default'}, auto-discovered from river/out/)",
          file=sys.stderr)
    argv = [str(_ROOT / "river" / "infer.py"), "--checkpoint", ck]
    if meta.get("base_model"):
        argv += ["--base-model", meta["base_model"]]
    if args.finding:
        argv += ["--finding", args.finding]
    elif args.file:
        argv += ["--file", args.file]
    proc = _run(argv)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def _status(company: str | None = None) -> int:
    print("=== company/run.py status ===")
    ck, meta = _latest_checkpoint()
    if ck:
        print(f"newest checkpoint: {ck}")
        print(f"  base_model: {meta.get('base_model', '?')}")
        print(f"  n_pairs:    {meta.get('n_pairs', '?')}")
    else:
        print("newest checkpoint: none (no owned model yet)")
    idx = _load_json(_BRAIN_INDEX) or {}
    companies = {k: v for k, v in idx.items() if k != "_meta"}
    print(f"brain index (memory/brain.json): {len(companies)} company/ies")
    if company:
        ent = idx.get(company) or idx.get(f"{re.sub(r'[^a-z0-9]+', '-', company.lower()).strip('-')}.example")
        print(f"  {company}: "
              f"{'not in brain index' if ent is None else f'{ent.get('facts', 0)} facts, {len(ent.get('findings', []))} findings'}")
    else:
        for c, ent in sorted(companies.items()):
            print(f"  {c}: {ent.get('facts', 0)} facts, {len(ent.get('findings', []))} findings")
    print("last suite files:")
    last = _recent_suites()
    if last:
        for p in last:
            print(f"  {p}")
    else:
        print("  none")
    print(f"gbrain on PATH: {shutil.which('gbrain') is not None}")
    return 0


def _selftest(echo: bool = True, label: str = "selftest") -> int:
    scan, company = _demo_input()
    source = "demo fixture" if (_ROOT / "demo" / "fixtures").is_dir() else "inline scan"
    print(f"{label}: onboarding {company} from {source} ({scan})")
    return _onboard(company, str(scan), f"{company}-model-v1",
                    _DEFAULT_MAX_ROWS, train=False, echo=echo)


def _demo() -> int:
    print(_DEMO_NARRATIVE)
    return _selftest(echo=True, label="demo")


def _parse(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="company/run.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    on = sub.add_parser("onboard", help="first onboarding: pairs -> train -> brain -> suite")
    on.add_argument("--company", required=True, help="display name, e.g. acme")
    on.add_argument("--scan", required=True, help="path to the probe scan report.json")
    on.add_argument("--train", action="store_true", help="live River training (needs RIVER_API_KEY)")
    on.add_argument("--name", default=None, help="checkpoint name (default <company>-model-v1)")
    on.add_argument("--max-rows", type=int, default=_DEFAULT_MAX_ROWS,
                    help="cap on emitted training pairs (default 300)")

    up = sub.add_parser("update", help="re-run memory + suite after a later scan")
    up.add_argument("--company", required=True)
    up.add_argument("--scan", required=True)
    up.add_argument("--train", action="store_true")

    inf = sub.add_parser("infer", help="paste a finding -> owned model severity")
    inf.add_argument("--finding", default=None, help="finding text inline")
    inf.add_argument("--file", default=None, help="read the finding from a file")
    inf.add_argument("--company", default=None, help="display-only header")

    st = sub.add_parser("status", help="checkpoint / brain / suite / gbrain availability")
    st.add_argument("--company", default=None, help="show only this company's brain entry")

    sub.add_parser("selftest", help="offline end-to-end check")
    sub.add_parser("demo", help="selftest with a HOW A COMPANY USES IT trace")

    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = _parse(argv)
    if args.command == "selftest":
        return _selftest(echo=True)
    if args.command == "demo":
        return _demo()
    if args.command == "onboard":
        return _onboard(args.company, args.scan, args.name or f"{args.company}-model-v1",
                        args.max_rows, args.train, echo=False, train_default=True)
    if args.command == "update":
        return _onboard(args.company, args.scan, f"{args.company}-model-v1",
                        _DEFAULT_MAX_ROWS, args.train, echo=False, train_default=False)
    if args.command == "infer":
        return _infer(args)
    if args.command == "status":
        return _status(args.company)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())