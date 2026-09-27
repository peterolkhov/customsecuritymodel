#!/usr/bin/env python3
"""suite/build_suite.py — per-company suite generator.

Reads the company's owned model (river/out/<ts>/meta.json) + the company's
GBrain memory (memory/brain.json when present) and the findings pairs
(`--input`, e.g. data/example.pairs.jsonl) and emits a per-company security
suite:

    python3 suite/build_suite.py --company target-01.example \
        --input data/example.pairs.jsonl

The multiplayer claim: every company gets a DIFFERENT suite, generated not
hand-tuned. `--company` selects the findings that make that company's suite
distinct; the standard floor is the shared pool, blind spots are the
stack-specific rows that justify a custom model.

Output: suite/<company>.md with N standard checks + M blind spots, each
ranked by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO). Offline by
default — if no checkpoint exists yet, severities are the gold/fixture
labels; when river/out/<ts>/meta.json lands, the ranking is attributed to
the owned model checkpoint.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_DEFAULT_INPUT = _ROOT / "data" / "example.pairs.jsonl"
_OUT = _HERE                       # suite/ itself
_BRAIN_JSON = _ROOT / "memory" / "brain.json"

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITIES = sorted(SEVERITY_RANK, key=SEVERITY_RANK.get, reverse=True)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_pairs(path: Path) -> list[dict]:
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        r = json.loads(line)
        for k in ("input", "output"):
            if k not in r:
                raise ValueError(f"{path}:{i + 1} missing {k!r}")
        rows.append(r)
    if not rows:
        raise ValueError(f"{path}: no pairs")
    return rows


def parse_finding(pair: dict) -> dict:
    """Extract a displayable finding from one pairs row.

    The `input` is "<key>: <value>; ..." (see data/README.md); fall back to
    the raw input text when a field can't be parsed so the fixture and any
    future adapter format both work.
    """
    prov = pair.get("provenance", {}) or {}
    text = pair["input"].strip()
    fields = {}
    for part in text.split(";"):
        part = part.strip()
        if ":" in part:
            k, v = part.split(":", 1)
            fields[k.strip().lower()] = v.strip()
    return {
        "type": fields.get("type") or pair.get("type") or "finding",
        "host": fields.get("host") or prov.get("target") or "*.example",
        "detail": fields.get("detail") or text,
        "severity": (pair.get("output") or "LOW").strip().upper(),
        "class": prov.get("class", "standard"),
        "target": prov.get("target"),
        "observed_at": prov.get("observed_at"),
    }


def latest_model() -> dict | None:
    """Newest river/out/<ts>/meta.json, or None when no checkpoint exists yet.

    checkpoint.txt is the source of truth for the river:// URI; meta.json
    carries the base model / n_pairs provenance. Same discovery river/infer.py
    uses, so the suite generator and the infer CLI always agree on the owned model.
    """
    out = _ROOT / "river" / "out"
    runs = sorted(out.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for run_dir in runs:
        if not run_dir.is_dir():
            continue
        meta: dict = {}
        ck = None
        cp = run_dir / "checkpoint.txt"
        if cp.is_file():
            ck = cp.read_text(encoding="utf-8").strip()
        mp = run_dir / "meta.json"
        if mp.is_file():
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
            except Exception:
                meta = {}
        ck = ck or meta.get("checkpoint")
        if not ck:
            continue
        meta["checkpoint"] = ck
        return meta
    return None


def load_brain() -> dict | None:
    if not _BRAIN_JSON.exists():
        return None
    try:
        brain = json.loads(_BRAIN_JSON.read_text(encoding="utf-8"))
    except Exception:
        return None
    return brain if isinstance(brain, dict) else None


def rank_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(f["severity"], -1), f["type"].lower()),
        reverse=True,
    )


def build_suite(company: str, findings: list[dict], n_standard: int, n_blind: int,
                model: dict | None, brain: dict | None) -> str:
    standard_all = rank_findings([f for f in findings if f["class"] == "standard"])
    blind_all = rank_findings([f for f in findings if f["class"] == "blind_spot"])

    own_standard = [f for f in standard_all if f["target"] == company]
    others_standard = [f for f in standard_all if f["target"] != company]
    own_blind = [f for f in blind_all if f["target"] == company]

    standard = own_standard + others_standard
    standard = standard[:n_standard]
    blind = own_blind[:n_blind]

    n_seen = len(findings)
    n_own = len(own_standard) + len(own_blind)

    L = [f"# Security suite — {company}", ""]
    L.append(f"> Generated {_now()} by suite/build_suite.py (offline, no keys). "
             f"Every company gets a different suite — generated from its own findings, not hand-tuned.")
    L.append("")

    if model:
        L.append(f"**Owned model:** {model.get('checkpoint')} "
                 f"(base {model.get('base_model', '?')}, {model.get('n_pairs', '?')} pairs)")
        L.append("Severity rankings below are attributed to this checkpoint.")
    else:
        L.append("**Owned model:** none yet — severity rankings are the gold/fixture labels. "
                 "Train a checkpoint (river/train.py --live) to personalize.")
    L.append(f"**Findings seen:** {n_seen} ({n_own} for this company, "
             f"{len(standard_all)} standard / {len(blind_all)} blind_spot total).")
    L.append("")

    L.append(f"## Standard checks ({len(standard)} of {n_standard} target)")
    L.append("The OWASP-style floor — every company's suite checks these.")
    L.append("")
    if standard:
        for i, f in enumerate(standard, 1):
            own = " (this company)" if f["target"] == company else " (shared floor)"
            L.append(f"{i}. **{f['severity']} — {f['type']}**{own}")
            L.append(f"   - host: `{f['host']}`")
            L.append(f"   - detail: {f['detail']}")
            if f.get("observed_at"):
                L.append(f"   - observed: {f['observed_at']}")
            L.append("")
    else:
        L.append("_No standard findings yet — run a scan._")
        L.append("")

    L.append(f"## Blind spots ({len(blind)} of {n_blind} target)")
    L.append("Stack-specific things teams miss — the rows that justify a custom model.")
    L.append("")
    if blind:
        for i, f in enumerate(blind, 1):
            L.append(f"{i}. **{f['severity']} — {f['type']}**")
            L.append(f"   - host: `{f['host']}`")
            L.append(f"   - detail: {f['detail']}")
            if f.get("observed_at"):
                L.append(f"   - observed: {f['observed_at']}")
            L.append("")
    else:
        L.append("_No blind spots observed for this company yet._")
        L.append("The owned model will flag stack-specific misses as scans compound "
                 "into the GBrain memory (second-scan beat).")
        L.append("")

    L.append("## Memory (GBrain)")
    if brain is not None:
        if company in brain:
            comp = brain[company]
            if isinstance(comp, dict):
                for k, v in comp.items():
                    if isinstance(v, (list, dict)):
                        L.append(f"- {k}: {json.dumps(v, default=str)}")
                    else:
                        L.append(f"- {k}: {v}")
            else:
                L.append(f"- {comp}")
        else:
            L.append(f"_Brain index present but no entry for {company} yet._")
    else:
        L.append("_No GBrain index yet (memory/brain.json). The suite compounds once the "
                 "findings brain lands: recall across scans instead of resetting each run._")
    L.append("")

    L.append("## How to read this suite")
    L.append(f"- Run the standard checks first — the floor applies to everyone.")
    L.append(f"- Spend budget on the top blind spots: severity is ranked "
             f"{', '.join(SEVERITIES)}.")
    L.append(f"- Re-run `suite/build_suite.py --company {company} --input ...` after each "
             f"scan to regenerate.")
    L.append("")
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="suite/build_suite.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--company", required=True, help="company id, e.g. target-01.example")
    ap.add_argument("--input", default=str(_DEFAULT_INPUT),
                    help="findings JSONL (pairs contract, see data/README.md)")
    ap.add_argument("--standard-count", type=int, default=5, dest="n_standard",
                    help="N standard checks to emit (capped at the shared pool)")
    ap.add_argument("--blind-spot-count", type=int, default=5, dest="n_blind",
                    help="M blind spots to emit (capped at the company's own)")
    ap.add_argument("--out", default=str(_OUT), help="output directory (default: suite/)")
    a = ap.parse_args(argv)

    findings = [parse_finding(p) for p in load_pairs(Path(a.input))]
    model = latest_model()
    brain = load_brain()
    md = build_suite(a.company, findings, a.n_standard, a.n_blind, model, brain)

    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{a.company}.md"
    out_path.write_text(md, encoding="utf-8")
    print(f"wrote {out_path} ({len(findings)} findings, "
          f"model={'yes' if model else 'none'}, brain={'yes' if brain is not None else 'none'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())