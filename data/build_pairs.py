#!/usr/bin/env python3
"""data/build_pairs.py — probe findings -> training pairs (JSONL).

Turns the real probe corpus at ~/probe/out/*/report.json into the training
JSONL described in data/README.md, byte-identical in shape to
data/example.pairs.jsonl:

    {"task": "severity",
     "instruction": "Given this finding, assign a severity for THIS company's stack.",
     "input": "type: <type>; host: <host>.example; detail: <detail>",
     "output": "<SEVERITY>",
     "provenance": {"source": "probe-report", "target": "target-01.example",
                    "observed_at": "<iso>", "class": "standard"}}

* De-identifies hosts/IPs/emails/brands to *.example (target-NN.example for
  the report's own hosts, thirdparty-NN.example for anything else).
* Classifies each finding `standard` (the OWASP floor) vs `blind_spot`
  (stack-specific misses) with a keyword heuristic.
* Stamps `provenance.observed_at` from the report's `generated` field.
* Emits data/out/manifest.json with per-class counts — the "what it learned" slide.

    python3 data/build_pairs.py --help
    python3 data/build_pairs.py --dry-run           # manifest only, no jsonl
    python3 data/build_pairs.py                     # real build

If ~/probe/out is absent or empty it falls back to data/example.pairs.jsonl
and reports that in the manifest.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_OUT = _HERE / "out"
_PAIRS = _OUT / "pairs.jsonl"
_MANIFEST = _OUT / "manifest.json"
_FALLBACK = _HERE / "example.pairs.jsonl"
_DEFAULT_CORPUS = Path("~/probe/out").expanduser()

INSTRUCTION = "Given this finding, assign a severity for THIS company's stack."
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# stack-specific misses — the rows that justify a custom model (coordinator-approved list).
BLIND_SPOT_TOKENS = (
    "graphql_introspection", "exposed_env_file", "stale_subdomain", "csrf",
    "hardcoded_api_key", "spa_catchall", "verbose_error", "missing_csp",
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FQDN_RE = re.compile(r"(?<![A-Za-z0-9.\-])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}")
_HOST_FROM_LOC_RE = re.compile(r"(?:[a-z]+://)?([A-Za-z0-9.\-]+)")
_GENERATED_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalize_generated(raw) -> str:
    if not raw:
        return _now()
    m = _GENERATED_RE.search(str(raw))
    if m:
        y, mo, d, h, mi = m.groups()
        return f"{y}-{mo}-{d}T{h}:{mi}:00Z"
    return _now()


def _host_from_location(location) -> str | None:
    if not location:
        return None
    m = _HOST_FROM_LOC_RE.match(str(location).strip())
    if not m:
        return None
    host = m.group(1).lower()
    if host.endswith(".example") or host.startswith(("http", "www")):
        return host if host.endswith(".example") else None
    if "." in host:
        return host
    return None


def collect_findings(report: dict) -> list[dict]:
    """Flatten every finding section into a uniform list of candidate rows."""
    scope = (report.get("scope") or "unknown.example").lower()
    out = []

    def emit(host, finding, section):
        if not isinstance(finding, dict) or not finding.get("type"):
            return
        detail = str(finding.get("detail") or finding.get("why") or "").strip()
        out.append({
            "type": str(finding["type"]),
            "severity": str(finding.get("severity", "MEDIUM")).upper(),
            "host": host or scope,
            "section": section,
            "detail": detail,
        })

    hosts = {scope}
    for s in report.get("subdomains", []) or []:
        hosts.add(str(s.get("domain", "")).lower() or scope)
        for sub in (s.get("subdomains", []) or []):
            hosts.add(str(sub.get("subdomain", "")).lower())
    for p in report.get("probe", []) or []:
        hosts.add(str(p.get("host", "")).lower() or scope)
    for h in (report.get("deep", {}).get("hosts", []) or []):
        hosts.add(str(h.get("host", "")).lower())
    for inf in (report.get("deep", {}).get("infra", []) or []):
        hosts.add(str(inf.get("domain", "")).lower())
    for f in report.get("findings", []) or []:
        emit(_host_from_location(f.get("location")), f, "findings")
    for p in report.get("probe", []) or []:
        h = str(p.get("host", scope)).lower() or scope
        for f in (p.get("findings", []) or []):
            emit(h, f, "probe")
    for h in (report.get("deep", {}).get("hosts", []) or []):
        hh = str(h.get("host", scope)).lower() or scope
        for f in (h.get("findings", []) or []):
            emit(hh, f, "deep.hosts")
    for f in (report.get("deep", {}).get("findings", []) or []):
        emit(_host_from_location(f.get("location")), f, "deep.findings")
    for f in (report.get("repos", {}) or {}).get("findings", []) or []:
        emit(_host_from_location(f.get("location")), f, "repos")
    return out, sorted({h for h in hosts if h})


def classify(finding_type: str) -> str:
    t = finding_type.lower()
    return "blind_spot" if any(tok in t for tok in BLIND_SPOT_TOKENS) else "standard"


def make_host_map(scope: str, hosts: set[str]) -> dict[str, str]:
    """scope -> target-01.example; scope subdomains keep their label;
    anything else -> target-NN.example."""
    mapping = {}
    counter = [2]
    scope = scope.lower().rstrip(".")
    for h in sorted(hosts, key=lambda x: (-len(x), x)):
        h = h.lower().rstrip(".")
        if not h:
            continue
        if h == scope:
            mapping[h] = "target-01.example"
        elif h.endswith("." + scope):
            label = h[: -(len(scope) + 1)]
            mapping[h] = f"{label}.target-01.example"
        else:
            mapping[h] = f"target-{counter[0]:02d}.example"
            counter[0] += 1
    return mapping


class Deident:
    """Deterministic *.example scrubbing with per-run counters."""

    def __init__(self):
        self.ips: dict[str, str] = {}
        self.thirdparty: dict[str, str] = {}
        self.n_emails = 0
        self.n_brands = 0

    def scrub(self, text: str, host_map: dict[str, str], brand_token: str | None) -> str:
        if not text:
            return text
        for host in sorted(host_map, key=lambda x: -len(x)):
            pat = r"(?<![a-zA-Z0-9._\-])" + re.escape(host) + r"(?![a-zA-Z0-9._\-])"
            text = re.sub(pat, host_map[host], text)
        if brand_token:
            pat = r"(?<![a-zA-Z0-9._\-])" + re.escape(brand_token) + r"(?![a-zA-Z0-9])"
            new, n = re.subn(pat, "brand.example", text)
            text, self.n_brands = new, self.n_brands + n

        def fqdn(m):
            h = m.group(0).lower()
            if h.endswith(".example"):
                return m.group(0)
            return self.thirdparty.setdefault(h, f"thirdparty-{len(self.thirdparty) + 1:02d}.example")

        text = _FQDN_RE.sub(fqdn, text)
        text = _IPV4_RE.sub(lambda m: self.ips.setdefault(m.group(0), f"198.51.100.{len(self.ips) + 1}"), text)
        text, self.n_emails = _EMAIL_RE.subn("user@example.com", text)
        return text


def brand_token_from_scope(scope: str) -> str | None:
    scope = scope.lower().strip().rstrip(".")
    if not scope or "." not in scope:
        return None
    labels = scope.split(".")
    root = labels[-2] if len(labels) >= 2 else labels[0]
    root = root.replace("-", "")
    return root if len(root) >= 3 else None


def iter_reports(corpus_dir: Path):
    if not corpus_dir.is_dir():
        return
    for sub in sorted(corpus_dir.iterdir()):
        rp = sub / "report.json"
        if not rp.is_file():
            continue
        try:
            yield rp, json.loads(rp.read_text(encoding="utf-8"))
        except Exception:
            continue


def build(corpus_dir: Path, out_path: Path, manifest_path: Path,
          max_rows: int, dry_run: bool, seed: int = 20260927) -> int:
    rng = random.Random(seed)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if corpus_dir.is_dir() and any(corpus_dir.iterdir()):
        corpus_kind = "probe-report"
        reports = companies = findings_seen = 0
        candidates: list[dict] = []
        seen = set()
        for rp, report in iter_reports(corpus_dir):
            reports += 1
            if report.get("scope"):
                companies += 1
            findings, hosts = collect_findings(report)
            if not findings:
                continue
            scope = (report.get("scope") or "unknown.example").lower().rstrip(".")
            target = "target-01.example"
            host_map = make_host_map(scope, hosts)
            observed_at = _normalize_generated(report.get("generated"))
            for f in findings:
                findings_seen += 1
                host = (f["host"] or scope).lower().rstrip(".")
                host_map.setdefault(host, f"target-{len(host_map) + 1:02d}.example")
                mapped_host = host_map.get(host, target)
                cls = classify(f["type"])
                dedup = (target, f["type"], f["detail"][:200])
                if dedup in seen:
                    continue
                seen.add(dedup)
                candidates.append({
                    "target": target, "host": mapped_host, "cls": cls,
                    "type": f["type"], "severity": f["severity"],
                    "detail": f["detail"], "observed_at": observed_at,
                    "brand": brand_token_from_scope(scope),
                    "host_map": host_map, "section": f["section"],
                })
        # stratified, type-diverse sample capped at max_rows
        by_class = {"standard": [], "blind_spot": []}
        for c in candidates:
            by_class[c["cls"]].append(c)
        selected = []
        for cls in ("standard", "blind_spot"):
            pool = by_class[cls]
            rng.shuffle(pool)
            per_type: dict[str, list] = {}
            for c in pool:
                per_type.setdefault(c["type"], []).append(c)
            types = list(per_type.keys())
            rng.shuffle(types)
            row_budget = max_rows // 2 if max_rows else len(pool)
            for t in types:  # one of each type first — diversity for the demo
                if row_budget <= 0:
                    break
                if per_type[t]:
                    selected.append(per_type[t].pop(0))
                    row_budget -= 1
            types = [t for t in types if per_type[t]]
            i = 0
            while row_budget > 0 and types:
                t = types[i % len(types)]
                if per_type[t]:
                    selected.append(per_type[t].pop(0))
                    row_budget -= 1
                    if not per_type[t]:
                        types.remove(t)
                        i = i % (len(types) or 1)
                i += 1
                if i > 10_000:
                    break
        corpus_info = {"kind": corpus_kind, "path": str(corpus_dir),
                       "reports_scanned": reports, "companies": companies,
                       "findings_seen": findings_seen, "dedup_candidates": len(candidates)}
    else:
        # Fallback: fixture corpus — pass rows through, restamp provenance.
        corpus_kind = "fallback"
        corpus_info = {"kind": corpus_kind, "path": str(_FALLBACK),
                       "reports_scanned": 0, "companies": 1,
                       "findings_seen": 0, "dedup_candidates": 0}
        selected = []
        for line in _FALLBACK.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            selected.append(r)

    deid = Deident()
    rows = []
    for c in selected:
        if isinstance(c, dict) and "host_map" in c:
            detail = deid.scrub(c["detail"], c["host_map"], c["brand"])
            if len(detail) > 280:
                detail = detail[:280].rstrip() + "..."
            row = {
                "task": "severity",
                "instruction": INSTRUCTION,
                "input": f"type: {c['type']}; host: {c['host']}; detail: {detail}",
                "output": c["severity"] if c["severity"] in SEVERITIES else "MEDIUM",
                "provenance": {"source": "probe-report", "target": c["target"],
                               "observed_at": c["observed_at"], "class": c["cls"]},
            }
        else:  # fallback rows already in contract
            row = c
        rows.append(row)

    if not dry_run and rows:
        with out_path.open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

    counts = {"total": len(rows)}
    by_class = {"standard": 0, "blind_spot": 0}
    by_sev = {s: 0 for s in SEVERITIES}
    class_types = {"standard": [], "blind_spot": []}
    for r in rows:
        cls = r["provenance"].get("class", "standard")
        by_class[cls] = by_class.get(cls, 0) + 1
        sev = r["output"]
        if sev in by_sev:
            by_sev[sev] += 1
        t = r["input"].split(";")[0].replace("type:", "").strip()
        if t and t not in class_types[cls]:
            class_types[cls].append(t)
    counts["by_class"] = by_class
    counts["by_severity"] = by_sev
    counts["distinct_types_per_class"] = {k: sorted(v) for k, v in class_types.items()}

    manifest = {
        "adapter": "data/build_pairs.py", "built_at": _now(), "dry_run": bool(dry_run),
        "max_rows": max_rows, "out_file": str(out_path) if not dry_run else None,
        "corpus": corpus_info, "counts": counts,
        "deidentified": {"hosts_mapped": len(deid.thirdparty) + 0,
                         "thirdparty_hosts": len(deid.thirdparty),
                         "ips_mapped": len(deid.ips),
                         "emails_replaced": deid.n_emails,
                         "brands_replaced": deid.n_brands},
        "sample": rows[:3] if rows else [],
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(f"corpus: {corpus_kind} ({corpus_dir})")
    print(f"rows: {len(rows)}  standard={by_class['standard']}  blind_spot={by_class['blind_spot']}")
    print(f"severities: {by_sev}")
    print(f"manifest: {manifest_path}")
    if not dry_run and rows:
        print(f"pairs: {out_path}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="data/build_pairs.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=str(_DEFAULT_CORPUS),
                    help="probe report corpus dir (default ~/probe/out)")
    ap.add_argument("--out", default=str(_PAIRS), help="output JSONL (default data/out/pairs.jsonl)")
    ap.add_argument("--manifest", default=str(_MANIFEST), help="manifest JSON (default data/out/manifest.json)")
    ap.add_argument("--max-rows", type=int, default=300,
                    help="cap on emitted pairs (0 = unlimited; default 300)")
    ap.add_argument("--dry-run", action="store_true", help="emit manifest only, no pairs JSONL")
    ap.add_argument("--seed", type=int, default=20260927)
    a = ap.parse_args(argv)
    return build(Path(a.corpus), Path(a.out), Path(a.manifest), a.max_rows, a.dry_run, a.seed)


if __name__ == "__main__":
    raise SystemExit(main())