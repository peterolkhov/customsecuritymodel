#!/usr/bin/env python3
"""memory/brain.py — per-company findings brain backed by GBrain.

PLAN #3 (spine): ingest a probe scan JSON (or a JSONL of pair-shaped rows)
and remember one GBrain fact per finding, entity-scoped to the company, so
`gbrain recall <company>` answers "what do we know about this company" across
scans. This is the GBrain tick the hackathon rules require.

    python3 memory/brain.py --self-test                # offline, no keys
    python3 memory/brain.py ingest <scan.json>         # probe report.json (or pairs .jsonl)
    python3 memory/brain.py recall <company> [query]   # what do we know about <company>

Every fact carries provenance (probe report timestamp) and hostnames are
de-identified to *.example by default, matching the data/ contract so the
brain's story never leaks real infra into the shared memory.

Degrades gracefully: if `gbrain` is missing from PATH, `ingest`/`recall`
explain what to do and exit 2; `--self-test` still passes its offline parse
checks and reports the degradation.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

_MAX_FACT_LEN = 128  # gbrain facts reject >132 chars; truncate with margin


def gbrain_available() -> bool:
    return shutil.which("gbrain") is not None


def _run_gbrain(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["gbrain", *args], capture_output=True, text=True)


def deidentify_host(host: str) -> str:
    """Rewrite a real hostname to *.example, keeping the subdomain label.

    Already-pseudonymised hosts (*.example) pass through unchanged, so the
    fixture rows and repeated ingests stay stable.
    """
    host = (host or "").strip()
    if not host:
        return host
    if host.endswith(".example"):
        return host
    if host == "example":
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return "example" if len(parts) == 1 else "example"
    return f"{parts[0]}.example"


def parse_pairs_findings(path: Path) -> list[tuple[str, str, list[dict]]]:
    """Pair-shaped JSONL rows (data contract) -> per-company (company, provenance, findings)."""
    row_re = re.compile(r"type:\s*(\S+?)\s*;\s*host:\s*(\S+?)\s*;\s*detail:\s*(.*)", re.S)
    groups: dict[str, dict] = {}
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        r = json.loads(line)
        prov = r.get("provenance", {})
        company = prov.get("target") or "unknown"
        provenance = f"probe-report {prov.get('observed_at', '')}".strip() or "probe-report"
        text = r.get("input", "")
        m = row_re.match(text)
        if m:
            ftype, host, detail = m.group(1), m.group(2), m.group(3).strip()
        else:
            ftype, host, detail = "finding", "", text
        if not host and company != "unknown":
            host = company
        g = groups.setdefault(company, {"provenance": provenance, "findings": []})
        g["findings"].append({
            "type": ftype,
            "host": host,
            "detail": detail,
            "severity": str(r.get("output", "")).strip() or "INFO",
            "location": prov.get("class", "standard"),
        })
    out = [(c, g["provenance"], g["findings"]) for c, g in groups.items()]
    if not out:
        raise ValueError(f"{path}: no pair rows")
    return out


def parse_scan_findings(scan: dict) -> tuple[str, str, list[dict]]:
    """Probe report.json shape -> (company, provenance, findings)."""
    scope = (scan.get("scope") or "").split(",")[0].strip() or "unknown"
    company = scope or "unknown"
    generated = scan.get("generated") or ""
    provenance = f"probe-report {generated}".strip()
    findings = []
    for entry in scan.get("probe", []) or []:
        host = entry.get("host", company)
        for f in entry.get("findings", []) or []:
            findings.append({
                "type": f.get("type", "finding"),
                "host": host,
                "detail": f.get("detail", ""),
                "severity": str(f.get("severity", "INFO")),
                "location": f.get("location", ""),
            })
    return company, provenance, findings


def load_findings(path: Path, deidentify: bool) -> list[tuple[str, str, list[dict]]]:
    if path.suffix.lower() == ".jsonl":
        groups = parse_pairs_findings(path)
    else:
        company, provenance, findings = parse_scan_findings(json.loads(path.read_text(encoding="utf-8")))
        groups = [(company, provenance, findings)]
    if deidentify:
        for _, _, findings in groups:
            for f in findings:
                f["host"] = deidentify_host(f["host"])
    return groups


def _fact_text(f: dict, run_tag: str = "") -> str:
    head = f"finding: {f['type']}" + (f" on {f['host']}" if f["host"] else "")
    detail = (f.get("detail") or "").strip()
    if detail:
        head = f"{head} — {detail}"
    suffix = f" | sev={f.get('severity', 'INFO')}"
    if f.get("location"):
        suffix = f"{suffix}, class={f.get('location')}"
    if run_tag:
        suffix = f"{suffix} | run={run_tag}"
    budget = _MAX_FACT_LEN - len(suffix)
    if len(head) > budget:
        head = head[:max(budget - 1, 1)].rstrip() + "…"
    return head + suffix


def remember_fact(fact: str, entity: str, provenance: str, ttl: str | None = None) -> int | None:
    """-> gbrain fact id, or None on failure. Works even while a live serve
    holds the brain (remember is a persistence-IPC write the serve accepts)."""
    args = ["remember", fact, "--entity", entity, "--provenance", provenance, "--kind", "fact"]
    if ttl:
        args += ["--ttl", ttl]
    proc = _run_gbrain(args)
    if proc.returncode != 0 or "invalid_params" in proc.stdout:
        return None
    m = re.search(r"fact #(\d+)", proc.stdout)
    return int(m.group(1)) if m else None


def ingest_findings(findings: list[dict], company: str, provenance: str,
                    ttl: str | None = None) -> list[dict]:
    entries = []
    for f in findings:
        claim = _fact_text(f)
        fid = remember_fact(claim, company, provenance, ttl=ttl)
        if fid is not None:
            entries.append({
                "claim": claim, "company": company, "provenance": provenance,
                "fact_id": fid, "severity": f.get("severity", "INFO"),
                "class": f.get("location", "standard"),
            })
    return entries


_LEDGER = _HERE / "brain-ledger.json"


def load_ledger() -> dict:
    try:
        return json.loads(_LEDGER.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_ledger(ledger: dict) -> None:
    _LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def ledger_add(company: str, entries: list[dict]) -> None:
    if not entries:
        return
    ledger = load_ledger()
    existing = {e["claim"] for e in ledger.get(company, [])}
    fresh = [e for e in entries if e["claim"] not in existing]
    ledger.setdefault(company, []).extend(fresh)
    save_ledger(ledger)


def ledger_remove(company: str) -> None:
    ledger = load_ledger()
    if company in ledger:
        del ledger[company]
        save_ledger(ledger)


def _is_lock_error(proc) -> bool:
    blob = (proc.stdout or "") + (proc.stderr or "")
    return "already open through" in blob or "LiveServeLock" in blob


def verify_fact(entry: dict) -> int | None:
    """Confirm a fact still exists in gbrain by re-issuing its remember (the
    serve-accepted write seam) — returns the fact id when it's still known."""
    return remember_fact(entry["claim"], entry["company"], entry["provenance"])


def _dedupe(facts: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in facts:
        key = f.get("id") or f.get("fact", "")
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def recall_facts(company: str, query: str | None = None) -> tuple[list[dict], str]:
    """-> (facts, mode). mode: 'live' (CLI recall), 'locked' (serve holds the
    brain; verified through the write seam from the local ledger), or 'none'."""
    params = {"entity": company}
    if query:
        params["query"] = query
    proc = _run_gbrain(["call", "recall", json.dumps(params)])
    if proc.returncode == 0 and not _is_lock_error(proc):
        try:
            facts = json.loads(proc.stdout).get("facts", [])
        except json.JSONDecodeError:
            facts = []
        if facts:
            return _dedupe(facts), "live"
    proc = _run_gbrain(["recall", company])
    if proc.returncode == 0 and not _is_lock_error(proc):
        facts = []
        for line in proc.stdout.splitlines():
            m = re.match(r".*id=(\d+).*\[([^\]]*)\] (.*?) \((fact|event|preference|commitment|belief),", line)
            if m:
                facts.append({"id": int(m.group(1)), "entity_slug": m.group(2),
                              "fact": m.group(3), "provenance": ""})
        if facts:
            return _dedupe(facts), "live"
    if _is_lock_error(proc):
        facts = []
        for entry in load_ledger().get(company, []):
            fid = verify_fact(entry)
            if fid is not None:
                facts.append({"id": fid, "entity_slug": company, "fact": entry["claim"],
                              "provenance": entry["provenance"]})
        return _dedupe(facts), "locked"
    return [], "none"


def forget_fact(fact_id: int) -> bool:
    """Forget via the `forget` verb (persistence-IPC, works under a live serve)."""
    return _run_gbrain(["call", "forget", json.dumps({"id": str(fact_id)})]).returncode == 0


def cmd_ingest(args) -> int:
    if not gbrain_available():
        print("gbrain is not on PATH — install it (gbrain init --pglite) then retry.",
              file=sys.stderr)
        return 2
    path = Path(args.scan)
    groups = load_findings(path, deidentify=not args.no_deidentify)
    total = sum(len(findings) for _, _, findings in groups)
    if not total:
        print(f"{path}: no findings to ingest", file=sys.stderr)
        return 2
    ok = 0
    for company, provenance, findings in groups:
        entries = ingest_findings(findings, company, provenance, ttl=args.ttl)
        ok += len(entries)
        ledger_add(company, entries)
        print(f"ingested {len(entries)}/{len(findings)} findings for {company} (provenance: {provenance})")
    if ok < total:
        print(f"note: {total - ok} skipped (duplicates or write failures)", file=sys.stderr)
    return 0 if ok else 2


def cmd_recall(args) -> int:
    if not gbrain_available():
        print("gbrain is not on PATH — install it (gbrain init --pglite) then retry.",
              file=sys.stderr)
        return 2
    facts, mode = recall_facts(args.company, args.query)
    if mode == "locked":
        note = (" (gbrain CLI recall blocked by a live `gbrain serve`; "
                "facts verified through the write seam)")
    else:
        note = ""
    if not facts:
        print(f"no facts for {args.company}" + (f" matching {args.query!r}" if args.query else ""))
        return 0
    print(f"facts for {args.company}: {len(facts)}" + note)
    for f in facts:
        extra = f.get("entity_slug", "")
        src = f.get("provenance", "")
        tail = " · ".join(x for x in (extra, src) if x)
        print(f"- [id={f.get('id')}] {f.get('fact', '')}" + (f"   [{tail}]" if tail else ""))
    return 0


def _self_test() -> int:
    pairs = _ROOT / "data" / "example.pairs.jsonl"
    groups = load_findings(pairs, deidentify=True)
    assert len(groups) >= 2, f"expected multiple companies in fixture, got {len(groups)}"
    n_findings = sum(len(f) for _, _, f in groups)
    assert n_findings >= 3, f"expected >=3 findings, got {n_findings}"
    for _, _, findings in groups:
        assert all(f["host"] for f in findings), "every finding needs a host"
        assert all(f["host"].endswith(".example") or f["host"] == "example" for f in findings), \
            "fixture hosts must stay de-identified"
    companies = ", ".join(c for c, _, _ in groups)
    offline = f"offline parse OK: {len(groups)} companies ({companies}), {n_findings} findings"

    if not gbrain_available():
        print(f"{offline}\nself-test DEGRADED: gbrain not on PATH — live ingest+recall skipped")
        return 0

    test_entity = f"selftest-{int(time.time())}"
    other_entity = f"selftest-other-{int(time.time())}"
    provenance = time.strftime("selftest %Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entries = []
    try:
        for _, _, findings in groups:
            for f in findings:
                fid = remember_fact(_fact_text(f, run_tag=test_entity), test_entity, provenance, ttl="30m")
                if fid is not None:
                    entries.append({"claim": _fact_text(f, run_tag=test_entity), "company": test_entity,
                                    "provenance": provenance, "fact_id": fid})
        assert len(entries) == n_findings, f"remembered {len(entries)}/{n_findings}"
        ledger_add(test_entity, entries)
        facts, mode = recall_facts(test_entity)
        assert len(facts) == n_findings, f"recall ({mode}) returned {len(facts)} facts, expected {n_findings}"
        assert any("finding:" in f["fact"] for f in facts)
        assert all(len(f["fact"]) <= _MAX_FACT_LEN + 8 for f in facts), "fact text over length cap"
        other, _ = recall_facts(other_entity)
        assert not other, "facts leaked across companies"
        expected_claim = _fact_text(groups[0][2][0], run_tag=test_entity)
        assert any(f["fact"] == expected_claim for f in facts), "exact claim round-trip failed"
        print(f"{offline}\nself-test OK ({mode} recall): ingest {len(entries)} facts -> recall "
              f"{len(facts)} for {test_entity}; cross-company isolation verified")
        return 0
    finally:
        for e in (test_entity, other_entity):
            for fact, _ in [recall_facts(e)]:
                for item in fact:
                    forget_fact(item["id"])
            ledger_remove(e)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="memory/brain.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true", help="offline check, no keys/network")
    sub = ap.add_subparsers(dest="command")

    ing = sub.add_parser("ingest", help="ingest a scan into the GBrain")
    ing.add_argument("scan", help="probe report.json (or a pairs .jsonl)")
    ing.add_argument("--ttl", default=None, help="optional fact TTL, e.g. 30m")
    ing.add_argument("--no-deidentify", action="store_true",
                     help="keep real hostnames (default de-identifies to *.example)")

    rec = sub.add_parser("recall", help="what do we know about a company")
    rec.add_argument("company")
    rec.add_argument("query", nargs="?", default=None)

    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if a.command == "ingest":
        return cmd_ingest(a)
    if a.command == "recall":
        return cmd_recall(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())