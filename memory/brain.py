#!/usr/bin/env python3
"""memory/brain.py — per-company findings brain backed by GBrain (PLAN #3 spine).

The rules-required GBrain module: ingest a probe scan report.json (or a JSONL
of pairs-contract rows) and sync every de-identified finding into GBrain under
a three-part entity ontology so `recall <company>` answers "what do we know
about this company" across scans:

    targets/<pseudonym>   the company rollup (one event fact per finding)
    findings/<type>       the cross-company per-type rollup (one event per sighting)
    runs/<run_id>         the per-run provenance summary (one event per scan)

    python3 memory/brain.py --self-test                 # offline, zero keys/network
    python3 memory/brain.py ingest <scan.json>          # probe report.json or pairs .jsonl
    python3 memory/brain.py recall <company> [query]    # what do we know about <company>
    python3 memory/brain.py recall --entity findings/<type>
    python3 memory/brain.py recall --entity runs/<run_id>
    python3 memory/brain.py status                      # backend + local-store health

De-identification reuses data/build_pairs.py (the pairs-contract scrubber):
hosts -> *.example, IPs -> 198.51.100.x, emails -> user@example.com, brand
tokens -> brand.example. After scrubbing every field the module REFUSES to
write (exit 3, nothing persisted) if a real-looking domain, email, or
non-documentation IP survives the scrub — the same guard gbrain_sync uses, so
the shared brain can never be asked to hold real infra.

Backends, in order of preference:
  1. live GBrain (gbrain on PATH, `gbrain recall <entity> --json` works)
  2. local JSONL mirror (memory/brain-local.jsonl) — used whenever gbrain is
     absent from PATH OR the PGLite brain is held by a live `gbrain serve`
     (reads lock; writes still land). memory/brain.json is a plain index the
     suite generator (suite/build_suite.py) already knows how to read.

Verified on gbrain 0.59.0.0: `gbrain remember '<text>' --entity <e> --kind
event --provenance <p>` (provenance REQUIRED; kind must be one of event |
preference | commitment | belief | fact — `runlog` is invalid); `gbrain recall
<entity>` is positional and `--json` returns structured facts; `gbrain forget
<id>` and `remember` both work while a live serve holds the brain (writes are
persistence-IPC), while plain `recall` reads lock.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from data.build_pairs import (  # noqa: E402  — the pairs-contract de-identification
    Deident,
    _normalize_generated,
    brand_token_from_scope,
    collect_findings,
    make_host_map,
)

_VALID_KINDS = ("event", "preference", "commitment", "belief", "fact")
_DEFAULT_KIND = "event"
_MAX_FACT_LEN = 260
_EXIT_REFUSE = 3

_LOCAL_STORE = _HERE / "brain-local.jsonl"
_INDEX = _HERE / "brain.json"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FQDN_RE = re.compile(r"(?<![A-Za-z0-9.\-])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}")

_DOC_IPV4 = ("192.0.2.", "198.51.100.", "203.0.113.", "198.18.", "198.19.", "127.0.0.")
_RESERVED_SUFFIXES = (".example", ".invalid", ".test", ".localhost")
_RESERVED_EXACT = ("example.com", "example.net", "example.org", "example.edu")
_SAFE_EMAIL_DOMAIN = "example.com"

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def gbrain_available() -> bool:
    return shutil.which("gbrain") is not None


def run_gbrain(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["gbrain", *args], capture_output=True, text=True)


def _is_lock_error(proc) -> bool:
    blob = (proc.stdout or "") + (proc.stderr or "")
    return "already open through" in blob or "LiveServeLock" in blob


def canonical_entity(raw: str) -> str:
    """Mirror gbrain's per-segment slugify so local-store matching and the
    live entity agree (targets/target-01.example -> targets/target-01-example)."""
    return "/".join(seg for seg in (re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")) for s in raw.split("/")) if seg)


def entity_is_slug(raw: str) -> bool:
    return raw.startswith("targets/") or raw.startswith("findings/") or raw.startswith("runs/")


def company_entity(company: str) -> str:
    return f"targets/{canonical_entity(company)}"


def finding_entity(ftype: str) -> str:
    return f"findings/{canonical_entity(ftype)}"


def run_entity(run_id: str) -> str:
    return f"runs/{canonical_entity(run_id)}"


def safe_domain(token: str) -> bool:
    t = token.lower().rstrip(".")
    if t == "example" or t == "localhost":
        return True
    if t in _RESERVED_EXACT:
        return True
    return t.endswith(_RESERVED_SUFFIXES)


def safe_email(token: str) -> bool:
    return token.lower().endswith(f"@{_SAFE_EMAIL_DOMAIN}")


def safe_ipv4(token: str) -> bool:
    return any(token.startswith(p) for p in _DOC_IPV4)


def guard_violations(text: str) -> list[str]:
    """Return a list of real-looking identifiers that survived de-identification."""
    bad: list[str] = []
    for m in _FQDN_RE.finditer(text or ""):
        if not safe_domain(m.group(0)):
            bad.append(f"domain {m.group(0)!r}")
    for m in _EMAIL_RE.finditer(text or ""):
        if not safe_email(m.group(0)):
            bad.append(f"email {m.group(0)!r}")
    for m in _IPV4_RE.finditer(text or ""):
        if not safe_ipv4(m.group(0)):
            bad.append(f"ip {m.group(0)!r}")
    return sorted(set(bad))


def scrub_text(text: str, host_map: dict[str, str], brand: str | None, deid: Deident) -> str:
    return deid.scrub(text, host_map, brand)


def _clip(s: str, budget: int) -> str:
    s = s.strip()
    if len(s) <= budget:
        return s
    return s[:max(budget - 3, 0)].rstrip() + "..."


def finding_fact(ftype: str, host: str, detail: str, severity: str, cls: str, run_id: str) -> str:
    head = f"finding: {ftype} on {host}"
    if detail:
        head = f"{head} — {detail}"
    suffix = f" | sev={severity}, class={cls}, run={run_id}"
    return _clip(head, _MAX_FACT_LEN - len(suffix)) + suffix


def run_fact(run_id: str, company: str, observed_at: str, findings: list[dict]) -> str:
    n = len(findings)
    std = sum(1 for f in findings if (f.get("class") or "standard") == "standard")
    blind = n - std
    sevs = ", ".join(f"{s}:{sum(1 for f in findings if f.get('severity') == s)}" for s in _SEV_ORDER)
    body = f"run {run_id}: scanned {company} at {observed_at} — {n} findings (standard {std}, blind_spot {blind})"
    return _clip(f"{body}; sev {sevs}", _MAX_FACT_LEN)


def type_fact(ftype: str, company: str, severity: str, cls: str, run_id: str, count: int) -> str:
    n = f" (x{count})" if count > 1 else ""
    return _clip(f"{ftype} sighting on {company}{n} | sev={severity}, class={cls}, run={run_id}", _MAX_FACT_LEN)


class LocalStore:
    """Append-only JSONL mirror of every fact the brain has been asked to hold."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else _LOCAL_STORE

    def append(self, records: list[dict]) -> None:
        if not records:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existing = {(r.get("entity"), r.get("fact")) for r in self.load()}
        fresh = []
        for r in records:
            key = (r.get("entity"), r.get("fact"))
            if key in existing:
                continue
            existing.add(key)
            fresh.append(r)
        with self.path.open("a", encoding="utf-8") as f:
            for r in fresh:
                f.write(json.dumps(r, sort_keys=True) + "\n")

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        rows = []
        for i, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows

    def recall(self, entity: str, company: str | None = None) -> list[dict]:
        rows = []
        seen = set()
        entity = canonical_entity(entity)
        comp_canon = canonical_entity(company) if company else None
        for r in self.load():
            if canonical_entity(r.get("entity", "")) != entity:
                continue
            if comp_canon and canonical_entity(r.get("company", "")) != comp_canon:
                continue
            key = r.get("fact", "")
            if key in seen:
                continue
            seen.add(key)
            rows.append(r)
        return rows

    def drop_entity(self, entity: str) -> None:
        if not self.path.exists():
            return
        rows = [r for r in self.load() if canonical_entity(r.get("entity", "")) != canonical_entity(entity)]
        self.path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + ("\n" if rows else ""), encoding="utf-8")


def load_index() -> dict:
    try:
        return json.loads(_INDEX.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_index(idx: dict) -> None:
    _INDEX.write_text(json.dumps(idx, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def remember(text: str, entity: str, provenance: str, kind: str, ttl: str | None = None) -> tuple[int | None, subprocess.CompletedProcess | None]:
    if kind not in _VALID_KINDS:
        raise ValueError(f"invalid --kind {kind!r} (valid: {', '.join(_VALID_KINDS)})")
    args = ["remember", text, "--entity", entity, "--kind", kind, "--provenance", provenance]
    if ttl:
        args += ["--ttl", ttl]
    proc = run_gbrain(args)
    if proc.returncode != 0 or "invalid_params" in proc.stdout or "invalid_params" in proc.stderr:
        return None, proc
    m = re.search(r"fact #(\d+)", proc.stdout)
    return (int(m.group(1)) if m else None), proc


def forget(fact_id: int) -> bool:
    return run_gbrain(["forget", str(fact_id)]).returncode == 0


def parse_pairs(path: Path) -> list[dict]:
    """Pairs-contract rows -> normalized finding dicts (input already de-identified)."""
    row_re = re.compile(r"type:\s*(\S+?)\s*;\s*host:\s*(\S+?)\s*;\s*detail:\s*(.*)", re.S)
    out: list[dict] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        r = json.loads(line)
        prov = r.get("provenance", {}) or {}
        company = (prov.get("target") or "unknown").strip().rstrip("/")
        m = row_re.match(str(r.get("input", "")))
        if m:
            ftype, host, detail = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        else:
            ftype, host, detail = "finding", company, str(r.get("input", ""))
        out.append({
            "company": company,
            "type": ftype,
            "host": host or company,
            "detail": detail,
            "severity": str(r.get("output", "")).strip().upper() or "INFO",
            "class": prov.get("class", "standard"),
            "observed_at": prov.get("observed_at") or _now(),
            "scan": prov.get("source", "pairs-jsonl"),
        })
    if not out:
        raise ValueError(f"{path}: no pair rows")
    return out


def parse_scan(path: Path) -> list[dict]:
    report = json.loads(path.read_text(encoding="utf-8"))
    scope = (report.get("scope") or "").split(",")[0].strip() or "unknown"
    findings, hosts = collect_findings(report)
    if not findings:
        raise ValueError(f"{path}: no findings")
    observed_at = _normalize_generated(report.get("generated"))
    host_map = make_host_map(scope, hosts)
    brand = brand_token_from_scope(scope)
    out = []
    for f in findings:
        raw_host = (f.get("host") or scope).lower().rstrip(".")
        if raw_host not in host_map:
            host_map[raw_host] = f"target-{len(host_map) + 1:02d}.example"
        out.append({
            "company": host_map.get(scope.lower().rstrip("."), "target-01.example"),
            "type": str(f["type"]),
            "host": host_map[raw_host],
            "detail": str(f.get("detail") or ""),
            "severity": str(f.get("severity", "MEDIUM")).upper(),
            "class": "blind_spot" if any(tok in str(f["type"]).lower() for tok in (
                "graphql_introspection", "exposed_env_file", "stale_subdomain", "csrf",
                "hardcoded_api_key", "spa_catchall", "verbose_error", "missing_csp",
            )) else "standard",
            "observed_at": observed_at,
            "scan": "probe-report",
            "_host_map": host_map,
            "_brand": brand,
        })
    return out


def load_findings(path: Path, deidentify: bool) -> list[dict]:
    findings = parse_scan(path) if path.suffix.lower() != ".jsonl" else parse_pairs(path)
    if not deidentify:
        return findings
    for f in findings:
        host_map = f.pop("_host_map", {})
        brand = f.pop("_brand", None)
        deid = Deident()
        f["host"] = scrub_text(f["host"], host_map, brand, deid)
        f["detail"] = scrub_text(f["detail"], host_map, brand, deid)
    return findings


def derive_run_id(findings: list[dict]) -> str:
    observed = next((f["observed_at"] for f in findings if f.get("observed_at")), _now())
    stamp = re.sub(r"[^0-9TZ]", "", observed)[:15]
    return f"run-{stamp}" if stamp else f"run-{int(time.time())}"


def _check_findings(findings: list[dict]) -> list[str]:
    bad: list[str] = []
    for f in findings:
        for field in ("host", "detail"):
            bad.extend(guard_violations(f.get(field, "")))
    return sorted(set(bad))


def build_records(findings: list[dict], run_id: str, provenance: str, kind: str) -> list[dict]:
    records: list[dict] = []
    company = findings[0]["company"]
    buckets: dict[tuple, list[dict]] = {}
    for f in findings:
        buckets.setdefault((f["type"], f["severity"], f["class"]), []).append(f)
    for f in findings:
        fact = finding_fact(f["type"], f["host"], f["detail"], f["severity"], f["class"], run_id)
        base = {
            "written_at": _now(), "kind": kind, "provenance": provenance,
            "run_id": run_id, "company": company,
            "type": f["type"], "severity": f["severity"], "class": f["class"],
            "observed_at": f["observed_at"], "scan": f["scan"],
        }
        records.append({**base, "entity": company_entity(company), "fact": fact})
    for (ftype, severity, cls), group in sorted(buckets.items()):
        tfact = type_fact(ftype, company, severity, cls, run_id, len(group))
        records.append({
            "written_at": _now(), "kind": kind, "provenance": provenance,
            "run_id": run_id, "company": company, "type": ftype, "severity": severity,
            "class": cls, "observed_at": findings[0]["observed_at"], "scan": findings[0]["scan"],
            "entity": finding_entity(ftype), "fact": tfact,
        })
    rfact = run_fact(run_id, company, findings[0]["observed_at"], findings)
    records.append({
        "written_at": _now(), "kind": kind, "provenance": provenance,
        "run_id": run_id, "company": company, "type": "run_summary",
        "severity": "", "class": "run", "observed_at": findings[0]["observed_at"],
        "scan": findings[0]["scan"], "entity": run_entity(run_id), "fact": rfact,
    })
    return records


def sync_to_gbrain(records: list[dict], ttl: str | None, workers: int = 8) -> dict:
    """Write every record to gbrain (parallel; each remember is a separate
    gbrain process). Returns remembered/skipped bookkeeping."""
    def one(r: dict) -> bool:
        fid, _proc = remember(r["fact"], r["entity"], r["provenance"], r["kind"], ttl=ttl)
        return fid is not None

    outcome = {"remembered": 0, "skipped": 0, "ids": []}
    if not records:
        return outcome
    if len(records) == 1 or workers <= 1:
        results = [one(r) for r in records]
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(one, records))
    outcome["remembered"] = sum(1 for ok in results if ok)
    outcome["skipped"] = sum(1 for ok in results if not ok)
    return outcome


def update_index(findings: list[dict], run_id: str, records: list[dict]) -> None:
    idx = load_index()
    idx.setdefault("_meta", {"backend": "gbrain+local", "updated_at": _now()})
    idx["_meta"]["updated_at"] = _now()
    company = findings[0]["company"]
    entry = idx.setdefault(company, {"runs": [], "findings": [], "facts": 0})
    if run_id not in entry["runs"]:
        entry["runs"].append(run_id)
    seen = {json.dumps(f, sort_keys=True, default=str) for f in entry["findings"]}
    for f in findings:
        key = json.dumps(f, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            entry["findings"].append({k: v for k, v in f.items() if not k.startswith("_")})
    entry["facts"] = sum(1 for r in records if r["entity"] == company_entity(company))
    save_index(idx)


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in findings:
        key = (f["company"], f["type"], f["host"], f["detail"][:200], f["severity"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def cmd_ingest(args) -> int:
    path = Path(args.scan)
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    try:
        findings = load_findings(path, deidentify=not args.no_deidentify)
    except (ValueError, json.JSONDecodeError, KeyError) as e:
        print(f"error: {path}: {e}", file=sys.stderr)
        return 2
    if not findings:
        print(f"error: {path}: no findings to ingest", file=sys.stderr)
        return 2
    findings = _dedupe_findings(findings)

    run_id = args.run_id or derive_run_id(findings)
    provenance = f"probe-report {findings[0]['observed_at']}" if findings[0].get("scan") == "probe-report" \
        else f"pairs-jsonl {findings[0]['observed_at']}"

    by_company: dict[str, list[dict]] = {}
    for f in findings:
        by_company.setdefault(f["company"], []).append(f)

    violations = _check_findings(findings)
    if violations and not args.allow_real:
        print("REFUSED to write: real-looking identifiers survived de-identification:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        print("fix: run ingest with de-identification (default) or pass --allow-real to override", file=sys.stderr)
        return _EXIT_REFUSE

    groups: list[tuple[str, list[dict], list[dict]]] = []
    for company in sorted(by_company):
        group = by_company[company]
        records = build_records(group, run_id, provenance, args.kind)
        for r in records:
            v = guard_violations(r["fact"])
            if v and not args.allow_real:
                print(f"REFUSED to write: guard flagged {v} in fact for {r['entity']}", file=sys.stderr)
                return _EXIT_REFUSE
        groups.append((company, group, records))

    if args.dry_run:
        n_facts = sum(len(r) for _, _, r in groups)
        n_company = sum(len(r) for _, _, r in groups)
        print(f"dry-run: {len(findings)} findings -> {n_facts} facts across {len(groups)} companies "
              f"({n_company} target facts), run {run_id}; guard clean")
        return 0

    store = LocalStore(args.store)
    for company, group, records in groups:
        if gbrain_available():
            sync_to_gbrain(records, args.ttl)
        store.append(records)
        if not args.no_index:
            update_index(group, run_id, records)

    backend = "gbrain+local" if gbrain_available() else "local"
    print(f"ingested {len(findings)} findings -> {sum(len(r) for _, _, r in groups)} facts "
          f"across {len(groups)} companies (run {run_id}; backend {backend})")
    for company, group, records in groups:
        n_company = sum(1 for r in records if r["entity"] == company_entity(company))
        n_type = sum(1 for r in records if r["entity"].startswith("findings/"))
        print(f"  targets/{company}: {n_company} finding facts + {n_type} findings/<type> + 1 runs/{run_id}")
    print(f"  local mirror: {sum(len(r) for _, _, r in groups)} records -> {store.path}")
    print(f"  guard: {len(violations)} real-looking identifiers survived")
    return 0


def _live_recall(entity: str) -> tuple[list[dict] | None, str]:
    proc = run_gbrain(["recall", entity, "--json"])
    if proc.returncode != 0 or _is_lock_error(proc):
        return None, "locked" if _is_lock_error(proc) else "error"
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, "error"
    facts = []
    for f in payload.get("facts", []) or []:
        facts.append({
            "id": f.get("id"),
            "entity": f.get("entity_slug"),
            "fact": f.get("fact"),
            "kind": f.get("kind"),
            "provenance": f.get("provenance"),
            "created_at": f.get("created_at"),
        })
    return facts, "live"


def _query_filter(facts: list[dict], query: str | None) -> list[dict]:
    if not query:
        return facts
    q = query.lower()
    return [f for f in facts if q in (f.get("fact") or "").lower()]


def recall_entity(entity: str, query: str | None = None, store: Path | None = None) -> tuple[list[dict], str]:
    if gbrain_available():
        live, mode = _live_recall(entity)
        if live is not None:
            return _query_filter(live, query), mode
    local = LocalStore(store).recall(entity)
    if not local and entity.startswith("targets/"):
        local = LocalStore(store).recall(entity, company=entity.split("/", 1)[1])
    return _query_filter(local, query), "local"


def _print_facts(entity: str, facts: list[dict], mode: str) -> None:
    if not facts:
        print(f"no facts for {entity}")
        return
    print(f"{entity} — {len(facts)} fact(s) " + (f"[{mode}]" if mode else ""))
    for f in facts:
        tag = f" [{f.get('entity')}]" if f.get("entity") and f.get("entity") != entity else ""
        extra = " · ".join(x for x in (str(f.get("kind", "")), str(f.get("provenance", ""))) if x)
        print(f"- [id={f.get('id', 'local')}] {f.get('fact', '')}" + (f"   [{tag.strip()}]" if tag.strip() else "") + (f"   ({extra})" if extra else ""))


def cmd_recall(args) -> int:
    if args.entity:
        entity = args.entity
    else:
        company = args.company.strip().strip("/")
        entity = company if entity_is_slug(company) else company_entity(company)
    entity = canonical_entity(entity)
    facts, mode = recall_entity(entity, args.query, Path(args.store) if args.store else None)
    if mode == "local" and gbrain_available():
        note = " — live recall locked by gbrain serve or read-failed; showing local mirror"
    elif mode == "local":
        note = " — gbrain not on PATH; local JSONL mirror"
    else:
        note = ""
    _print_facts(entity, facts, mode)
    if note:
        print(f"note:{note}", file=sys.stderr)
    return 0


def cmd_status(args) -> int:
    print(f"gbrain on PATH: {gbrain_available()}")
    if gbrain_available():
        probe, _ = _live_recall("targets/__status_probe__")
        if probe is None:
            print("live recall: BLOCKED (serve holds the brain or read failed) — using local mirror")
        else:
            print("live recall: OK")
    print(f"local store: {LocalStore(args.store).path} ({len(LocalStore(args.store).load())} records)")
    idx = load_index()
    print(f"index: {len([k for k in idx if k != '_meta'])} companies")
    return 0


def _self_test() -> int:
    reports: list[str] = []

    pairs = _ROOT / "data" / "example.pairs.jsonl"
    groups = parse_pairs(pairs)
    n_pairs = len(groups)
    assert n_pairs == 6, f"fixture expected 6 pairs, got {n_pairs}"
    assert all(g["company"].endswith(".example") for g in groups)
    assert all(g["host"].endswith(".example") for g in groups)
    for g in groups:
        assert not guard_violations(g["host"]), f"host leaked: {g['host']}"
        assert not guard_violations(g["detail"]), f"detail leaked in {g['type']}"
    companies = sorted({g["company"] for g in groups})
    reports.append(f"fixture parse: {n_pairs} pairs across {len(companies)} companies ({', '.join(companies)})")

    scan = {
        "scope": "acme-corp.com",
        "generated": "2026-09-27 21:52 UTC",
        "probe": [{
            "host": "www.acme-corp.com",
            "findings": [{"type": "exposed_env_file", "severity": "CRITICAL",
                          "detail": "/.env on https://admin.acme-corp.com leaks DATABASE_URL=postgres://alice@db.internal:5432/app; contact security@acme-corp.com; origin 203.0.113.7"}],
        }],
        "findings": [{"type": "missing_csp", "severity": "MEDIUM",
                      "location": "https://www.acme-corp.com", "detail": "CSP header absent on acme-corp.com marketing pages"}],
    }
    with tempfile.TemporaryDirectory() as tmp:
        sp = Path(tmp) / "scan.json"
        sp.write_text(json.dumps(scan), encoding="utf-8")
        findings = load_findings(sp, deidentify=True)
    assert findings and findings[0]["company"] == "target-01.example", findings[0]["company"]
    assert all(f["host"].endswith(".example") for f in findings)
    assert all(f["host"].startswith(("target", "www")) for f in findings)
    assert all(not guard_violations(f["host"]) and not guard_violations(f["detail"]) for f in findings)
    blob = " ".join(f["detail"] for f in findings)
    assert "acme-corp.com" not in blob and "acme" not in blob
    assert "db.internal" not in blob
    assert "alice@" not in blob and "security@" not in blob
    assert "203.0.113.7" not in blob
    assert "target-01.example" in blob and ("www.target-01.example" in blob or "thirdparty-" in blob)
    assert "198.51.100." in blob
    assert "user@example.com" in blob
    reports.append("scan de-id: hosts->*.example, IPs->198.51.100.x, emails->user@example.com, brands->*.example; guard clean")

    assert finding_entity("exposed_env_file") == "findings/exposed-env-file"
    assert company_entity("target-01.example") == "targets/target-01-example"
    assert run_entity("run-20260927T215200Z") == "runs/run-20260927t215200z"
    assert canonical_entity("target-01.example") == "target-01-example"
    assert entity_is_slug("findings/xss")
    assert not entity_is_slug("target-01.example")
    reports.append("ontology: targets/<pseudonym>, findings/<type>, runs/<run_id>; canonicalization matches gbrain slugify")

    v = guard_violations("recon on www.real-target.com and user@realcorp.io from 10.0.0.5")
    assert any("www.real-target.com" in x for x in v)
    assert any("user@realcorp.io" in x for x in v)
    assert any("10.0.0.5" in x for x in v)
    assert not guard_violations("host api.target-01.example user@example.com ip 198.51.100.4")
    reports.append("guard: refuses real domain/email/non-doc IP; passes reserved *.example/example.com/198.51.100.x")

    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "brain-local.jsonl"
        store = LocalStore(store_path)
        run_id = "run-selftest"
        prov = "selftest probe-report 2026-09-27T00:00:00Z"
        a_company = groups[0]["company"]
        b_company = next(g["company"] for g in groups if g["company"] != a_company)
        store.append(build_records([groups[0]], run_id, prov, "event"))
        store.append(build_records([next(g for g in groups if g["company"] == b_company)], run_id, prov, "event"))
        a_rec = store.recall(company_entity(a_company))
        b_rec = store.recall(company_entity(b_company))
        assert a_rec and b_rec, "both fixture companies must recall"
        assert all(canonical_entity(r["entity"]) == company_entity(a_company) for r in a_rec)
        assert all(canonical_entity(r["entity"]) == company_entity(b_company) for r in b_rec)
        r_run = store.recall(run_entity(run_id))
        assert len(r_run) == 2, f"run summaries expected 2 (one per company), got {len(r_run)}"
        assert any(a_company in r["fact"] for r in r_run) and any(b_company in r["fact"] for r in r_run)
        t_rec = store.recall(finding_entity(groups[0]["type"]))
        assert t_rec, "findings/<type> cross-company recall must work"
        assert any(a_company in r["fact"] for r in t_rec)
        reports.append(f"local store: {len(a_rec) + len(b_rec) + len(r_run)} records -> company isolation OK, "
                       f"run summary OK, cross-company type rollup OK ({len(t_rec)} sighting(s))")

    live = gbrain_available()
    live_detail = "degraded"
    if live:
        test_entity = company_entity(f"selftest-{int(time.time())}")
        ttype = "selftest_probe"
        run_id = f"run-selftest-{int(time.time())}"
        prov = "selftest 2026-09-27T00:00:00Z"
        recs = build_records([
            {"company": test_entity.split("/", 1)[1], "type": ttype, "host": "api.target-01.example",
             "detail": "selftest finding detail with no real infra", "severity": "LOW", "class": "standard",
             "observed_at": "2026-09-27T00:00:00Z", "scan": "probe-report"},
        ], run_id, prov, "event")
        try:
            outcome = sync_to_gbrain(recs, ttl="30m")
            assert outcome["remembered"] == len(recs), f"remembered {outcome['remembered']}/{len(recs)}"
            LocalStore().append(recs)
            facts, mode = recall_entity(test_entity)
            assert mode in ("live", "local"), f"unexpected recall mode {mode}"
            assert facts, "recall must find the self-test fact"
            assert any(ttype in f["fact"] for f in facts)
            cross, _ = recall_entity(finding_entity(ttype))
            assert any("selftest" in f["fact"] for f in cross), "findings/<type> cross-entity live recall failed"
            live_detail = f"live round-trip via {mode} recall: remember {len(recs)} -> recall OK, cross-entity OK"
        finally:
            for e in (test_entity, finding_entity(ttype), run_entity(run_id)):
                for f, _m in [recall_entity(e)]:
                    for item in f:
                        if item.get("id"):
                            forget(int(item["id"]))
                LocalStore().drop_entity(e)

    print(f"self-test OK: {live_detail}")
    for line in reports:
        print(f"  - {line}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="memory/brain.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true", help="offline check, no keys/network")
    sub = ap.add_subparsers(dest="command")

    ing = sub.add_parser("ingest", help="ingest a probe scan into the GBrain")
    ing.add_argument("scan", help="probe report.json (or a pairs-contract .jsonl)")
    ing.add_argument("--run-id", default=None, help="run identifier (default derived from observed_at)")
    ing.add_argument("--ttl", default=None, help="optional fact TTL, e.g. 30m")
    ing.add_argument("--kind", default=_DEFAULT_KIND, choices=_VALID_KINDS,
                     help="fact kind for all written facts (default event)")
    ing.add_argument("--no-deidentify", action="store_true",
                     help="skip host/IP/email/brand scrubbing (guard still refusals on real identifiers)")
    ing.add_argument("--allow-real", action="store_true",
                     help="override the refuse guard (UNSAFE: real infra would reach the shared brain)")
    ing.add_argument("--dry-run", action="store_true", help="build + guard-check only, write nothing")
    ing.add_argument("--store", default=str(_LOCAL_STORE), help="local JSONL mirror path")
    ing.add_argument("--no-index", action="store_true", help="skip memory/brain.json index update")

    rec = sub.add_parser("recall", help="what do we know about a company (or any brain entity)")
    rec.add_argument("company", nargs="?", default=None)
    rec.add_argument("query", nargs="?", default=None)
    rec.add_argument("--entity", default=None, help="recall any entity: targets/<c>, findings/<t>, runs/<id>")
    rec.add_argument("--store", default=str(_LOCAL_STORE))

    st = sub.add_parser("status", help="backend + local-store health")
    st.add_argument("--store", default=str(_LOCAL_STORE))

    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if a.command == "ingest":
        return cmd_ingest(a)
    if a.command == "recall":
        return cmd_recall(a)
    if a.command == "status":
        return cmd_status(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())