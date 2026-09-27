#!/usr/bin/env python3
"""data/build_vulns.py — mine the existing superset-sh recon report into
de-identified severity pairs for the customsecuritymodel corpus.

    python3 data/build_vulns.py --report ~/probe/out/superset-sh-deep-exploit-ports-nuclei/report.json

Reads the report (report.json: top-level `findings` + `deep.findings` union),
de-identifies every row (hosts -> *.example, secret VALUES -> described TYPE,
emails -> counts, brands -> brand-NN), classifies each finding `standard`
(OWASP floor) vs `blind_spot` (stack-specific things a generic suite misses),
and emits data/vulns-superset.jsonl + data/vulns-superset.manifest.json.

Data contract (data/README.md): one JSONL row = one training/eval example;
input/output never contain a real hostname, IP, email, brand or secret value;
provenance stamps source/target/class/observed_at.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deidentify

# Additional infra hosts this corpus legitimately mentions (integrations, not targets).
# NOTE: do NOT add the target apex domains here — they are the targets and must be
# pseudonymized by build_mapping, otherwise their subdomains leak raw.
for _infra in ("posthog.com", "firestore.googleapis.com", "github.com"):
    if _infra not in deidentify.INFRA_SUFFIXES:
        deidentify.INFRA_SUFFIXES += (_infra,)

# Canonical superset org / repo names -> stable pseudonyms (brands, not hosts).
ORG = "superset-sh"
_REPOS = (
    "superset", "mastra", "coding-agent", "coding-agent-mastra", "frontend-interview",
    "ghostty-web", "homebrew-tap", "acme-demo", "acme-ios-demo", "skills", ".github",
)

# Finding types a *generic* OWASP-style suite already checks (the floor).
_STANDARD = {
    "cdn_waf_detected", "xss_sink_escaped", "robots_exposed", "csp_unsafe_https_script",
    "missing_hsts", "missing_xframe", "missing_csp", "missing_xcontent", "tls_expired",
    "clickjacking_live", "cors_reflective", "cors_permissive", "unauth_api_200",
    "cloud_bucket_public", "dangling_dns_record", "swagger_api_docs", "exposed_swagger",
    "exposed_console", "openapi_public_api_map", "firebase_project_exists",
    "saas_service_detected", "cf_challenge_blocking", "spa_catchall", "paas_hosted",
    "github_org_member", "repo_email_leak",
}
# Everything else observed in this corpus is stack/org-specific (blind_spot).
_BLIND_SPOT = {
    "repo_secret_history", "repo_secret_file", "repo_secret_tree", "repo_posture_noscanning",
    "repo_posture_noprotection", "repo_ignore_gap", "repo_ci_risky", "git_commit_sha_leak",
    "mcp_tools_unauth", "api_post_csrf", "sentry_dsn_telemetry_injection",
    "posthog_analytics_injection", "nextauth_session_default", "supabase_anon_key_exposed",
    "firebase_firestore_open", "dub_metatags_ssrf", "challenge_bypass_host_reveal",
    "js_api_host_found", "js_cross_root_host", "csp_infra_leak", "js_route_extraction",
    "js_api_surface", "github_code_search_hit", "brand_repo_out_of_scope", "alias_duplicate",
    "cross_domain_redirect", "subdomain_wildcard", "tech_fingerprint",
}

# Secret VALUE patterns -> human class. Order matters: longest/most-specific first.
# We never emit the value — only the class. (dummy/test values get their own class.)
SECRET_CLASSES = (
    (re.compile(r"sk-ant-(?:api03|oat01|oat)"), "Anthropic API/OAuth key (sk-ant-*)"),
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,}"), "Stripe key (sk_/pk_/rk_ live|test)"),
    (re.compile(r"\bghp_[0-9A-Za-z]{20,}"), "GitHub personal access token (ghp_*)"),
    (re.compile(r"\bghs_[0-9A-Za-z]{20,}"), "GitHub server-to-server token (ghs_*)"),
    (re.compile(r"\bghu_[0-9A-Za-z]{20,}"), "GitHub user-to-server OAuth token (ghu_*)"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}"), "AWS access key (AKIA/ASIA)"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\."), "JWT (eyJ*)"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token (xox*)"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"), "Google API key (AIza*)"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key (PEM)"),
)
_DUMMY = re.compile(r"dummy|aaaaaaaa|EXAMPLE|placeholder|for-replay-mode", re.I)

# Code/config file extensions that residue() misreads as host TLDs (`.ts`, `.yml`).
# A bare filename ending in these is structural signal, not an identifier.
_FILE_EXT = re.compile(r"^[A-Za-z0-9_.\-]+\.(?:ts|tsx|js|jsx|yml|yaml|json|md|py|env|sample|npmrc|lock|toml|sh|example|test|gitignore|local|template|hcl|tf|txt)$", re.I)

# Bare-word foreign brands/template artifacts that are NOT this target's — they
# leak other companies (probe template contamination). Replace with generic tokens.
_FOREIGN_WORDS = {
    "vca": "foreign-brand", "piaget": "foreign-brand", "pax": "foreign-brand",
    "hims": "foreign-brand", "tomboyx": "foreign-brand",
    "wikipedia": "an-external-wiki", "vantatrust": "foreign-brand",
}
# Public-but-identifying client keys/SHAs in the report: keep the TYPE, never the value.
_VALUE_REDACT = (
    (re.compile(r"phc_[A-Za-z0-9_]+"), "phc_<posthog-project-key-redacted>"),
    (re.compile(r"(?i)sentry_key=[0-9a-f]{32}"), "sentry_key=<public-key-redacted>"),
    (re.compile(r"(?i)sentry\.io/api/\d+"), "sentry.io/api/<org-id-redacted>"),
    (re.compile(r"\b[0-9a-f]{40}\b"), "<40-hex-git-commit-sha-redacted>"),
    (re.compile(r"qztolncjqcteyyhiyvrw"), "<supabase-project-ref-redacted>"),
    (re.compile(r"(?<=documents/)[A-Za-z0-9_-]{20,}"), "<doc-id-redacted>"),
)
# File-extension paths to tokenize BEFORE host-mapping. NOTE: never include host
# TLDs here ("sh", "dev", "io", ...) — "superset.sh" must stay a hostname. Only
# extensions that cannot be a domain TLD are safe to treat as file paths.
_FILEPATH_RE = re.compile(
    r"\b[A-Za-z0-9_./-]+\.(?:ts|tsx|js|jsx|yml|yaml|json|md|py|html|php|txt|plist|npmrc|lock|toml)\b")
# JS code artifacts in detail text that otherwise read as "hosts" (json.stringify,
# console.log, user.email, ...). Tokenize them too.
_JSARTIFACT_RE = re.compile(
    r"\b(?:JSON\.stringify|console\.log|config\.accessKeyId|user\.email|result\.tools|[a-z][a-z0-9-]*\.(?:stringify|accessKeyId))\b", re.I)


def sanitize_text(text: str) -> str:
    """Pre-clean raw corpus text so build_mapping never treats emails or file paths
    as hostnames. Emails -> placeholder, file-ish paths -> 'a-file-path', probe
    output paths -> 'a-probe-output-path', foreign brand words -> generic tokens.
    Secret VALUES (no dots) survive untouched for class detection."""
    if not text:
        return text
    out = deidentify.EMAIL_RE.sub("user@target-00.example", text)
    out = re.sub(r"(?:/Users/[\w.-]+)?/probe/out/[\w./-]+", "a-probe-output-path", out)
    out = _FILEPATH_RE.sub("a-file-path", out)
    out = _JSARTIFACT_RE.sub("js-code-token", out)
    for pat, repl in _VALUE_REDACT:
        out = pat.sub(repl, out)
    for word, repl in _FOREIGN_WORDS.items():
        out = re.sub(rf"(?<![A-Za-z]){re.escape(word)}(?![A-Za-z])", repl, out, flags=re.IGNORECASE)
    out = out.replace("superset-data", "project-01")
    out = out.replace("superset-uploads", "bucket-01")
    return out

REPO_RE = re.compile(r"^([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+)")
EMAIL_COUNT_RE = re.compile(r"(\d+)\s+real emails? in history")

_INSTRUCTION = "Given this finding, assign a severity for THIS company's stack."


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_findings(report_path: Path) -> tuple[list[dict], str]:
    d = json.loads(report_path.read_text(encoding="utf-8"))
    generated = str(d.get("generated", "")).strip()
    if generated:
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})(?::\d{2})?", generated)
        if m:
            observed_at = f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:00Z"
        else:
            observed_at = generated
    else:
        observed_at = _now()
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in d.get("findings", []) + d.get("deep", {}).get("findings", []):
        key = (f.get("type"), f.get("severity"), f.get("location"), f.get("detail"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out, observed_at


def secret_class(text: str) -> str | None:
    for pat, label in SECRET_CLASSES:
        m = pat.search(text or "")
        if m:
            val = m.group(0)
            if _DUMMY.search(val):
                return label + " (dummy/test value)"
            return label
    return None


def repo_of(finding: dict) -> str | None:
    """Return 'org/repo' only when the location truly names a repo under the target
    org. Firestore URLs / other org/path pairs must not be mistaken for repos."""
    m = REPO_RE.match(finding.get("location") or "")
    if not m:
        return None
    org, _, name = m.group(1).partition("/")
    if org == ORG and name:
        return m.group(1)
    return None


def _describe_repo(repo: str, mapping: dict) -> str:
    org, _, name = repo.partition("/")
    org_p = mapping.get(org, org)
    if name in _REPOS:
        name = f"repo-{_REPOS.index(name) + 1:02d}"
    return f"{org_p}/{name}"


def describe_secret_finding(f: dict, repo: str, mapping: dict) -> str:
    """Return a de-identified description for secret-bearing findings — the secret
    VALUE is replaced with its class. Never include raw secret material."""
    loc = f.get("location") or ""
    detail = f.get("detail") or ""
    blob = loc + " " + detail
    cls = secret_class(blob)
    repo_p = _describe_repo(repo, mapping) if repo else "org"
    ftype = f.get("type")

    if ftype == "repo_secret_history":
        if "Binary file" in blob:
            base = "a secret is embedded in a binary blob in git history"
        else:
            base = f"a {'real ' if cls and 'dummy' not in cls else 'dummy/test '}secret"
            base += f" ({cls})" if cls else ""
            base += " is present in git history"
        return f"{base} of {repo_p}; deleting it in a later commit does not purge it; if the repo is public the value is internet-exposed — treat as compromised, rotate then purge history"

    if ftype == "repo_secret_file":
        # secret-named file: <path>  (path is structural, not a secret value)
        path = detail.removeprefix("secret-named file: ").strip() or "a secret-named file"
        return f"file named like a secret store in {repo_p}: {path}"

    if ftype == "repo_secret_tree":
        # high-confidence secret in tree: <path>:<line>: <provider>: '<value>'
        prov = "a provider credential"
        m = re.search(r"\b(anthropic|stripe|aws|github|slack|google|openai)\b", blob, re.I)
        if m:
            prov = m.group(1).lower()
        kind = cls or "a credential"
        return f"live secret ({kind}) in the current working tree of {repo_p} ({prov}) — trivially fetchable"

    return deidentify.scrub(detail, mapping)


def build_rows(finding: dict, mapping: dict, observed_at: str,
               primary_target: str) -> list[dict]:
    ftype = finding.get("type")
    sev = finding.get("severity")
    cls = "blind_spot" if ftype in _BLIND_SPOT else ("standard" if ftype in _STANDARD else "standard")
    loc = finding.get("location") or ""
    repo = repo_of(finding)

    if repo:
        host_field = f"repo: {_describe_repo(repo, mapping)}"
        target = primary_target
        detail = describe_secret_finding(finding, repo, mapping) if ftype in (
            "repo_secret_history", "repo_secret_file", "repo_secret_tree",
        ) else deidentify.scrub(sanitize_text(finding.get("detail") or ""), mapping)
    else:
            host = loc.split(":")[0].strip() if loc else ""
            host_p = mapping.get(host) if host else primary_target
            host_field = f"host: {host_p}"
            target = host_p or primary_target
            if ftype == "repo_email_leak":
                m = EMAIL_COUNT_RE.search((finding.get("detail") or "") + " " + loc)
                n = m.group(1) if m else "multiple"
                detail = f"{n} real contributor emails are committed in git history (email addresses are scraped/spam-targeted and enable account-takeover phishing); values not reproduced"
            else:
                detail = deidentify.scrub(sanitize_text(finding.get("detail") or ""), mapping)

    if not detail.strip():
        detail = (deidentify.scrub(sanitize_text(finding.get("why") or ""), mapping) or ftype).strip()

    input_text = f"type: {ftype}; {host_field}; detail: {detail}"
    prov = {"source": "probe-report", "target": target, "class": cls,
            "observed_at": observed_at}

    rows = [{"task": "severity", "instruction": _INSTRUCTION, "input": input_text,
             "output": sev, "provenance": prov}]

    if ftype in ("repo_secret_history", "repo_secret_file", "repo_posture_noscanning",
                 "repo_posture_noprotection", "api_post_csrf", "mcp_tools_unauth",
                 "sentry_dsn_telemetry_injection", "posthog_analytics_injection",
                 "firebase_firestore_open", "git_commit_sha_leak"):
        fix = deidentify.scrub(sanitize_text(finding.get("fix") or ""), mapping)
        if fix:
            rows.append({"task": "remediation", "instruction": "Write the concrete remediation for this scanner finding.",
                         "input": input_text, "output": fix, "provenance": dict(prov)})
        nxt = deidentify.scrub(sanitize_text(finding.get("test_next") or ""), mapping)
        if nxt and ftype in ("api_post_csrf", "mcp_tools_unauth", "repo_secret_history",
                             "git_commit_sha_leak", "sentry_dsn_telemetry_injection"):
            rows.append({"task": "next_test", "instruction": "Name the single highest-value manual check that confirms or kills this finding.",
                         "input": input_text, "output": nxt, "provenance": dict(prov)})
    return rows


def merge_duplicates(rows: list[dict]) -> list[dict]:
    """Collapse near-identical severity rows (e.g. 237 repo_secret_history findings
    in the same repo+class) into one row carrying a count, keeping the corpus
    high-signal instead of 237 identical examples."""
    merged: dict[tuple, dict] = {}
    for r in rows:
        key = (r["task"], r["input"], r["output"])
        if key in merged:
            merged[key]["_count"] += 1
        else:
            merged[key] = dict(r)
            merged[key]["_count"] = 1
    out = []
    for r in merged.values():
        n = r.pop("_count")
        if n > 1:
            r["input"] = r["input"] + f" (count: {n} occurrences in corpus)"
        out.append(r)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="data/build_vulns.py", description=__doc__)
    ap.add_argument("--report", required=True, help="path to report.json")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "vulns-superset.jsonl"))
    a = ap.parse_args(argv)

    report_path = Path(a.report).expanduser()
    findings, observed_at = load_findings(report_path)
    if not findings:
        print(f"no findings in {report_path}", file=sys.stderr)
        return 2

    # Build the host mapping from SANITIZED text so emails and file paths never
    # become "hostnames"; scrub later runs on sanitized text too.
    import copy as _copy
    sanitized = []
    for f in findings:
        s = _copy.deepcopy(f)
        for k, v in s.items():
            if isinstance(v, str):
                s[k] = sanitize_text(v)
        sanitized.append(s)
    mapping = deidentify.build_mapping(sanitized)
    # The GitHub org "superset-sh" is the same brand as the apex domains.
    mapping["superset-sh"] = mapping.get("superset", "brand-01")
    primary_target = mapping.get("superset.sh") or "target-01.example"

    rows: list[dict] = []
    dropped = {"contaminated": 0, "residue": 0, "unparseable": 0}
    for f in findings:
        try:
            cand = build_rows(f, mapping, observed_at, primary_target)
        except Exception:
            dropped["unparseable"] += 1
            continue
        for r in cand:
            text = r["input"] + " " + r["output"]
            res = [h for h in deidentify.residue(text) if not _FILE_EXT.match(h)]
            if res:
                dropped["residue"] += 1
                continue
            rows.append(r)

    rows = merge_duplicates(rows)
    out_path = Path(a.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    by_class = Counter(r["provenance"]["class"] for r in rows)
    by_task = Counter(r["task"] for r in rows)
    by_type = Counter()
    for r in rows:
        t = r["input"].split(";")[0].replace("type: ", "").strip()
        by_type[t] += 1
    manifest = {
        "rows": len(rows),
        "source": "probe-report",
        "observed_at": observed_at,
        "primary_target": primary_target,
        "corpus_findings": len(findings),
        "by_class": dict(by_class),
        "by_task": dict(by_task),
        "by_type": dict(by_type.most_common(20)),
        "dropped": dropped,
        "deidentify_version": deidentify.MODULE_VERSION,
        "adapter": "build_vulns/1.0",
    }
    mpath = out_path.with_suffix(".manifest.json")
    mpath.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())