#!/usr/bin/env python3
"""De-identify probe findings before they touch a trainer, a memory store, or a screen.

Three jobs, in this order:

1. `build_mapping(findings)` assigns every real host a stable pseudonym
   (`target-07.example`, `host-03.target-07.example`) and every brand label a
   stable token (`brand-04`). Stable means: the same corpus always produces the
   same mapping, so pairs rebuilt tomorrow keep the same split group keys.
2. `scrub(text, mapping)` replaces mapped hosts/brands, then runs a set of
   catch-all regexes over what is left: bare IPv4, emails, AWS-ish keys, JWTs,
   bearer tokens, private keys, S3 buckets.
3. `residue(text)` re-reads the scrubbed string and reports anything that still
   looks like a real identifier. Callers are expected to treat a non-empty
   residue as a hard failure, not a warning.

Known hazards this module exists to catch (from
`notes/probe-validation-pass-2026-09-09.md`):
  - the auto-redactor of the first pass caught 164 brand labels and 310 exact
    domains but missed third-party hostnames embedded in `why` / `detail`;
  - template contamination: some `why` / `detail` fields explain the impact
    using a *different* target's hostname. `cross_target_contamination()`
    flags those explicitly, because scrubbing them is not enough - the
    sentence is factually about the wrong asset and must be dropped.

Stdlib only. Import it, or run it: `python3 data/deidentify.py --self-test`.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Iterable

MODULE_VERSION = "deidentify/1.1"

# Hosts that are infrastructure, not targets. Keeping them is what makes the
# training signal readable ("an S3 bucket", "a Vercel preview"), and they carry
# no information about who the target was.
INFRA_SUFFIXES = (
    "amazonaws.com", "blob.core.windows.net", "storage.googleapis.com", "googleapis.com",
    "cloudfront.net", "akamaized.net", "fastly.net", "cloudflare.com", "cloudflare.net",
    "github.io", "githubusercontent.com", "gitlab.io", "netlify.app", "vercel.app",
    "herokuapp.com", "onrender.com", "fly.dev", "railway.app", "webflow.io",
    "supabase.co", "firebaseio.com", "sentry.io", "readthedocs.io", "pages.dev",
    "wpengine.com", "shopify.com", "myshopify.com", "hubspot.com", "zendesk.com",
    "atlassian.net", "sharepoint.com", "outlook.com", "office.com", "google.com",
    "microsoft.com", "apple.com", "example.com", "example.org", "localhost",
)

_TLD_STOP = {
    "com", "co", "org", "net", "io", "ai", "app", "dev", "so", "sh", "gg", "me", "xyz",
    "cloud", "club", "run", "tech", "tools", "build", "science", "uk", "fr", "jp", "de",
    "ca", "au", "eu", "us", "info", "biz", "site", "online", "store", "shop",
}

HOST_RE = re.compile(r"(?<![\w@.-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?![\w-])")
IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?!\w)(?!\.\d)")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}")
SECRET_RES = (
    ("{{aws-access-key}}", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("{{google-api-key}}", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("{{slack-token}}", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("{{stripe-key}}", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b")),
    ("{{github-token}}", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b")),
    ("{{jwt}}", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("{{bearer-token}}", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("{{private-key}}", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
)

PRIVATE_IP_RE = re.compile(r"^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")


def _is_infra(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in INFRA_SUFFIXES)


def _registrable(host: str) -> str:
    """Best-effort eTLD+1 without a public-suffix list.

    Two-label public suffixes we actually see in this corpus are handled
    explicitly; everything else falls back to the last two labels. Getting this
    slightly wrong is safe: it only changes which pseudonym a host groups under,
    and the residue check still catches anything left unmapped.
    """
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_label_suffixes = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk", "ac.uk", "gov.uk"}
    if ".".join(parts[-2:]) in two_label_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _iter_text_fields(finding: dict) -> Iterable[str]:
    for key in ("domain", "location", "why", "detail", "triage", "test_next", "fix", "evidence", "title"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            yield value
        elif isinstance(value, dict):
            yield json.dumps(value)


def collect_hosts(findings: list[dict]) -> list[str]:
    """Every non-infra host mentioned anywhere in the corpus, deterministically ordered."""
    hosts: set[str] = set()
    for f in findings:
        for text in _iter_text_fields(f):
            for m in HOST_RE.finditer(text):
                host = m.group(1).lower().rstrip(".")
                if host.split(".")[-1] in _TLD_STOP or "." in host:
                    if not _is_infra(host):
                        hosts.add(host)
    return sorted(hosts)


def build_mapping(findings: list[dict]) -> dict[str, str]:
    """Map real identifiers -> stable pseudonyms.

    Sites sharing a registrable domain share a target number, so `api.acme.com`
    and `www.acme.com` become `host-01.target-03.example` and
    `host-02.target-03.example`. That keeps the structural signal (same target,
    different host) which is exactly what the model should learn from, and it
    gives `data/splits.py` a group key that cannot leak one target across
    train and test.
    """
    hosts = collect_hosts(findings)
    registrables: dict[str, str] = {}
    mapping: dict[str, str] = {}

    for host in hosts:
        reg = _registrable(host)
        if reg not in registrables:
            registrables[reg] = f"target-{len(registrables) + 1:02d}.example"

    sub_counters: dict[str, int] = {}
    for host in hosts:
        reg = _registrable(host)
        pseudo_reg = registrables[reg]
        if host == reg:
            mapping[host] = pseudo_reg
        else:
            sub_counters[reg] = sub_counters.get(reg, 0) + 1
            mapping[host] = f"host-{sub_counters[reg]:02d}.{pseudo_reg}"

    # Brand labels: the bare word form of a target ("acme" in "Acme Inc", "acme-prod").
    brand_counter = 0
    for reg in sorted(registrables):
        label = reg.split(".")[0]
        if len(label) > 2 and label not in _TLD_STOP and label not in mapping:
            brand_counter += 1
            mapping[label] = f"brand-{brand_counter:02d}"

    # Public IPs get numbered too; private ranges are structural, keep them.
    ip_counter = 0
    seen_ips: set[str] = set()
    for f in findings:
        for text in _iter_text_fields(f):
            for m in IPV4_RE.finditer(text):
                ip = m.group(1)
                if ip in seen_ips or PRIVATE_IP_RE.match(ip):
                    continue
                octets = ip.split(".")
                if len(octets) == 4 and all(o.isdigit() and int(o) < 256 for o in octets):
                    seen_ips.add(ip)
    for ip in sorted(seen_ips):
        ip_counter += 1
        mapping[ip] = f"198.51.100.{ip_counter % 254 + 1}"  # RFC 5737 documentation range

    return mapping


def scrub(text: str, mapping: dict[str, str]) -> str:
    """Apply the mapping, then the catch-all regexes. Order matters."""
    if not text:
        return text
    out = text

    for repl, pattern in SECRET_RES:
        out = pattern.sub(repl, out)

    # Longest first so `api.acme.com` is replaced before `acme.com`.
    for real in sorted(mapping, key=len, reverse=True):
        if not real:
            continue
        out = re.sub(rf"(?<![\w-]){re.escape(real)}(?![\w-])", mapping[real], out, flags=re.IGNORECASE)

    out = EMAIL_RE.sub("user@target-00.example", out)

    def _ip_repl(m: re.Match) -> str:
        ip = m.group(1)
        return ip if PRIVATE_IP_RE.match(ip) else "198.51.100.254"

    out = IPV4_RE.sub(_ip_repl, out)

    def _host_repl(m: re.Match) -> str:
        host = m.group(1)
        if _is_infra(host) or host.lower().endswith(".example"):
            return host
        return "target-xx.example"

    out = HOST_RE.sub(_host_repl, out)
    return out


def scrub_finding(finding: dict, mapping: dict[str, str]) -> dict:
    """Scrub every text field of a finding, keeping non-text fields untouched."""
    out: dict[str, Any] = {}
    for key, value in finding.items():
        if isinstance(value, str):
            out[key] = scrub(value, mapping)
        elif isinstance(value, dict):
            out[key] = {k: (scrub(v, mapping) if isinstance(v, str) else v) for k, v in value.items()}
        elif isinstance(value, list):
            out[key] = [scrub(v, mapping) if isinstance(v, str) else v for v in value]
        else:
            out[key] = value
    return out


def residue(text: str) -> list[str]:
    """Anything in `text` that still looks like a real identifier."""
    hits: list[str] = []
    for m in HOST_RE.finditer(text or ""):
        host = m.group(1).lower()
        if host.endswith(".example") or _is_infra(host):
            continue
        hits.append(host)
    for m in IPV4_RE.finditer(text or ""):
        ip = m.group(1)
        if PRIVATE_IP_RE.match(ip) or ip.startswith("198.51.100."):
            continue
        hits.append(ip)
    for m in EMAIL_RE.finditer(text or ""):
        if not m.group(0).endswith(".example"):
            hits.append(m.group(0))
    for _, pattern in SECRET_RES:
        for m in pattern.finditer(text or ""):
            hits.append(m.group(0)[:24] + "...")
    return sorted(set(hits))


def cross_target_contamination(finding: dict) -> list[str]:
    """Hosts mentioned in the prose that do not belong to this finding's target.

    This is the template-contamination bug from the 2026-09-09 pass: a
    `norseprojects.com` finding whose `why` explains impact using
    `artie-backend.onrender.com`, or a `waf_free_preview_mirror` `why` that
    still names `harrywinston.com` on an unrelated target. The sentence is
    about the wrong asset, so the row is unusable as training signal no matter
    how well it is scrubbed. Drop it.
    """
    own = set()
    for key in ("domain", "location"):
        value = finding.get(key)
        if isinstance(value, str):
            for m in HOST_RE.finditer(value):
                own.add(_registrable(m.group(1)))
    foreign: set[str] = set()
    for key in ("why", "detail", "triage", "test_next", "fix"):
        text = finding.get(key)
        if not isinstance(text, str):
            continue
        for m in HOST_RE.finditer(text):
            host = m.group(1).lower()
            if _is_infra(host) or host.endswith(".example"):
                continue
            reg = _registrable(host)
            if own and reg not in own:
                foreign.add(host)
    return sorted(foreign)


def jev_residue_gate(scrubbed: list[dict], api_key: str | None = None,
                     base_url: str = "https://api.typesafe.ai",
                     model: str = "jev-latest", threshold: float = 0.5,
                     batch: int = 50, timeout: float = 30.0) -> dict:
    """Optional semantic second pass over regex-clean rows (needs TYPESAFE_API_KEY).

    Regex residue() catches things that still *look* like identifiers; Jev
    answers the harder question — "does this text read like it's about a real
    named company/host?" — which catches unmapped brands and identifiers with
    no regex shape. One request per batch of `batch` rows: each row gets one
    `noul` question, they run in parallel server-side.

    Returns {"flagged": [row indices], "checked": n, "status": "ok"|"skipped"|"error"}.
    Never drops rows itself — callers decide; on API error the gate reports
    and defers to the regex gate rather than silently passing.
    """
    import os
    import urllib.request
    import urllib.error

    key = api_key or os.environ.get("TYPESAFE_API_KEY")
    if not key:
        return {"flagged": [], "checked": 0, "status": "skipped",
                "reason": "no TYPESAFE_API_KEY"}

    flagged: list[int] = []
    checked = 0
    try:
        for start in range(0, len(scrubbed), batch):
            chunk = scrubbed[start:start + batch]
            questions = {}
            for i, f in enumerate(chunk):
                questions[f"row_{i}"] = {
                    "type": "noul",
                    "instructions": (
                        "Does this security-finding record still contain a real "
                        "identifier — an actual company name, domain, IP, email, "
                        "or secret — that survived de-identification? Placeholders "
                        "like target-01.example, brand-02, 198.51.100.x and "
                        "{{tokens}} are already anonymized and are NOT residue."
                    ),
                    "criteria": {
                        "true": "A real, identifying name or address remains",
                        "false": "Only pseudonyms, placeholders, and infra hosts remain",
                    },
                }
            state = {"rows": [json.dumps(f, sort_keys=True)[:4000] for f in chunk]}
            req = urllib.request.Request(
                f"{base_url.rstrip('/')}/v1/systemone",
                data=json.dumps({"model": model, "state": state,
                                 "questions": questions}).encode("utf-8"),
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {key}"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            answers = body.get("answers") or {}
            for i in range(len(chunk)):
                ans = answers.get(f"row_{i}") or {}
                if ans.get("noul", 0.0) >= threshold:
                    flagged.append(start + i)
            checked += len(chunk)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError,
            json.JSONDecodeError) as e:
        return {"flagged": flagged, "checked": checked, "status": "error",
                "reason": str(e)}
    return {"flagged": flagged, "checked": checked, "status": "ok"}


def _self_test() -> int:
    findings = [
        {
            "domain": "acme.com",
            "type": "dkim_missing",
            "severity": "HIGH",
            "location": "mail.acme.com",
            "why": "Acme has no DKIM selector, so mail from acme.com cannot be verified.",
            "detail": "dig TXT selector1._domainkey.acme.com -> NXDOMAIN. Origin 34.120.5.9. Contact ops@acme.com.",
            "fix": "Publish the selector TXT record.",
        },
        {
            "domain": "beta-corp.co.uk",
            "type": "unauth_api_200",
            "severity": "HIGH",
            "location": "api.beta-corp.co.uk/v1/billing",
            "why": "Impact is the same as the artie-backend.onrender.com leak on harrywinston.com.",
            "detail": "GET returns 200 with 9049B JSON, token eyJhbGciOiJIUzI1NiJ9.abcdefgh.ijklmnop, no auth header.",
        },
    ]
    mapping = build_mapping(findings)
    failures: list[str] = []

    if "acme.com" not in mapping or not mapping["acme.com"].endswith(".example"):
        failures.append(f"acme.com not mapped to a pseudonym: {mapping.get('acme.com')!r}")
    if mapping.get("mail.acme.com", "").split(".", 1)[-1] != mapping.get("acme.com"):
        failures.append("subdomain not grouped under its registrable pseudonym")
    if mapping.get("beta-corp.co.uk") == mapping.get("acme.com"):
        failures.append("two distinct targets collapsed into one pseudonym")

    scrubbed = [scrub_finding(f, mapping) for f in findings]
    for f in scrubbed:
        for text in _iter_text_fields(f):
            left = residue(text)
            if left:
                failures.append(f"residue survived scrubbing: {left} in {text[:70]!r}")

    if "{{jwt}}" not in json.dumps(scrubbed):
        failures.append("JWT not redacted")
    if "34.120.5.9" in json.dumps(scrubbed):
        failures.append("public IP not redacted")

    contamination = cross_target_contamination(findings[1])
    if "harrywinston.com" not in contamination:
        failures.append(f"cross-target contamination not detected: {contamination}")
    if cross_target_contamination(findings[0]):
        failures.append("false positive contamination on a clean finding")

    stable = build_mapping(findings)
    if stable != mapping:
        failures.append("mapping is not deterministic across calls")

    gate = jev_residue_gate([{"domain": "target-01.example", "why": "ok"}],
                            api_key=None, base_url="http://127.0.0.1:1", timeout=0.1)
    if gate["status"] != "skipped":
        failures.append(f"jev gate without key should skip, got {gate['status']}")

    for line in failures:
        print(f"FAIL {line}")
    if failures:
        return 1
    print(f"ok {MODULE_VERSION}: mapping={len(mapping)} entries, scrub clean, contamination detector armed, jev gate skips keyless")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", help="JSON file: a list of findings, or {'findings': [...]}")
    ap.add_argument("--output", help="Where to write the scrubbed findings (default stdout)")
    ap.add_argument("--print-mapping", action="store_true", help="Print the pseudonym mapping to stderr")
    ap.add_argument("--jev-check", action="store_true",
                    help="semantic residue gate via TypeSafe Jev (needs TYPESAFE_API_KEY)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()
    if not args.input:
        ap.error("--input is required unless --self-test")

    with open(args.input, encoding="utf-8") as fh:
        raw = json.load(fh)
    findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
    mapping = build_mapping(findings)
    scrubbed = [scrub_finding(f, mapping) for f in findings]

    if args.jev_check:
        gate = jev_residue_gate(scrubbed)
        if gate["status"] == "ok":
            for idx in sorted(gate["flagged"], reverse=True):
                del scrubbed[idx]
            print(f"jev gate: checked {gate['checked']} rows, "
                  f"dropped {len(gate['flagged'])} with semantic residue", file=sys.stderr)
        else:
            print(f"jev gate {gate['status']}: {gate.get('reason', '')} — "
                  "regex gate only, nothing dropped", file=sys.stderr)

    if args.print_mapping:
        for real, pseudo in sorted(mapping.items()):
            print(f"{real}\t{pseudo}", file=sys.stderr)

    payload = json.dumps(scrubbed, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"wrote {len(scrubbed)} scrubbed findings to {args.output}")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
