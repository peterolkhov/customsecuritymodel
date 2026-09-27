#!/usr/bin/env python3
"""
arch_mine: CHEAP architecture-derived vulnerability characterization.

Reads EXISTING probe reports (no scanning, no network) and, from the DNS/mail/CDN/
hosting architecture alone, derives the *likely* vulnerabilities a stack implies.
Emits one contract row per target to data/arch-mine.jsonl and a demo table to
ARCH-MINE.md.

Contract (data/README.md):
  {task, instruction, input, output, provenance}
  - input/output fully de-identified: *.example only, no hostnames/IPs/emails/brands
  - provenance: source=probe-report-arch, target=<slug>.example, class=blind_spot
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROBE_OUT = Path("/Users/peterolkhovets/probe/out")
REPO = Path(__file__).resolve().parent.parent
OUT_JSONL = REPO / "data" / "arch-mine.jsonl"
OUT_MD = REPO / "ARCH-MINE.md"

OBSERVED_AT = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------------------
# Selection: (slug, report_subdir, industry_guess)
# ~30 diverse targets: payment processors, ecommerce, AI infra, crypto,
# healthcare, devtools, security, cloud.
# ---------------------------------------------------------------------------
SELECTION = [
    ("razorpay-com", "razorpay-com-deep-exploit-ports-nuclei", "payment processing"),
    ("affirm-com", "affirm-com-deep-payment", "payment processing / BNPL"),
    ("chewy-com", "chewy-com-deep-payment", "ecommerce / pet retail"),
    ("glossier-com", "glossier-com-deep-payment", "ecommerce / DTC beauty"),
    ("stockx-com", "stockx-com-deep-payment", "ecommerce / resale marketplace"),
    ("poshmark-com", "poshmark-com-deep-payment", "ecommerce / C2C marketplace"),
    ("therealreal-com", "therealreal-com-deep-payment", "ecommerce / luxury resale"),
    ("replicate-com", "replicate-com-deep", "AI infrastructure"),
    ("together-ai", "together-ai-deep", "AI infrastructure"),
    ("groq-com", "groq-com-deep", "AI hardware / inference"),
    ("modal-com", "modal-com-deep", "AI infrastructure"),
    ("deepinfra-com", "deepinfra-com-deep", "AI inference"),
    ("runpod-io", "runpod-io-deep", "GPU cloud"),
    ("coreweave-com", "coreweave-com-deep", "GPU cloud"),
    ("cerebras-net", "cerebras-net-deep", "AI hardware"),
    ("fal-ai", "fal-ai-deep", "AI media / API"),
    ("baseten-co", "baseten-co-deep", "AI infrastructure"),
    ("cognition-ai", "cognition-ai-deep-exploit", "AI devtools / agents"),
    ("sierra-ai", "sierra-ai-deep-exploit", "AI agents / customer experience"),
    ("stoaexchange-com", "stoaexchange-com-deep-exploit", "crypto exchange"),
    ("opentrade-live", "opentrade-live-deep-exploit", "crypto trading"),
    ("donkey-trade", "donkey-trade-deep-exploit", "crypto trading"),
    ("cerebral-com", "cerebral-com-deep-payment", "healthcare / telehealth"),
    ("hims-com", "hims-com-deep-payment", "healthcare / telehealth"),
    ("nurx-com", "nurx-com-deep-payment", "healthcare / telehealth"),
    ("letsgetchecked-com", "letsgetchecked-com-deep-payment", "healthcare / diagnostics"),
    ("posthog-com", "posthog-com-deep", "devtools / product analytics"),
    ("langfuse-com", "langfuse-com-deep", "devtools / LLM observability"),
    ("zendesk-com", "zendesk-com-deep-exploit", "SaaS / support platform"),
    ("huntresslabs-com-huntress-com", "huntresslabs-com-huntress-com-deep", "security"),
    ("ouraring-com", "ouraring-com-deep-payment", "wearables / health"),
    ("linode-com", "linode-com-deep", "cloud hosting"),
]

# ---------------------------------------------------------------------------
# De-identification maps: real brands -> generic categories (contract: no brands)
# ---------------------------------------------------------------------------
MAIL_PROVIDER_MAP = {
    "Google Workspace": "hosted-email (workspace-class)",
    "Microsoft 365": "hosted-email (office-class)",
    "Zoho": "hosted-email (zoho-class)",
    "Proton": "hosted-email (privacy-class)",
}

SAAS_CATEGORY = {
    "Google Search Console": "search-console verification",
    "Apple Business": "apple business verification",
    "Microsoft 365": "office-suite",
    "Stripe Payments": "payment-processor",
    "DocuSign": "e-signature",
    "Notion": "docs-suite",
    "Slack": "chat-suite",
    "Zoom": "video-suite",
    "Meta/Facebook Business": "social business verification",
    "OneTrust": "privacy-governance",
    "Adobe SSO": "identity-provider",
    "Miro": "whiteboard-suite",
    "Cloudflare Dashboard SSO": "cdn-provider-sso",
    "Amazon Business": "b2b-marketplace",
    "Rippling (HR/IT)": "hr-it-suite",
}

VERIFY_TOKEN_CATEGORY = {
    "google-site-verification": "search-console",
    "apple-domain-verification": "apple",
    "stripe-verification": "payment-processor",
    "docusign": "e-signature",
    "facebook-domain-verification": "social",
    "adobe-idp-site-verification": "identity-provider",
}

# CDN / hosting server -> category (brand-free)
CDN_CATEGORY = {
    "cloudflare": "edge-cdn/waf (cloudflare-class)",
    "cloudfront": "edge-cdn (aws-class)",
    "vercel": "edge-cdn (vercel-class)",
    "fastly": "edge-cdn (fastly-class)",
    "akamai": "edge-cdn (akamai-class)",
    "netlify": "edge-cdn (netlify-class)",
    "sucuri": "edge-waf (sucuri-class)",
}
SERVER_CATEGORY = {
    "vercel": "vercel-class edge runtime",
    "cloudflare": "cloudflare-class edge",
    "nginx": "nginx",
    "apache": "apache",
    "amazons3": "aws s3",
    "microsoft-httpapi/2.0": "microsoft httpapi",
    "awselb/2.0": "aws elb",
    "cloudfront": "aws cloudfront",
    "google frontend": "google frontend",
    "microsoft-iis/10.0": "microsoft iis",
    "akamaighost": "akamai edge",
    "akamainetstorage": "akamai netstorage",
    "squarespace": "squarespace managed",
    "github.com": "github pages",
    "esf": "esf",
}

# ---------------------------------------------------------------------------
# Derived-vuln rules. Each: (name, severity, detect(profile)->bool|None, reason)
# None severity = skip. Deterministic, no LLM.
# ---------------------------------------------------------------------------
SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class ArchProfile:
    def __init__(self, slug: str, industry: str, report: dict):
        self.slug = slug
        self.industry = industry
        d = report.get("deep") or {}
        self.infra = d.get("infra") or []
        self.hosts = d.get("hosts") or []
        self.scope = report.get("scope") or ""
        self._compute()

    # ---- signal aggregation -------------------------------------------------
    def _compute(self):
        dns_records = [i.get("dns") or {} for i in self.infra if (i.get("dns") or {}).get("domain")]
        # canonical apex = first scope entry (primary registrable domain)
        apex = ""
        if self.scope:
            apex = str(self.scope).split(",")[0].strip().lower()
        apex_rec = next((r for r in dns_records if str(r.get("domain")).strip().lower() == apex), None)
        # fall back: any record with a mail provider, else first non-empty record
        chosen = apex_rec or next((r for r in dns_records if r.get("mail_provider")), None) or (dns_records[0] if dns_records else {})
        self.dns_available = bool(dns_records)

        # positive signals aggregated across ALL records (org-wide posture)
        any_dkim = any(r.get("dkim_found") for r in dns_records)
        any_dnssec = any(r.get("dnssec") for r in dns_records)
        any_mta_sts = any(r.get("mta_sts_txt") for r in dns_records)
        any_caa = any(r.get("caa") for r in dns_records)
        any_bimi = any(r.get("bimi") for r in dns_records)
        saas_all = []
        verify_all = []
        for r in dns_records:
            saas_all.extend(SAAS_CATEGORY.get(s, "third-party-saas") for s in (r.get("saas_footprint") or []))
            verify_all.extend(VERIFY_TOKEN_CATEGORY.get(str(t).split("=")[0], "third-party") for t in (r.get("verification_tokens") or []))

        self.mail_provider = chosen.get("mail_provider") or ""
        self.mail_provider_cat = self._cat_mail(self.mail_provider)
        self.dmarc_policy = chosen.get("dmarc_policy")
        self.dmarc_weak = bool(chosen.get("dmarc_weak"))
        self.dnssec = any_dnssec
        self.spf_all = chosen.get("spf_all") or ""
        self.dkim_found = any_dkim
        self.mta_sts = any_mta_sts
        self.bimi = any_bimi
        self.caa = any_caa
        self.tls_rpt = bool(chosen.get("tls_rpt"))
        self.saas_footprint = saas_all
        self.verify_tokens = verify_all
        self.third_party_spf = chosen.get("third_party_spf") or []

        # host-level signals
        self.cdns = Counter()
        self.servers = Counter()
        self.host_findings = Counter()
        self.challenge_hosts = 0
        self.origin_exposed_hosts = 0
        self.total_hosts = len(self.hosts)
        for h in self.hosts:
            c = h.get("cdn") or {}
            cdn = c.get("cdn")
            if cdn:
                self.cdns[CDN_CATEGORY.get(str(cdn).lower(), str(cdn).lower())] += 1
            srv = c.get("server")
            if srv:
                self.servers[SERVER_CATEGORY.get(str(srv).lower(), str(srv).lower())] += 1
            if c.get("challenge"):
                self.challenge_hosts += 1
            if not cdn and (str(srv).lower() in ("nginx", "apache", "awselb/2.0", "amazons3", "")):
                self.origin_exposed_hosts += 1
            for f in h.get("findings") or []:
                self.host_findings[f.get("type")] += 1

        # top-level deep.findings too (mirror host findings in most reports)
        deep_findings = []
        for i in self.infra:
            deep_findings.extend(i.get("findings") or [])
        self.all_findings = self.host_findings.copy()
        for f in deep_findings:
            self.all_findings[f.get("type")] += 1

    def _cat_mail(self, mp: str) -> str:
        mp = mp or ""
        if not mp and not self.dns_available:
            return "unknown (dns not captured)"
        key = mp.split("(")[0].strip()
        if "self-hosted" in mp or key in ("self-hosted/other", "self-hosted"):
            return "self-hosted/third-party mail relay"
        return MAIL_PROVIDER_MAP.get(key, "hosted-email (other-class)")

    # ---- rule helpers -------------------------------------------------------
    def has(self, *types: str) -> bool:
        return any(self.host_findings.get(t, 0) > 0 for t in types)

    def count(self, *types: str) -> int:
        return sum(self.host_findings.get(t, 0) for t in types)

    @property
    def no_cdn_any(self) -> bool:
        return len(self.cdns) == 0 or (self.total_hosts and self.cdns.total() == 0)


# ---------------------------------------------------------------------------
def derive(ap: ArchProfile) -> list[dict]:
    """Return [{vuln, severity, reason}] ranked by severity desc."""
    out = []

    def add(vuln, severity, reason):
        if severity:
            out.append({"vuln": vuln, "severity": severity, "reason": reason})

    # ---- email spoofing chain (only when DNS was actually collected) ----
    if ap.dns_available:
        dmarc_bad = ap.dmarc_policy in (None, "none") or ap.dmarc_weak
        dkim_bad = not ap.dkim_found
        spf_bad = ap.spf_all in ("~all", "", None)
        if dmarc_bad and dkim_bad and spf_bad:
            add("domain_spoofing", "HIGH",
                "no DMARC enforcement (p=none/absent), no DKIM signer, SPF softfail/absent: the domain is directly spoofable for phishing.")
        elif dmarc_bad and (dkim_bad or spf_bad):
            add("domain_spoofing", "MEDIUM",
                "DMARC not enforcing and at least one of DKIM/SPF is missing or soft — a partial spoofing window exists.")
        elif dmarc_bad:
            add("domain_spoofing", "LOW",
                "DMARC policy is none/weak but DKIM+SPF present — spoofed mail lands but is unenforced.")
        if not ap.dnssec:
            add("dnssec_missing", "MEDIUM",
                "no DNSSEC: DNS responses are unauthenticated, widening cache-poisoning/spoofing surface for the whole domain.")
        if not ap.mta_sts:
            add("mta_sts_missing", "LOW",
                "no MTA-STS: inbound SMTP transport can be downgraded/stripped on the wire.")
        if "self-hosted" in ap.mail_provider_cat:
            add("self_hosted_mail", "MEDIUM",
                "mail is self-hosted/third-party relay: mail infra is an in-scope brute-force and relay-abuse surface the org must patch itself.")
        if not ap.caa:
            add("caa_missing", "LOW",
                "no CAA records: any authorized CA (or attacker with a cert-issuance path) can mint certificates for the domain.")
        if not ap.bimi and (ap.dmarc_policy in (None, "none") or ap.dmarc_weak):
            add("bimi_missing", "LOW",
                "no BIMI + no DMARC enforcement: recipients get no brand trust indicator, phishing is harder to distinguish.")
    else:
        add("dns_posture_unknown", "INFO",
            "DNS/mail posture not captured for this target's report (probe gap) — email chain derived from host signals only.")

    # ---- credential / secret exposure ----
    if ap.has("js_hardcoded_api_key"):
        add("js_credential_exposure", "HIGH",
            f"hardcoded API key(s) shipped in client-side JS bundles ({ap.count('js_hardcoded_api_key')} hits): directly extractable credentials.")
    if ap.has("nextjs_sourcemap_exposed"):
        add("sourcemap_disclosure", "MEDIUM",
            f"Next.js source maps exposed ({ap.count('nextjs_sourcemap_exposed')} hits): original TS/TSX source + env names recoverable, feeding secret hunting.")

    # ---- subdomain takeover / DNS hygiene ----
    if ap.has("dangling_dns_record"):
        add("subdomain_takeover", "HIGH",
            f"dangling DNS records ({ap.count('dangling_dns_record')}): live subdomains point at reclaimable infra, enabling origin spoofing/cookie theft.")
    if ap.has("wildcard_dns_sinkhole"):
        add("wildcard_dns_sinkhole", "MEDIUM",
            "wildcard DNS sinkhole: every label resolves, masking sensitive hostnames and creating a takeover/littering surface.")
    if ap.verify_tokens:
        add("dangling_verification_tokens", "MEDIUM",
            f"3rd-party domain-verification tokens present ({ap.verify_tokens}) — if any tenant is dropped the token becomes a takeover/impersonation lever.")

    # ---- web / infra exposure ----
    if ap.origin_exposed_hosts and (ap.no_cdn_any or ap.origin_exposed_hosts >= 2):
        add("origin_exposure", "MEDIUM",
            f"{ap.origin_exposed_hosts} host(s) served from raw origin (no CDN/WAF in front): direct attack surface bypassing edge filtering.")
    if ap.has("origin_server_leak"):
        add("origin_leak", "MEDIUM",
            "origin server fingerprint leaks behind the CDN (e.g. legacy backend reveals its server header) — WAF-bypass recon lever.")
    if ap.has("exposed_console"):
        add("admin_surface", "LOW",
            f"admin/debug endpoints reachable ({ap.count('exposed_console')} hits): /admin, /login, /console etc. present, weak-auth risk.")
    if ap.has("http_method_trace"):
        add("http_trace", "LOW",
            "HTTP TRACE enabled on at least one host: reflector for credential-stealing via XST.")

    # ---- identity / sso ----
    if ap.has("wellknown_oidc", "oidc_discovery_open"):
        add("oidc_discovery_open", "MEDIUM",
            "unauthenticated OIDC discovery endpoints exposed: reveals SSO/identity-provider surface for config attacks.")
    if ap.has("m365_autodiscover_proxy"):
        add("m365_autodiscover_proxy", "MEDIUM",
            "Microsoft365 autodiscover proxy surface found: classic endpoint for credential-harvesting misconfigurations.")

    # ---- app-layer blind spots the stack implies ----
    if ap.has("commerce_platform_detected") or ap.has("payment_provider_detected"):
        add("checkout_payment_surface", "MEDIUM",
            "commerce platform + payment provider(s) in the stack: checkout/coupon/webhook IDOR & price-tampering surface implied by architecture.")
    if ap.has("shopify_ucp_surface"):
        add("shopify_ucp_surface", "MEDIUM",
            "Shopify UCP/MCP checkout surface advertised: unauthenticated order-lifecycle tooling exposed.")
    if ap.has("graphql_endpoint"):
        add("graphql_surface", "LOW",
            f"GraphQL endpoint(s) present ({ap.count('graphql_endpoint')}): introspection / over-fetching surface if schema is open.")
    if ap.has("api_post_csrf"):
        add("api_csrf", "MEDIUM",
            f"state-changing POST endpoints without CSRF protection ({ap.count('api_post_csrf')}): cross-site action forgery.")
    if ap.has("cors_permissive"):
        add("cors_permissive", "MEDIUM",
            "permissive CORS reflected on API hosts: cross-origin data read risk.")
    if ap.has("csp_infra_leak"):
        add("csp_infra_leak", "LOW",
            "CSP policy leaks infra hostnames/cloud storage — recon amplifier for the attacker.")
    if ap.has("firebase_project_exists"):
        add("firebase_config_leak", "MEDIUM",
            "Firebase project exists in the surface: misconfigured RTDB/auth-chain account-takeover risk implied by the stack.")
    if ap.has("saas_service_detected"):
        add("saas_supply_chain", "MEDIUM",
            f"3rd-party SaaS tenants reachable via subdomains ({ap.count('saas_service_detected')}): tenant-takeover/supply-chain surface.")
    if ap.has("dns_verification_token"):
        add("dns_verification_token", "LOW",
            "DNS verification tokens present on live hosts — dangling tokens become takeover levers.")

    # ---- sort ----
    out.sort(key=lambda v: SEV_RANK.get(v["severity"], 0), reverse=True)
    return out


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Architecture/posture signal types only (no active-exploit results).
# These are the *stack* facts the derive rules reason over.
# ---------------------------------------------------------------------------
ARCH_SIGNAL_TYPES = [
    "cdn_waf_detected", "cf_challenge_blocking", "commerce_platform_detected",
    "payment_provider_detected", "saas_service_detected", "firebase_project_exists",
    "js_hardcoded_api_key", "nextjs_sourcemap_exposed", "dangling_dns_record",
    "wildcard_dns_sinkhole", "origin_server_leak", "csp_infra_leak",
    "wellknown_oidc", "oidc_discovery_open", "m365_autodiscover_proxy",
    "exposed_console", "http_method_trace", "graphql_endpoint", "api_post_csrf",
    "cors_permissive", "dns_verification_token", "shopify_ucp_surface",
    "tech_fingerprint", "hosting_ports_exposed", "spa_catchall", "paas_hosted",
    "vercel_app_candidate", "clerk_dev_instance_in_prod", "stytch_dev_instance_in_prod",
    "payment_order_idor", "payment_coupon_code_injection", "csp_unsafe_https_script",
    "csp_infra_leak", "js_api_surface", "js_cross_root_host", "js_api_host_found",
    "posthog_analytics_injection", "permissive_frame_ancestors", "missing_hsts",
    "missing_xframe", "missing_csp", "missing_xcontent", "clickjacking_live",
    "dmarc_none", "spf_softfail", "dkim_missing", "bimi_missing", "dnssec_missing",
    "mta_sts_missing", "caa_missing", "tls_rpt_missing", "dns_mail_provider",
    "dkim_selector_found", "origin_ptr_cross_root", "cross_domain_redirect",
    "wellknown_security_txt", "robots_exposed", "wayback_payment_surface",
]


def summarize_arch(ap: ArchProfile) -> str:
    """De-identified architecture summary (the JSONL input)."""
    if ap.dns_available:
        dmarc_s = ap.dmarc_policy or "absent"
        spf_s = ap.spf_all or "absent"
        dkim_s = "present" if ap.dkim_found else "absent"
        mta_s = "present" if ap.mta_sts else "absent"
    else:
        dmarc_s = spf_s = dkim_s = mta_s = "unknown (dns not captured)"
    parts = [f"scope: {ap.slug}.example"]
    parts.append(f"mail: {ap.mail_provider_cat}")
    parts.append(f"dmarc: {dmarc_s} (weak={ap.dmarc_weak})")
    parts.append(f"spf: {spf_s}")
    parts.append(f"dkim: {dkim_s}")
    parts.append(f"dnssec: {('present' if ap.dnssec else 'absent') if ap.dns_available else 'unknown (dns not captured)'}")
    parts.append(f"mta-sts: {mta_s}")
    if ap.saas_footprint:
        parts.append(f"saas-footprint: {', '.join(sorted(set(ap.saas_footprint))[:6])}")
    if ap.verify_tokens:
        parts.append(f"verification-tokens: {', '.join(sorted(set(ap.verify_tokens))[:4])}")
    cdns = ", ".join(f"{k} x{v}" for k, v in ap.cdns.most_common(3)) or "none"
    servers = ", ".join(f"{k} x{v}" for k, v in ap.servers.most_common(3)) or "none"
    parts.append(f"edge: {cdns}")
    parts.append(f"origin: {servers}")
    parts.append(f"hosts-in-scope: {ap.total_hosts}")
    top = [t for t, c in ap.all_findings.most_common(10) if t in ARCH_SIGNAL_TYPES][:6]
    parts.append("arch-signals: " + ", ".join(top))
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Corpus-wide baselines: present for ~every target, so they are poor
# discriminators. Kept in the derived set but not allowed to *headline* a
# company when a stack-specific vuln exists (the demo needs per-company signal).
# ---------------------------------------------------------------------------
BASELINE_VULNS = {"dnssec_missing", "mta_sts_missing", "caa_missing", "bimi_missing",
                  "dangling_verification_tokens"}


def pick_top(derived: list[dict]) -> dict:
    """Choose the headline derived vuln for the output label."""
    if not derived:
        return {"vuln": "none", "severity": "INFO", "reason": "no architecture-derived blind spot triggered."}
    for v in derived:
        if v["vuln"] not in BASELINE_VULNS:
            return v
    return derived[0]


def top_n_for_table(derived: list[dict], n: int = 3) -> list[dict]:
    """n most signal-bearing derived vulns: stack-specific first, baselines fill."""
    specific = [v for v in derived if v["vuln"] not in BASELINE_VULNS]
    baseline = [v for v in derived if v["vuln"] in BASELINE_VULNS]
    return (specific + baseline)[:n]


def format_output(top: dict) -> str:
    return f"{top['severity']}: {top['vuln']} — {top['reason']}"


def build_rows() -> list[dict]:
    rows = []
    for slug, subdir, industry in SELECTION:
        report = json.load(open(PROBE_OUT / subdir / "report.json"))
        ap = ArchProfile(slug, industry, report)
        derived = derive(ap)
        top = pick_top(derived)
        input_text = summarize_arch(ap)
        output_text = format_output(top)
        rows.append({
            "task": "severity",
            "instruction": "Given this company's architecture (mail/DNS/CDN/hosting posture), derive the likely vulnerability and assign a severity for THIS company's stack.",
            "input": input_text,
            "output": output_text,
            "provenance": {
                "source": "probe-report-arch",
                "target": f"{slug}.example",
                "observed_at": OBSERVED_AT,
                "class": "blind_spot",
            },
            "_derived": derived,
            "_industry": industry,
        })
    return rows


def md_table(rows: list[dict]) -> str:
    lines = [
        "# ARCH-MINE — architecture-derived vulnerability characterization",
        "",
        f"**{len(rows)} companies, zero scans.** Vulns derived purely from each target's"
        " existing probe architecture (DNS/mail/DMARC/DNSSEC, CDN/WAF, hosting origin,"
        " SaaS footprint, JS/config-leak signals). All targets de-identified to `*.example`.",
        "",
        "| target | industry (guess) | architecture signals | top derived vuln(s) | severity |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        ap_signal = r["input"].split("; ")
        # pick a compact set of architecture signals for the md column
        sig_bits = []
        for part in ap_signal:
            if part.startswith(("mail:", "dmarc:", "spf:", "dnssec:", "edge:", "origin:", "saas-footprint:", "arch-signals:")):
                sig_bits.append(part)
        sig = "; ".join(sig_bits[:4])
        derived = r["_derived"]
        top3 = ", ".join(f"{v['vuln']}({v['severity']})" for v in top_n_for_table(derived, 3)) or "none"
        sev = pick_top(derived)["severity"]
        lines.append(
            f"| `{r['provenance']['target']}` | {r['_industry']} | {sig} | {top3} | {sev} |"
        )
    lines.append("")
    lines.append("Generated by `data/arch_mine.py` — analysis only, no scanning.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    rows = build_rows()
    public_rows = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
    OUT_JSONL.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in public_rows) + "\n")
    OUT_MD.write_text(md_table(rows))
    print(f"wrote {len(rows)} rows -> {OUT_JSONL}")
    print(f"wrote table      -> {OUT_MD}")
    # quick severity distribution
    from collections import Counter
    print(Counter(pick_top(d["_derived"])["severity"] for d in rows))


if __name__ == "__main__":
    main()