# Security suite — northbridge.example

> Generated 2026-09-27T21:12:47Z by suite/build_suite.py (offline, no keys). Every company gets a different suite — generated from its own findings, not hand-tuned.

**Owned model:** none yet — severity rankings are the gold/fixture labels. Train a checkpoint (river/train.py --live) to personalize.
**Findings seen:** 10 (10 for this company, 6 standard / 4 blind_spot total).

## Standard checks (6 of 6 target)
The OWASP-style floor — every company's suite checks these.

1. **CRITICAL — hosting_ports_exposed** (this company)
   - host: `hosting.northbridge.example`
   - detail: hosting control panel exposed: 2087/WHM HTTPS plus 8443 - the TLS/DPI firewall only blocks 80/443
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — wildcard_dns_sinkhole** (this company)
   - host: `www.northbridge.example`
   - detail: wildcard A record points 20 sensitive labels (admin, adminer, api, backup, cpanel, database, db, dev...) at a sinkhole that 404s everything
   - observed: 2026-09-27T21:12:43Z

3. **HIGH — outdated_stack** (this company)
   - host: `www.northbridge.example`
   - detail: EOL components: PHP 8.2 (EOL Dec 2025, public CVEs)
   - observed: 2026-09-27T21:12:43Z

4. **MEDIUM — tls_expired** (this company)
   - host: `docs.northbridge.example`
   - detail: certificate expired on the docs subdomain
   - observed: 2026-09-27T21:12:43Z

5. **MEDIUM — missing_hsts** (this company)
   - host: `checkout.northbridge.example`
   - detail: no Strict-Transport-Security on storefront/checkout hosts
   - observed: 2026-09-27T21:12:43Z

6. **MEDIUM — dangling_dns_record** (this company)
   - host: `docs.northbridge.example`
   - detail: docs subdomain CNAME serves a cert for an unrelated control-panel product - IP is reclaimable, subdomain takeover candidate
   - observed: 2026-09-27T21:12:43Z

## Blind spots (4 of 5 target)
Stack-specific things teams miss — the rows that justify a custom model.

1. **HIGH — payment_provider_detected**
   - host: `www.northbridge.example`
   - detail: payment provider shopify detected - unlocks webhook forgery, price/plan tampering testing
   - observed: 2026-09-27T21:12:43Z

2. **MEDIUM — shopify_ucp_surface**
   - host: `www.northbridge.example`
   - detail: Shopify UCP surface present: /.well-known/ucp and /api/ucp/mcp expose 13 tools unauth incl checkout and order
   - observed: 2026-09-27T21:12:43Z

3. **MEDIUM — challenge_bypass_host_reveal**
   - host: `www.northbridge.example`
   - detail: headless-browser challenge bypass revealed in-scope backend API hosts the passive enum missed
   - observed: 2026-09-27T21:12:43Z

4. **LOW — origin_ptr_cross_root**
   - host: `www.northbridge.example`
   - detail: SPF origin IP reverse-resolves to a hosting vendor's root, differing from the storefront root - mail infra on a third-party root
   - observed: 2026-09-27T21:12:43Z

## Memory (GBrain)
_No GBrain index yet (memory/brain.json). The suite compounds once the findings brain lands: recall across scans instead of resetting each run._

## How to read this suite
- Run the standard checks first — the floor applies to everyone.
- Spend budget on the top blind spots: severity is ranked CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Re-run `suite/build_suite.py --company northbridge.example --input ...` after each scan to regenerate.
