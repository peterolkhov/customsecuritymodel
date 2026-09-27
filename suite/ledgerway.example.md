# Security suite — ledgerway.example

> Generated 2026-09-27T21:12:47Z by suite/build_suite.py (offline, no keys). Every company gets a different suite — generated from its own findings, not hand-tuned.

**Owned model:** none yet — severity rankings are the gold/fixture labels. Train a checkpoint (river/train.py --live) to personalize.
**Findings seen:** 11 (11 for this company, 6 standard / 5 blind_spot total).

## Standard checks (6 of 6 target)
The OWASP-style floor — every company's suite checks these.

1. **CRITICAL — js_hardcoded_api_key** (this company)
   - host: `cdn.ledgerway.example`
   - detail: hardcoded 40-char API key in production JS bundle for the merchant portal login page
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — unauth_api_200** (this company)
   - host: `api.ledgerway.example`
   - detail: /api/v1/merchants/recommended returns 200 unauth with a merchant + pricing JSON payload
   - observed: 2026-09-27T21:12:43Z

3. **HIGH — broken_access_control** (this company)
   - host: `api.ledgerway.example`
   - detail: 302-redirect-with-body on the auth boundary: 1 path returns a 3xx redirect to login but still emits its full 1.2KB page body
   - observed: 2026-09-27T21:12:43Z

4. **MEDIUM — missing_xframe** (this company)
   - host: `checkout.ledgerway.example`
   - detail: no X-Frame-Options and no CSP frame-ancestors on the checkout page - framable (clickjacking)
   - observed: 2026-09-27T21:12:43Z

5. **MEDIUM — missing_hsts** (this company)
   - host: `auth.ledgerway.example`
   - detail: no Strict-Transport-Security on the auth and checkout hosts
   - observed: 2026-09-27T21:12:43Z

6. **MEDIUM — csp_unsafe_https_script** (this company)
   - host: `app.ledgerway.example`
   - detail: CSP script-src allows unsafe-inline - no XSS mitigation from CSP
   - observed: 2026-09-27T21:12:43Z

## Blind spots (5 of 5 target)
Stack-specific things teams miss — the rows that justify a custom model.

1. **HIGH — mcp_tools_unauth**
   - host: `api.ledgerway.example`
   - detail: MCP tools/list at /mcp returns 200 unauth exposing 8 tools incl execute-request and get-server-variables
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — firebase_hosting_config_leak**
   - host: `app.ledgerway.example`
   - detail: /__/firebase/init.json returns the project's full web config to an anonymous GET
   - observed: 2026-09-27T21:12:43Z

3. **HIGH — clerk_dev_instance_in_prod**
   - host: `cdn.ledgerway.example`
   - detail: Clerk pk_test_ key shipped in the production merchant-portal bundle
   - observed: 2026-09-27T21:12:43Z

4. **MEDIUM — wayback_payment_surface**
   - host: `www.ledgerway.example`
   - detail: Wayback CDX shows 295 payment/API surface URLs hidden from the live probe by the WAF
   - observed: 2026-09-27T21:12:43Z

5. **MEDIUM — https_to_http_downgrade**
   - host: `checkout.ledgerway.example`
   - detail: HTTPS /checkout returns 307 to a plaintext HTTP download path - session downgrade on a commerce path
   - observed: 2026-09-27T21:12:43Z

## Memory (GBrain)
_No GBrain index yet (memory/brain.json). The suite compounds once the findings brain lands: recall across scans instead of resetting each run._

## How to read this suite
- Run the standard checks first — the floor applies to everyone.
- Spend budget on the top blind spots: severity is ranked CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Re-run `suite/build_suite.py --company ledgerway.example --input ...` after each scan to regenerate.
