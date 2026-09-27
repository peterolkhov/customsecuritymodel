# Security suite — target-01.example

> Generated 2026-09-27T21:39:58Z by suite/build_suite.py (offline, no keys). Every company gets a different suite — generated from its own findings, not hand-tuned.

**Owned model:** river://c1f3375c-3877-488c-99f9-3660cb9b0a3d/sampler_weights/company-model-v1 (base Qwen/Qwen3.5-9B, 300 pairs)
Severity rankings below are attributed to this checkpoint.
**Findings seen:** 300 (300 for this company, 150 standard / 150 blind_spot total).

## Standard checks (5 of 5 target)
The OWASP-style floor — every company's suite checks these.

1. **CRITICAL — repo_secret_tree** (this company)
   - host: `target-01.example`
   - detail: high-confidence secret in tree: /Users/peterolkhovets/probe/out/agentmail-to-deep-exploit-ports-nuclei/repos/openclaw/extensions/slack/src/monitor/thirdparty-51.example:800:      token: "xoxb-test-tok
   - observed: 2026-09-08T03:28:00Z

2. **CRITICAL — payment_provider_secret_leak** (this company)
   - host: `api.target-01.example`
   - detail: Payment-provider SECRET key(s) embedded in client-side JS on api.target-01.example: square EAAAAeaWxvYw…. A live provider secret lets an attacker call the provider API as the merchant — issue refunds, move/drain balances, list stored payment methods, create checkouts — with no me...
   - observed: 2026-08-12T12:39:00Z

3. **CRITICAL — payment_price_tampering_scale** (this company)
   - host: `target-393.example`
   - detail: EXPANDED 2026-08-19: the Anor Cloud checkout trusts client-supplied pricePerHour with NO server-side validation across the entire boundary sweep. Server-authoritative quote (POST /api/v1/matching/price for B300/H100, quantity 1) = $0.676/hr minimum, but checkout accepts pricePerH...
   - observed: 2026-08-19T07:58:00Z

4. **CRITICAL — payment_checkout_bypass** (this company)
   - host: `en.target-01.example`
   - detail: Order endpoint /exec/front/order/Calculationcreate/ created an order WITHOUT payment (HTTP 200). The server allows creating orders without a completed checkout/payment intent — an attacker skips the payment step entirely. Response: '{"result":false,"code":422,"message":"fail vali...
   - observed: 2026-08-19T17:13:00Z

5. **CRITICAL — cross_tenant_idor** (this company)
   - host: `target-01.example`
   - detail: Cross-tenant IDOR via companyId parameter on ALL API endpoints. The Bezel platform is a multi-tenant SaaS where ALL API endpoints (/api/tiktok/creators, /api/tiktok/products, /api/tiktok/videos, /api/analyze/track-brand, /api/simulate/*, /api/optimize/email, etc.) accept a compan...
   - observed: 2026-08-04T06:08:00Z

## Blind spots (5 of 5 target)
Stack-specific things teams miss — the rows that justify a custom model.

1. **HIGH — server_action_csrf**
   - host: `zlg.target-01.example`
   - detail: thirdparty-77.example Server Action on /login executes with a CROSS-ORIGIN Origin (action id 60f61b994d0b09182fa6...): POST with Origin: https://evil.example returns 500 while same-origin returns 200. No Origin/CSRF check — a malicious page can submit this login/signup form cross...
   - observed: 2026-08-16T03:08:00Z

2. **HIGH — js_hardcoded_api_key**
   - host: `target-27.example`
   - detail: Hardcoded 40-char hex API key in JS bundle https://thirdparty-74.example/onsite/js/RYeEns/thirdparty-75.example?company_id=RYeEns: 497393c6a664... (context: ow.__klkey=window.__klkey||o,p||(window._thirdparty-76.example(["account",o]),p={changeid:)
   - observed: 2026-08-15T14:24:00Z

3. **HIGH — js_hardcoded_api_key**
   - host: `target-25.example`
   - detail: Hardcoded 40-char hex API key in JS bundle /thirdparty-80.example: 0b3826282d19... (context: c-pages-auth-password-tsx",923:"component---src-pages-online-vet-free-tsx",1410:)
   - observed: 2026-08-15T08:56:00Z

4. **HIGH — js_hardcoded_api_key**
   - host: `target-310.example`
   - detail: Hardcoded 40-char hex API key in JS bundle https://thirdparty-81.example/thirdparty-82.example: d4a6650d5b9a... (context: thirdparty-83.example"}}},{key:"version",get:function(){return{timestamp:1786548583330,sha:)
   - observed: 2026-08-13T05:30:00Z

5. **HIGH — js_hardcoded_api_key**
   - host: `target-30.example`
   - detail: Hardcoded 40-char hex API key in JS bundle https://target-09.example/assets/merchantportal_login/master/thirdparty-85.example: c8005b7df0c1... (context: ject:"merchantportal-login",version:"7.1.0",name:"merchantportal_login",git_sha:)
   - observed: 2026-08-12T12:30:00Z

## Memory (GBrain)
_No GBrain index yet (memory/brain.json). The suite compounds once the findings brain lands: recall across scans instead of resetting each run._

## How to read this suite
- Run the standard checks first — the floor applies to everyone.
- Spend budget on the top blind spots: severity is ranked CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Re-run `suite/build_suite.py --company target-01.example --input ...` after each scan to regenerate.
