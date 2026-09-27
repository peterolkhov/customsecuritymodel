# Security suite — pulsepath.example

> Generated 2026-09-27T21:13:38Z by suite/build_suite.py (offline, no keys). Every company gets a different suite — generated from its own findings, not hand-tuned.

**Owned model:** none yet — severity rankings are the gold/fixture labels. Train a checkpoint (river/train.py --live) to personalize.
**Findings seen:** 12 (12 for this company, 7 standard / 5 blind_spot total).

## Standard checks (7 of 7 target)
The OWASP-style floor — every company's suite checks these.

1. **HIGH — subdomain_takeover** (this company)
   - host: `staging.pulsepath.example`
   - detail: CNAME points to a deprovisioned load balancer that no longer resolves - dangling DNS, takeover candidate
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — oauth_grant_type_abuse** (this company)
   - host: `auth.pulsepath.example`
   - detail: /token accepts grant_type=password (ROPC enabled - bypasses MFA and login rate-limiting)
   - observed: 2026-09-27T21:12:43Z

3. **HIGH — graphql_introspection** (this company)
   - host: `api.pulsepath.example`
   - detail: /api/graphql introspection enabled in prod - full schema readable
   - observed: 2026-09-27T21:12:43Z

4. **HIGH — grafana_exposed** (this company)
   - host: `grafana.pulsepath.example`
   - detail: Grafana /api/search is anonymous - dashboards readable without auth
   - observed: 2026-09-27T21:12:43Z

5. **HIGH — dangling_dns_record** (this company)
   - host: `capture.pulsepath.example`
   - detail: CNAME serves a cert for a vendor static-hosting product - IP reclaimable
   - observed: 2026-09-27T21:12:43Z

6. **MEDIUM — missing_hsts** (this company)
   - host: `app.pulsepath.example`
   - detail: no Strict-Transport-Security across the patient-facing hosts
   - observed: 2026-09-27T21:12:43Z

7. **MEDIUM — exposed_config** (this company)
   - host: `api.pulsepath.example`
   - detail: /actuator/env exposed (HTTP 200, 250KB of environment/config)
   - observed: 2026-09-27T21:12:43Z

## Blind spots (5 of 5 target)
Stack-specific things teams miss — the rows that justify a custom model.

1. **HIGH — unauth_api_200**
   - host: `api.pulsepath.example`
   - detail: /api/keys returns 200 unauth
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — cors_reflective**
   - host: `api.pulsepath.example`
   - detail: reflects arbitrary Origin with Allow-Credentials:true - PHI exfil primitive for a health stack
   - observed: 2026-09-27T21:12:43Z

3. **MEDIUM — js_api_surface**
   - host: `app.pulsepath.example`
   - detail: JS bundles reference checkout endpoints on a payment integration the passive enum never saw
   - observed: 2026-09-27T21:12:43Z

4. **MEDIUM — exposed_console**
   - host: `portal.pulsepath.example`
   - detail: /login present and reachable outside the auth boundary
   - observed: 2026-09-27T21:12:43Z

5. **LOW — exposed_swagger**
   - host: `api.pulsepath.example`
   - detail: /api-docs exposed (HTTP 200)
   - observed: 2026-09-27T21:12:43Z

## Memory (GBrain)
_No GBrain index yet (memory/brain.json). The suite compounds once the findings brain lands: recall across scans instead of resetting each run._

## How to read this suite
- Run the standard checks first — the floor applies to everyone.
- Spend budget on the top blind spots: severity is ranked CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Re-run `suite/build_suite.py --company pulsepath.example --input ...` after each scan to regenerate.
