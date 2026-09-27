# Security suite — qm-oss.example

> Generated 2026-09-27T21:12:47Z by suite/build_suite.py (offline, no keys). Every company gets a different suite — generated from its own findings, not hand-tuned.

**Owned model:** none yet — severity rankings are the gold/fixture labels. Train a checkpoint (river/train.py --live) to personalize.
**Findings seen:** 10 (10 for this company, 6 standard / 4 blind_spot total).

## Standard checks (6 of 6 target)
The OWASP-style floor — every company's suite checks these.

1. **CRITICAL — exposed_env_file** (this company)
   - host: `app.qm-oss.example`
   - detail: /.env returns 200 with a live postgres connection string
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — unauth_api_200** (this company)
   - host: `api.qm-oss.example`
   - detail: run/execute endpoints return 200 unauth with task results
   - observed: 2026-09-27T21:12:43Z

3. **HIGH — graphql_introspection** (this company)
   - host: `graphql.qm-oss.example`
   - detail: /graphql introspection enabled - schema readable unauth
   - observed: 2026-09-27T21:12:43Z

4. **MEDIUM — verbose_error** (this company)
   - host: `api.qm-oss.example`
   - detail: fastify default error handler leaks a full stack trace with postgres query internals
   - observed: 2026-09-27T21:12:43Z

5. **MEDIUM — missing_xframe** (this company)
   - host: `console.qm-oss.example`
   - detail: no X-Frame-Options on the admin console - framable
   - observed: 2026-09-27T21:12:43Z

6. **MEDIUM — missing_hsts** (this company)
   - host: `app.qm-oss.example`
   - detail: no Strict-Transport-Security on the API host
   - observed: 2026-09-27T21:12:43Z

## Blind spots (4 of 4 target)
Stack-specific things teams miss — the rows that justify a custom model.

1. **HIGH — sandbox_escape_surface**
   - host: `sandbox.qm-oss.example`
   - detail: code-execution sandbox endpoint reachable unauth - escape primitive becomes host RCE
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — pg_backup_exposed**
   - host: `db.qm-oss.example`
   - detail: postgres dump route on the public API returns a full schema+data export
   - observed: 2026-09-27T21:12:43Z

3. **MEDIUM — js_hardcoded_api_key**
   - host: `cdn.qm-oss.example`
   - detail: hardcoded API key in the published web bundle
   - observed: 2026-09-27T21:12:43Z

4. **LOW — npm_package_leak**
   - host: `www.qm-oss.example`
   - detail: brand package on the registry references internal API URLs and a maintainer email
   - observed: 2026-09-27T21:12:43Z

## Memory (GBrain)
_No GBrain index yet (memory/brain.json). The suite compounds once the findings brain lands: recall across scans instead of resetting each run._

## How to read this suite
- Run the standard checks first — the floor applies to everyone.
- Spend budget on the top blind spots: severity is ranked CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Re-run `suite/build_suite.py --company qm-oss.example --input ...` after each scan to regenerate.
