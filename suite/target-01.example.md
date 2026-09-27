# Security suite — target-01.example

> Generated 2026-09-27T21:50:40Z by suite/build_suite.py (offline, no keys). Every company gets a different suite — generated from its own findings, not hand-tuned.

**Owned model:** none yet — severity rankings are the gold/fixture labels. Train a checkpoint (river/train.py --live) to personalize.
**Findings seen:** 6 (2 for this company, 4 standard / 2 blind_spot total).

## Standard checks (4 of 5 target)
The OWASP-style floor — every company's suite checks these.

1. **LOW — missing_security_headers** (this company)
   - host: `app.target-01.example`
   - detail: X-Frame-Options and CSP absent on the marketing pages
   - observed: 2026-09-27T00:00:00Z

2. **INFO — tls_cert_expiry** (this company)
   - host: `api.target-01.example`
   - detail: certificate expires in 11 days, auto-renew via LE confirmed
   - observed: 2026-09-27T00:00:00Z

3. **CRITICAL — exposed_env_file** (shared floor)
   - host: `static.target-02.example`
   - detail: /.env returns 200 with DATABASE_URL containing a live postgres password
   - observed: 2026-09-27T00:00:00Z

4. **MEDIUM — verbose_error** (shared floor)
   - host: `billing.target-03.example`
   - detail: stack trace leaks Django ORM query with customer table names
   - observed: 2026-09-27T00:00:00Z

## Blind spots (0 of 5 target)
Stack-specific things teams miss — the rows that justify a custom model.

_No blind spots observed for this company yet._
The owned model will flag stack-specific misses as scans compound into the GBrain memory (second-scan beat).

## Memory (GBrain)
2 remembered fact(s) for target-01.example (memory/brain-ledger.json). Top by severity:
- **LOW** finding: missing_security_headers on app.target-01.example — X-Frame-Options and CSP absent on the ma… | sev=LOW, class=standard  _(probe-report 2026-09-27T00:00:00Z · fact #296)_
- **INFO** finding: tls_cert_expiry on api.target-01.example — certificate expires in 11 days, auto-renew via L… | sev=INFO, class=standard  _(probe-report 2026-09-27T00:00:00Z · fact #297)_

## How to read this suite
- Run the standard checks first — the floor applies to everyone.
- Spend budget on the top blind spots: severity is ranked CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Re-run `suite/build_suite.py --company target-01.example --input ...` after each scan to regenerate.
