# Security suite — river-sdk-oss.example

> Generated 2026-09-27T21:12:47Z by suite/build_suite.py (offline, no keys). Every company gets a different suite — generated from its own findings, not hand-tuned.

**Owned model:** none yet — severity rankings are the gold/fixture labels. Train a checkpoint (river/train.py --live) to personalize.
**Findings seen:** 10 (10 for this company, 6 standard / 4 blind_spot total).

## Standard checks (6 of 6 target)
The OWASP-style floor — every company's suite checks these.

1. **CRITICAL — exposed_env_file** (this company)
   - host: `train.river-sdk-oss.example`
   - detail: /.env returns 200 with RIVER_API_KEY and a base model identifier
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — unauth_api_200** (this company)
   - host: `api.river-sdk-oss.example`
   - detail: train/fine-tune endpoints return 200 to anonymous POST
   - observed: 2026-09-27T21:12:43Z

3. **MEDIUM — verbose_error** (this company)
   - host: `api.river-sdk-oss.example`
   - detail: error responses include full request headers and a stack trace
   - observed: 2026-09-27T21:12:43Z

4. **MEDIUM — tls_expired** (this company)
   - host: `api.river-sdk-oss.example`
   - detail: certificate expired on the API host
   - observed: 2026-09-27T21:12:43Z

5. **MEDIUM — missing_hsts** (this company)
   - host: `api.river-sdk-oss.example`
   - detail: no Strict-Transport-Security on the inference host
   - observed: 2026-09-27T21:12:43Z

6. **MEDIUM — cors_permissive** (this company)
   - host: `api.river-sdk-oss.example`
   - detail: ACAO:* - browser clients can read inference responses cross-origin
   - observed: 2026-09-27T21:12:43Z

## Blind spots (4 of 4 target)
Stack-specific things teams miss — the rows that justify a custom model.

1. **HIGH — grpc_reflection_exposed**
   - host: `grpc.river-sdk-oss.example`
   - detail: gRPC reflection service enabled unauth - full proto/service schema dump from the wire
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — api_key_leak_in_logs**
   - host: `api.river-sdk-oss.example`
   - detail: training request logging captures the full prompt and the caller's API key
   - observed: 2026-09-27T21:12:43Z

3. **MEDIUM — exposed_config**
   - host: `api.river-sdk-oss.example`
   - detail: config endpoint returns runtime settings incl model routing table
   - observed: 2026-09-27T21:12:43Z

4. **LOW — origin_server_leak**
   - host: `api.river-sdk-oss.example`
   - detail: response reveals the origin framework behind the gateway - forgotten legacy backend
   - observed: 2026-09-27T21:12:43Z

## Memory (GBrain)
_No GBrain index yet (memory/brain.json). The suite compounds once the findings brain lands: recall across scans instead of resetting each run._

## How to read this suite
- Run the standard checks first — the floor applies to everyone.
- Spend budget on the top blind spots: severity is ranked CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Re-run `suite/build_suite.py --company river-sdk-oss.example --input ...` after each scan to regenerate.
