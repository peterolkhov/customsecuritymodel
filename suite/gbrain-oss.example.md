# Security suite — gbrain-oss.example

> Generated 2026-09-27T21:12:47Z by suite/build_suite.py (offline, no keys). Every company gets a different suite — generated from its own findings, not hand-tuned.

**Owned model:** none yet — severity rankings are the gold/fixture labels. Train a checkpoint (river/train.py --live) to personalize.
**Findings seen:** 10 (10 for this company, 6 standard / 4 blind_spot total).

## Standard checks (6 of 6 target)
The OWASP-style floor — every company's suite checks these.

1. **CRITICAL — exposed_env_file** (this company)
   - host: `app.gbrain-oss.example`
   - detail: /.env returns 200 with DATABASE_URL containing a live postgres password
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — unauth_api_200** (this company)
   - host: `api.gbrain-oss.example`
   - detail: recall/search endpoints return 200 to anonymous GET with stored entity summaries
   - observed: 2026-09-27T21:12:43Z

3. **HIGH — mcp_tools_unauth** (this company)
   - host: `mcp.gbrain-oss.example`
   - detail: MCP tools/list at /mcp returns 200 unauth - any anonymous caller can enumerate and drive the server's tools
   - observed: 2026-09-27T21:12:43Z

4. **MEDIUM — missing_hsts** (this company)
   - host: `app.gbrain-oss.example`
   - detail: no Strict-Transport-Security on the server host
   - observed: 2026-09-27T21:12:43Z

5. **MEDIUM — exposed_console** (this company)
   - host: `console.gbrain-oss.example`
   - detail: admin console path present and serves 200 outside an auth boundary
   - observed: 2026-09-27T21:12:43Z

6. **MEDIUM — cors_permissive** (this company)
   - host: `api.gbrain-oss.example`
   - detail: ACAO:* with no allow-credentials - every origin can read tool responses
   - observed: 2026-09-27T21:12:43Z

## Blind spots (4 of 4 target)
Stack-specific things teams miss — the rows that justify a custom model.

1. **HIGH — pg_proxy_exposed**
   - host: `db.gbrain-oss.example`
   - detail: pglite HTTP/wire endpoint exposed publicly - direct database access without the API layer
   - observed: 2026-09-27T21:12:43Z

2. **HIGH — mcp_prompt_injection_surface**
   - host: `mcp.gbrain-oss.example`
   - detail: tool arguments accepted from untrusted user content with no instruction/content boundary - prompt-injection path into recall queries
   - observed: 2026-09-27T21:12:43Z

3. **MEDIUM — tool_schema_leak**
   - host: `mcp.gbrain-oss.example`
   - detail: MCP tool descriptions leak internal model names and memory namespace structure to anonymous clients
   - observed: 2026-09-27T21:12:43Z

4. **LOW — wellknown_oidc**
   - host: `app.gbrain-oss.example`
   - detail: /.well-known/openid-configuration present and readable
   - observed: 2026-09-27T21:12:43Z

## Memory (GBrain)
_No GBrain index yet (memory/brain.json). The suite compounds once the findings brain lands: recall across scans instead of resetting each run._

## How to read this suite
- Run the standard checks first — the floor applies to everyone.
- Spend budget on the top blind spots: severity is ranked CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Re-run `suite/build_suite.py --company gbrain-oss.example --input ...` after each scan to regenerate.
