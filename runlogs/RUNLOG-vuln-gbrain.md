# RUNLOG — ws-vuln-gbrain

`UTC_TIMESTAMP | ACTION | FILE(s) | RESULT/CHECK | DECISION`

| UTC | action | file(s) | result/check | decision |
|---|---|---|---|---|
| 2026-09-27T21:00:00Z | started vuln-gbrain task; read data/README.md, BRIEF.md, PLAN.md, reference/gbrain-gstack.md | RUNLOG.md, data/README.md | contract confirmed (JSONL: instruction/input/output + provenance class standard\|blind_spot) | proceed; emit findings to data/vulns-gbrain.jsonl |
| 2026-09-27T21:05:00Z | static read of GBrain source: scope.ts, sql-query.ts, mcp/server.ts, http-transport.ts, serve-http.ts, company-brain/admission.ts, serve-http-grants.ts, config.ts, mcp-registration.ts, creds/vault.ts, tailscale.ts | /Users/peterolkhovets/yc-hackathon/gbrain/src/** | security model mapped (OAuth scope hierarchy, DCR ceilings, magic-link admin, bearer-hash tokens, source-scoped reads, SSRF guards) | architecture doc reflects observed code, not README claims |
| 2026-09-27T21:08:00Z | dependency scan package.json + bun.lock + websearch advisories | package.json, bun.lock | ip-address@10.1.0 nested (CVE-2026-42338 XSS, CVE-2026-69192 SSRF-guard) not collapsed by root override ^10.3.1; MCP SDK 1.29.0 patched for CVE-2026-25536 | F2 confirmed (low reachability); MCP SDK ok |
| 2026-09-27T21:10:00Z | confirmed insecure default: `gbrain auth create` without --scopes mints full access (read/write/admin) | src/commands/auth.ts:1162,125; src/mcp/http-transport.ts:285 | comment + runtime fallback both grant admin | F1 confirmed (high) |
| 2026-09-27T21:12:00Z | company-brain isolation check: existingBroadGrants counted but not gated at admission | src/core/company-brain/admission.ts:146-155,190 | preview returns count; admitCompanyBrain never blocks on it | F3 confirmed (high, multi-tenant break) |
| 2026-09-27T21:13:00Z | MCP-expose / funnel / DCR footgun + admin session lifetime + creds plaintext at rest + SSRF guard gaps | mcp-expose.ts:63,281; serve-http.ts:993-999,1414-1417; creds/vault.ts:214-268; mcp-registration.ts:23-98 | funnel+DCR-insecure = public self-registration; 7d admin cookie no idle timeout; vault plaintext 0600; SSRF guard hostname-string only | F4/F5/F6/F7 drafted |
| 2026-09-27T21:14:00Z | gbrain doctor | n/a | 0.59.0.0; DB-backed checks skipped (live serve holds PGLite lock PID 83881); filesystem checks OK | note in report: doctor ran, partially offline |
| 2026-09-27T21:15:00Z | wrote SECURITY-ARCHITECTURE.md + stack-references.md + data/vulns-gbrain.jsonl (8 findings) | SECURITY-ARCHITECTURE.md, stack-references.md, data/vulns-gbrain.jsonl | written | validate next |
| 2026-09-27T21:16:00Z | python3 JSONL validation | data/vulns-gbrain.jsonl | 8 rows; all lines parse; task/instruction/input/output/provenance present; class standard\|blind_spot; targets *.example; no real urls/emails (only npm paths/@versions) | valid |
| 2026-09-27T21:16:30Z | gbrain remember milestone + git add/commit/push | RUNLOG.md, SECURITY-ARCHITECTURE.md, stack-references.md, data/vulns-gbrain.jsonl | pushed hack/ws-vuln-gbrain | DONE envelope |
