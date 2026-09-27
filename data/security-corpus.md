# Probe-corpus security intel — what the owned model must learn

Mined by the corpus-research worker from `~/probe/out` (real probe runs, 2026-08/09). Rows shipped as `data/vulns-corpus.jsonl` (59 findings, all de-identified). This doc is the reasoning layer: what the corpus says, how severity is actually decided, and where the rulebook fails.

## 1. Corpus scale observed

27 reports sampled across fintech, insurtech, health, D2C, AI-SaaS, and OSS. 52,748 findings total in the sample:

| severity | count | share |
|---|---|---|
| CRITICAL | 84 | 0.2% |
| HIGH | 4,416 | 8.4% |
| MEDIUM | 12,365 | 23.4% |
| LOW | 7,027 | 13.3% |
| INFO | 28,856 | 54.7% |

212 distinct finding types in-sample. The parent corpus (857 reports with findings) is far larger — the sample is representative enough to drive blind-spot selection because the top-25 types hold across targets.

## 2. Vuln-class distribution

**By count** (the noise that drowns triage): `repo_secret_history` (11,660), `api_post_csrf` (4,157), `spa_catchall` (2,427), `tech_fingerprint` (2,270), `cdn_waf_detected` (2,068), `unauth_api_200` (1,620), `xss_sink_escaped` (1,402), `missing_csp` (1,335), `js_route_extraction` (1,323), `missing_xcontent` (1,201).

**By HIGH/CRITICAL count** (what actually matters): `unauth_api_200` (1,279 H), `js_hardcoded_api_key` (879 H), `broken_access_control` (302 H), `repo_dep_vuln` (250 H), `js_key_in_bundle` (200 H), `cloud_bucket_public` (133 H), `dangling_dns_record` (93 H), `consul_exposed` (87 H), `unauth_write_bypass` (81 H), `cors_reflective` (74 H), `payment_price_tampering` (69 H), `ssrf` (66 H), `oauth_dcr_open` (57 H), `cors_credentials_reflected` (51 CRITICAL).

Pattern: **the noisy types are missing-header/header-posture (LOW/INFO). The dangerous types are auth + secrets + payment + infra-mesh.** A count-ranked rulebook ranks the wrong things.

## 3. Severity-reasoning patterns extracted

What separates CRITICAL/HIGH from INFO for the SAME type, across 59 curated rows:

1. **Response body decides, not the 200.** `unauth_api_200` returning `{merchants:[...]}` on a payments API = HIGH; returning `{authenticated:false}` session-status = benign; returning 65B `{models:[],collections:[]}` on a public search = INFO; returning a 300KB SPA shell (catch-all route) = INFO. The rulebook says HIGH for every 200.
2. **Write asymmetry proves missing auth.** A 401 on sibling routes + 400/422/200 on the target route = auth guard absent, not "protected". `unauth_write_bypass` (81 H across corpus) is invisible to GET-only scanners.
3. **Provider-key semantics.** `js_hardcoded_api_key` = HIGH only if the key is a live-format secret (payment-provider SECRET, cloud API key). A `pk_test_`/`public-token-` publishable key in a bundle = LOW/MEDIUM (auth-provider test-mode, per design) — but still a blind-spot signal (dev instance in prod, provider+project leak).
4. **Reachability beats advisory.** `repo_dep_vuln` advisory HIGH is not the verdict: dev-only deps (babel, loader-utils, nodemon) with no attacker-controlled path = LOW. The `why` field in the corpus literally says "severity from the advisory is a starting point, not the verdict."
5. **Dangling = takeover only if the target is claimable.** CNAME to a deprovisioned ELB/CloudFront/Heroku = HIGH. A records serving a *different org's* cert on a reclaimable cloud IP = HIGH but is a different class (`dangling_dns_record` vs `subdomain_takeover`) — cert-subject is the proof.
6. **Stack-specific classes get raw severity.** `payment_provider_secret_leak` (live SECRET in client JS) = CRITICAL; `firebase_rtdb_open` (production DB readable) = CRITICAL; `cors_credentials_reflected` (Origin echo + credentials) = CRITICAL. These never appear in a generic rulebook.

## 4. Blind-spot taxonomy per stack

- **Fintech / BNPL / payment** (`target-01`, `target-04`, `target-06`): unauthenticated MCP `tools/list`+`tools/call` on API-docs hosts; open Firebase auth self-registration bypassing invite-only enrollment; payment-method IDOR on incrementing user IDs; invoice/receipt endpoints gated by tenant header, not auth; payment-provider SECRET in client JS; Wayback-archived payment surface hidden behind WAF; SPF-listed origin IP leaking the CDN origin.
- **Health / health-device** (`target-09`, `target-10`, `target-11`): Next.js `/_next/data/<buildId>/...json` middleware bypass (auth on /api but not data routes); weak-auth-provider config (no password complexity) readable unauthenticated; auth-provider posture leak (signup mode, OAuth client IDs, factors); production Firebase Realtime DB public read; Spring `/actuator/env` exposing env/DB vars; subdomain takeover on cardiac-device staging; dangling A records to reclaimable cloud IPs.
- **D2C / retail / marketplace** (`target-04`, `target-05`, `target-06`, `target-07`): live payment-provider SECRET in client JS; MCP exposing full cart→checkout→complete lifecycle unauth; GraphQL field-name validation oracle leaking schema with introspection off; Shopify storefront product-API as intel base; third-party checkout-as-a-service surface on staging; `__NEXT_DATA__` server-side secrets; Fastly/cloudflare dangling CNAMEs and A-record takeover across a wide subdomain estate.
- **AI-SaaS / infra / dev-tools** (`target-13`, `target-14`, `target-16`, `target-17`, `target-20`): unauth MCP across docs hosts (read-only tools = MEDIUM, exec/data tools = HIGH); service-registry (`consul/v1/agent/self`) exposed on prod+staging estates; unauth write-path on ops endpoints (400 vs 401 asymmetry); Prometheus `/metrics` (24B aggregate = INFO, 98KB full dump = MEDIUM); Git-history secrets in public repos (persist past "deletion"); open DCR OAuth registration with wildcard redirect URIs; full Swagger/ReDoc API docs (430KB) publicly mapped.
- **OSS / email-infra** (`target-21`, `target-22`): live third-party OAuth tokens + env-style API keys in git history (worst place to leak — every clone reads them); MCP docs servers unauth (read-only → MEDIUM).

## 5. Top 10 things the owned model must learn that the rulebook gets wrong

1. **The 200 is not the finding.** Read the body: size, fields, and whether the payload is data vs. a catch-all SPA shell vs. a designed-public empty collection. Same type, five different severities.
2. **Write-path 401-asymmetry detection.** When a route family returns 401 but one sibling returns 400/422/200 to an unauth write, the auth guard is missing — that is a HIGH, not a quirk.
3. **MCP severity is tool-catalog-driven.** Unauthenticated `tools/list`/`tools/call` = HIGH when tools touch data/exec/checkout, MEDIUM when read-only docs tools. The protocol alone is not a severity.
4. **Provider key semantics.** Live-format secrets (`sk_live_`-class, payment-provider SECRETs) in client JS = CRITICAL/HIGH. `pk_test_`/public tokens = LOW but still a stack signal (dev instance in prod). Don't blanket-HIGH every hardcoded string.
5. **Git history never forgets.** `repo_secret_history` is a permanent exposure regardless of later deletion; live-format values in OSS repos are HIGH, not INFO.
6. **Next.js and framework data routes.** `/_next/data/*`, `__NEXT_DATA__`, and `/_next/static` are leak channels a header/endpoint rulebook misses; auth on `/api` does not protect the data routes.
7. **Dangling-DNS is two classes.** CNAME-to-deprovisioned-provider (takeover) vs A-record-on-reclaimable-IP-serving-foreign-cert. Both HIGH; the remediation differs (delete CNAME vs release IP + delete record).
8. **Payment surfaces hide behind WAFs and archives.** Wayback-archived payment endpoints and CDN-origin leaks (SPF IP, origin-server) reveal a larger attack surface than the live scan sees.
9. **Infra mesh + OAuth plumbing.** `consul/agent/self`, `/actuator/*`, open DCR registration, and Firebase RTDB public-read are stack-specific and never in the OWASP floor — yet several are the CRITICALs of the corpus.
10. **Reachability, not advisory.** Vulnerable dependency = LOW when dev-only or unreachable with attacker input; the model must reason about the code path, not copy the CVE score.