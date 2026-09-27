# stack-references.md

Curated stack/surface references per scanned target, in the fastify/node TS family. Appended by the vuln workers; each block records the target's stack, key trust boundaries, and the blind spots that justify a custom severity model.

## qm

**Target:** YC's open-source multiplayer agent harness — org-scale agent runtime (Fastify/Node-TS headless core, Postgres sessions/memory when configured, per-scope sandboxes, Slack Bolt + web surfaces). Source `~/yc-hackathon/qm` @ b6abeaf; reviewed `2026-09-27` (see `SECURITY-ARCHITECTURE.md`, `data/vulns-qm.jsonl`).

**Stack:** Fastify 5 / Node 24 TS ESM core · Postgres (pg, pg-boss) · Docker-based per-scope sandboxes (local/e2b/modal/porter/smolmachines/aws/sprites/superserve backends) · Slack Bolt (socket-mode + HTTP events) · jose/signed capability tokens · zod/typebox · web UI via Lit/Vite portal.

**Posture model:** `dangerous | auto | strict` scope-composed enum + orthogonal `isolated | open` sharing. Defaults: `auto` posture (`config.ts:1040`), `isolated` sharing (`config.ts:1049`), security screen `off` (`config.ts:1058`), session store `memory` (`config.ts:1439`).

**Key trust boundaries:** capability-token API gate (live-person required for admin writes) · egress authz proxy (DNS re-resolve → connect to IP, fail-closed tokenless) · command-policy regex + approval gate on execute · LLM security screener (opt-in) · AES-256-GCM keychain at rest · portal-only actions (no agent route for admin grants/impersonation/approvals).

**Blind spots (stack-specific — the custom-model rows):**
- Local sandbox backend has **no egress enforcement** (`egressEnforcement:none`, no proxy URL) + `host.docker.internal:host-gateway` always on → Auto's private-network block doesn't hold on the local/dev path (`src/sandbox/local-sandbox.ts:343-358,280`).
- Strict posture has `denyPrivateNetworks=false`; session/always approval grants collapse the human gate (`src/security/security-posture.ts:18`).
- Proxy-env egress is advisory — raw TCP/DNS/SSH bypass (`src/sandbox/sandbox-env.ts:30-42`).
- 48h capability claims (memory.read/egress/credentials/grants) not re-validated per request; revocation ineffective (`src/auth/capability-token.ts:8`, `src/api/server.ts:235-249`).
- Historical-scope retention — removed members keep file/memory access to old channel scopes (`src/api/app-helpers.ts:375-401`).
- Ambient Slack solicited-turn membership TOCTOU; public channels unchecked at solicitation (`src/api/app-ambient.ts:179-203`).
- External memory providers `failOpen:true` by default — silent recall/capture loss (`src/memory/provider-config.ts:182`).

**Standard floor (OWASP-style rows):** default execute gate is a 5-rule regex denylist · source-auth routes with arbitrary principalId (`/v1/memory`, `/v1/connectors/token`, `/v1/principals/:id/deactivate`) · aud-less session-cap tokens · secret-masking exact-substring + unmasked background output · memory-backed default stores lose audit trail on restart · unverified `/slack/events` proxy · unscreened webhook payloads by default.

**Confirmed positives:** npm audit 0 vulns + min-release-age=7 cooldown; egress tokenless default deny; keychain AES-256-GCM with atomic once-grant claims; portal-only escalation walls hold.