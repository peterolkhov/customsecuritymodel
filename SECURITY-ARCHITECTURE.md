# QM — Security Architecture Review

Reviewer: customsecuritymodel / vuln-qm
Target: `~/yc-hackathon/qm` @ `b6abeaf` (2026-09-26), a Fastify/Node-TS headless core for a multiplayer org agent harness (per-scope sandboxes, Slack + web surfaces, Postgres when configured, memory-provider seam). Findings corpus: `data/vulns-qm.jsonl` (both `standard` and `blind_spot` classes).

---

## 1. Posture model (the ceilings)

Security posture is a scope-composed enum `dangerous | auto | strict` (`src/security/security-posture.ts:15-19`). Org sets a floor; child scopes can only tighten (`composeSecurityPosture`, `:37-40`). Sharing posture is orthogonal: `isolated | open` (`src/resolution/sharing-posture.ts`). These two axes ARE the security model.

| posture | `inboundScreening` | `toolApprovals` | `denyPrivateNetworks` | meaning |
|---|---|---|---|---|
| **Strict** | `off` | `all` | **`false`** | Every harness tool pauses for human approval. **No screening and NO private-network block** — the human gate is the only control (`:18`). |
| **Auto** (default, `config.ts:1040`) | `external` | `none` | `true` | Blocks private networks + screens external content. **No approval gate** on tool calls. |
| **Dangerous** | `off` | `none` | `false` | Full speed. Ceiling = identity + scope + grants + audit still apply (`:16`). |

Key structural facts:

- **Auto is the default and it approves nothing and screens almost nothing.** `SECURITY_SCREEN_BACKEND` defaults to `off` (`config.ts:1058`), so the `external` screening flag is forced back to `off` at resolution (`resolution-service.ts:86-89`) unless an operator flips the env. Net effect on a stock deployment: the only pre-execution gate between the model and `sandbox.run` is a 5-rule regex denylist (`src/policy/command-policy.ts:5-19`) evaluated by `authorizeExecution` (`src/tools/primitives.ts:536-572`).
- **Strict's ceiling is the approval grant, not per-call human consent.** Approvals can be granted "once / for the session / always" (`security-posture.ts:263`). A session/always grant collapses the per-call gate into a pre-declared decision, and because Strict has `denyPrivateNetworks:false`, a Strict turn with broad pre-grants reaches private networks exactly like Dangerous.
- **Command policy is a speed bump, explicitly.** SECURITY.md admits it is bypassable (obfuscation, encoding, write-then-execute). The floor rules only catch: `rm -r`, `git push --force`, destructive SQL, `mkfs`/fork bomb, and `curl | sh`.

### Sharing posture: Isolated vs Open

- **Isolated (default, `config.ts:1049`)** — a turn's memory/files/keychain are only its own scope. Cross-scope reads need grants.
- **Open** — a live, authenticated internal human's opted-in personal files/memory/skills can enter a shared conversation, provenance-labelled and audited (`src/resolution/sharing-access.ts:41-77`, `turn-context.ts:63-105`). Bounds: 200 files / 25 shared contexts from the 100 most recent sessions; binary files require explicit share. Open does NOT change approvals, egress, screening, or transcript audience. Keychain in Open only via a separate disposable computer destroyed at turn end (`SECURITY.md:86-102`).
- The hard boundary: external/ambient/non-live turns are forced back to `isolated` (`resolution-service.ts:90-92`).

### Per-scope sandbox + durable execute

- One sandbox container/machine per scope (`sandboxScopeName` in `src/sandbox/exec-sandbox-base.ts:22-28`; local backend `localContainerName`/`localVolumeName`, `src/sandbox/local-sandbox.ts:80-84`). Resident disk volume persists home; scratch computers are disposable per turn.
- `execute` runs inside that scope's sandbox; the sandbox is a **sensitive boundary** — it runs model-generated commands and holds usable credentials in plaintext (`SECURITY.md:59-62, 146-150`).
- Cross-scope resource access re-evaluates the target scope's own command policy + egress (`src/core/orchestrator/sandboxes.ts:426-471`).

### Memory-provider seams

`MEMORY_PROVIDER_CONFIG` → `src/memory/provider-config.ts`, `provider-router.ts`. `default` = QM's notebook (Postgres or memory); external providers (`mcp`, `memorable`) attach recall/capture. **External routes default to `failOpen: true`** (`provider-config.ts:182`) — a failing provider is silently skipped (recall returns `""`, capture returns 0) unless `failOpen:false` is set. GBrain/Memorable hook in here.

---

## 2. Threat surface

Actors: internal users, org admins, deployment operators, the model-driven agent, sandbox processes, surface plugins (Slack), model & browser providers, connected services. Assets: capability tokens, credentials, transcripts, memory, files, sandbox home, audit records, connected-system side effects.

Trust boundaries and the controls that hold them:

1. **Capability-token gate** — per-turn signed token (`actorId/scopeId/exp`, `CAPABILITY_TTL_MS` 60m, sandbox tokens 48h, `src/auth/capability-token.ts:7-8`). Callers re-check scope membership; admin routes additionally require a live-person token (`src/api/server.ts:58-70`).
2. **Egress authz proxy** — per-scope egress policy token; proxy resolves DNS itself and returns the **IP** to connect to (DNS-rebinding safe), blocks cloud metadata + loopback + RFC1918 when `denyPrivateNetworks` (and the backend actually enforces the proxy). Fail-closed default: wrong/missing token → `DENY_ALL` (`egress-authz-main.ts:141-143,246`).
3. **Command policy + approvals** — regex gate on `execute`/`background` (`primitives.ts:536-572, 1260-1262`).
4. **Security screening** — LLM classifier for external content (webhook bodies, tool results) when enabled; `decision ∈ {auto, strict}` (`security-posture.ts:153-170`).
5. **Keychain** — AES-256-GCM at rest (`connector-client-store.ts:71-77`), owner/audience/once-vs-standing grants, advisory-locked claims.
6. **Raw/self-auth routes** — blobs, git broker, webhooks, loop ingress each self-authenticate (`server.ts:553-558`).
7. **Published apps** — signed session cookies, `bypassAcl` only for public apps; capability links are bearer by design (`SECURITY.md:179-183`).

---

## 3. Where the "org-scale multi-agent" boundary can break

The product's selling point (many agents, many scopes, shared rooms, org memory, Open sharing, ambient Slack) is exactly where the security model gets thin. Highest-risk seams, ordered:

1. **Default-everything-fails-open at the network egress.** `Auto` promises private-network blocking, but enforcement only exists where the sandbox backend wires the egress proxy (`egressEnforcement: "domain"|"ip_port"`). The **local Docker backend has `egressEnforcement: "none"`** and no egress proxy URL at all (`local-sandbox.ts:343-358`), and `effectiveEgressEnforcement` degrades to `"none"` when signing/api wiring is absent (`sandbox.ts:43-48`). Local-sandbox also always adds `--add-host=host.docker.internal:host-gateway` (`local-sandbox.ts:280`). So on the dev/local path, a prompt-injected agent can reach the host's network namespace, LAN services, and cloud metadata (via NAT). This is the #1 place the boundary breaks in practice.
2. **Proxy-based egress is advisory for non-HTTP traffic.** `forceThroughProxyEnv` sets `HTTP(S)_PROXY` + `NO_PROXY=localhost,127.0.0.1,::1` (`sandbox-env.ts:30-42`). Anything that ignores proxy env (raw TCP, UDP, DNS, SSH, git-over-ssh, `--no-proxy` client overrides) bypasses the gate entirely. DNS exfil never touches the proxy.
3. **48h capability claims are not re-validated.** The token embeds `memory.read`, `egress` policy, `credentials` (broker slugs), and `grants` at mint time (`orchestrator.ts:1649-1811`). Each request re-checks only top-level scope membership (`server.ts:235-249`). A revoked grant, a changed egress policy, or a demoted admin keeps operating for up to 48h on the old token. In an org-scale system where roles change mid-day, that's a real revocation hole.
4. **Source-auth-only routes with no principal binding.** `/v1/memory` GET/PUT takes `principalId` from query/body with no actor binding (`surface.ts:615-645`, routes `:1418-1419`); `/v1/principals/:id/deactivate|reactivate` has no admin grant (`directory.ts:10-28,166-167`); `/v1/session-cap` mints an **aud-less** token (`surface.ts:696-707`) accepted by the control-plane gate's "either" branch (`server.ts:258-259`). Any component holding `CORE_SIGNING_SECRET` — or any deployment with `ALLOW_UNAUTHENTICATED_CORE=1` (`config.ts:1432`) — can read/overwrite any user's memory or disable any principal. This is the identity seam.
5. **Memory-provider fail-open default.** `failOpen: provider !== "default"` (`provider-config.ts:182`). On recall/capture/query errors the provider is silently skipped (`provider-router.ts:49-53,72-76,88-92`). Consequences: (a) silent memory-data loss during capture outages, (b) an attacker who can flap a memory provider (or the org's gbrain/Memorable endpoint) strips the model of its memory context without a visible error. Availability/compliance surface, not confidentiality.
6. **Historical-scope retention.** Viewer scopes are built from all sessions ever joined (`app-helpers.ts:375-401`), and file reads check scope ownership, not current membership (`app-sessions.ts:383-396`). A removed channel member keeps reading that channel's files. Org memory is also injected into every internal turn's recall scope by default (`memory/policy.ts:33`, `resolution-service.ts:50-53`).
7. **Ambient Slack TOCTOU.** The solicited asker is membership-verified at **spawn** (`app-ambient.ts:179-203`), and public-channel solicitation does no membership check at all; the run may execute after the asker left (`scope-membership.ts:100-107`). Plus the `/slack/events` proxy forwards unverified (its trust is that the loopback receiver does Slack signature checks — `slack-events.ts:24-69`).
8. **Secrets ride in-band.** Capability/source secrets in env, credential files delivered as base64 shell scripts over HTTP (`keychain.ts:1583-1612`), full `~/.aws`/`~/.ssh`/`~/.netrc` trees restored to `$HOME` by device-flow (`device-flow-persist.ts:558-657`), 7-day secret-drop bearer URLs posted into chat (`secret-drop.ts:239-255`). Every one of these is a documented design tradeoff, but each is a one-bug-away extraction primitive.

### Controls that held up (for the record)

- Egress authz re-resolves and connects to an **IP**, blocking DNS-rebinding; metadata/loopback always blocked; tokenless default is deny (`egress-authz-main.ts:102-124,141-143`).
- Keychain at rest is real AES-256-GCM with per-record IV + auth tag; grants are owner+audience+mode checked, once-grants claimed atomically (`keychain.ts:988-1018`).
- Portal-only actions (admin grants, impersonation, approval decisions) genuinely have no agent self-API route (`SECURITY.md:108-129`); admin write routes require a live-person token.
- `npm audit --omit=dev` → **0 vulnerabilities**; `min-release-age=7` cooldown in `.npmrc`, committed lockfiles, `npm ci` in CI.
- Webhook signature verification is `timingSafeEqual`, per-provider schemes with timestamp windows (`webhooks/verifiers.ts`).

---

## 4. Finding ledger

Full rows with file:line evidence in `data/vulns-qm.jsonl` (de-identified, `standard`/`blind_spot`). Summary:

| id | class | title | verdict |
|---|---|---|---|
| V1 | standard | Default posture runs all commands with only a 5-rule regex denylist (no approvals, screen off) | CONFIRMED |
| V2 | blind_spot | Local Docker sandbox: no egress enforcement, no private-network block, host-gateway always on | CONFIRMED |
| V3 | blind_spot | Strict posture has denyPrivateNetworks=false; session/always approval grants collapse the human gate | CONFIRMED |
| V4 | blind_spot | Proxy-env egress is advisory — non-HTTP/raw clients bypass | CONFIRMED |
| V5 | standard | Secret masking is exact-substring; background output unmasked; literal-in-command secrets stored in transcript/audit | CONFIRMED |
| V6 | standard | `/v1/memory` GET/PUT: source-auth, arbitrary principalId, no identity binding | CONFIRMED |
| V7 | standard | `/v1/principals/:id/deactivate|reactivate`: source-auth, no admin grant | CONFIRMED |
| V8 | standard | session-cap mints aud-less token accepted by control-plane gate; verifyCapabilityToken never checks aud centrally | CONFIRMED |
| V9 | blind_spot | Embedded capability claims (memory.read/egress/credentials/grants) not re-validated; 48h TTL, no revocation | CONFIRMED |
| V10 | blind_spot | Historical-scope retention: removed members keep file/memory access to old channel scopes | CONFIRMED |
| V11 | blind_spot | Ambient Slack solicited-turn membership TOCTOU; public channels unchecked at solicitation | CONFIRMED |
| V12 | blind_spot | Memory-provider failOpen default true for external providers — silent recall/capture failure | CONFIRMED |
| V13 | standard | Session/run/artifact/idempotency stores default to memory — audit trail + replay dedupe evaporate on restart | CONFIRMED |
| V14 | standard | `POST /v1/connectors/token` stores token for arbitrary body principalId (no identity binding) | CONFIRMED |
| V15 | blind_spot | Secret-drop: 7-day bearer URL in chat; channel drops auto-mint standing grants; burn-on-deny quirk | CONFIRMED |
| V16 | standard | `/slack/events` proxy forwards unverified requests to loopback receiver | CONFIRMED |
| V17 | standard | Webhook payloads reach the model unscreened by default (SECURITY_SCREEN_BACKEND=off) | CONFIRMED |
| V18 | INFO | npm audit clean; min-release-age=7; lockfile pinned; egress tokenless default deny | CONFIRMED (positive) |