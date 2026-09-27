# GBrain Security Architecture — trust model, threat surface, and where the company-brain claim can break

Target: `github.com/garrytan/gbrain` @ 0.59.0.0 (static analysis of the local checkout at
`~/yc-hackathon/gbrain`; no live attack). Findings contract: `data/vulns-gbrain.jsonl`.

---

## 1. What GBrain is

A Postgres-native personal/team knowledge brain with hybrid RAG. One binary, four routing axes:

- **engine** — where the DB lives: embedded **PGLite** (WASM Postgres, local file, zero-config,
  single-process lock) or **Supabase/Postgres** (remote, `DATABASE_URL`, pgvector).
- **brain** — which database (`host` = yours; team brains mounted via `gbrain mounts add`).
- **source** — which repository/slice inside the DB (`--source`, `.gbrain-source`, `GBRAIN_SOURCE`).
- **transport** — stdio (local pipe), legacy HTTP bearer (`gbrain serve --http`), OAuth HTTP
  (`gbrain serve --http` + MCP SDK auth router), and `gbrain mcp expose` (Tailscale tailnet or
  public Funnel).

Authorization is **OAuth-scope + source-scope + takes-holder**, applied at the application layer —
there is no row-level security / Postgres role isolation. Everything above the engine is one
process with full DB rights; all tenant separation is enforced in code (`src/core/scope.ts`,
`sourceScopeOpts` threaded through every read op, per-token `takes_holders` allow-lists).

---

## 2. Trust model

### 2.1 Actors

| actor | trusted? | capability |
|---|---|---|
| CLI operator (local shell) | **fully trusted** | runs as the OS user; `gbrain call` sets `remote:false`, bypasses remote-only restrictions |
| `gbrain serve` stdio MCP caller (a coding agent on the same host) | **semi-trusted, remote:true** | every op dispatchable; `takesHoldersAllowList` defaults to `['world']`; `--source-guard` opt-in fail-closed on ambiguous writes (`src/mcp/server.ts:288-345`) |
| HTTP MCP bearer-token client | **semi-trusted** | scoped by token row; NULL scopes → full `read write admin` (`src/mcp/http-transport.ts:285`) |
| OAuth client (`authorization_code`) | **least-trusted** | scope ceiling from grant; DCR self-registered clients capped at `read write` (authz-code) / `read` (client_credentials) (`src/core/scope.ts:63,70`); every authz-code flow needs owner approval in the admin UI |
| Admin UI session | **trusted owner** | bootstrap token → one-time magic-link nonce → 7-day `gbrain_admin` cookie |
| cwd `.env` files | **untrusted** | protected variables dropped + process re-runs from a quarantine dir (see SECURITY.md) |

### 2.2 Brain mounts and the "brain" axis

`brain` selects which DB. A mounted remote brain is reached through the operator's
`remote_mcp` config (an OAuth client to a remote gbrain server). Trust = TLS to that host +
whatever the remote server's grants enforce. Mounting is operator-initiated; there is no
auto-discovery, so the attack surface is limited to operator confusion / leaked credentials.

### 2.3 Source routing and per-company slices

Every page/take/chunk is stamped with a `source_id`. Reads route through `sourceScopeOpts(ctx)`
(`src/core/ops/contract.ts:382-398`, `src/mcp/dispatch.ts:480-527`): federated array → scalar →
refuse (`missing_source_scope` for remote callers without a grant). The "company brain" mode
(`src/core/company-brain/`) is exactly this: one brain, N sources (one per company), each
admitted under an immutable `company_brain` policy (`committedOnly`, `noPull`, `noEmbed`,
`noWriteback`, audience `internal`, `federated:false`). The **claim** is per-company isolation
on a shared brain.

### 2.4 MCP expose on Tailscale / Funnel

`gbrain mcp expose`:
- tailnet-only by default — TLS certs, MagicDNS, tailnet ACLs gate who can reach `:443`.
- `--funnel` publishes on the **public internet** via Tailscale Funnel. Protection falls back
  entirely to **gbrain's own auth** (OAuth/bearer + grants) — Tailscale ACLs no longer apply.
- `--enable-dcr` (a documented flag on the same command) switches on OAuth Dynamic Client
  Registration for that publicly-reachable server. (`src/commands/mcp-expose.ts:51-66,281,856,1009`)
- A `--no-tailscale` path exists for operators who publish the port themselves; the exposure is
  then whatever their own reverse proxy does.

### 2.5 PGLite local vs Supabase remote

- **PGLite** = single-file WASM Postgres. No network, no roles, no auth. Lock is a
  `native/locks` filesystem/ABI lock (single-writer). Data at rest is a plain file with the
  OS user's permissions. The OAuth/bearer layer is the *only* enforcement.
- **Supabase/Postgres** = real network Postgres. gbrain still does app-layer auth; it does
  **not** provision Postgres roles or RLS per client. `DATABASE_URL` embeds the full superuser
  DSN — anyone who obtains it owns the brain.

---

## 3. Threat surface

| surface | entry | mitigations in-tree |
|---|---|---|
| HTTP OAuth endpoints (`/authorize /token /register /revoke`) | network | scope hierarchy + DCR ceilings (`scope.ts:27-95`), PKCE, hash-only confidential creds, rate limits, owner-approval gate on authz-code |
| HTTP MCP bearer (`/mcp`) | network | sha-256-hashed tokens, pre/post-auth IP+token rate limits, 1MiB body cap, CORS default-deny, `mcp_request_log` (`http-transport.ts:250-555`) |
| Admin UI + API | network | bootstrap token (sha-256, timing-safe), single-use 5-min magic-link nonce, HttpOnly+SameSite=Strict+Secure cookie, in-memory sessions, rate-limited mint/redemption (`serve-http.ts:1194-1441`) |
| stdio MCP (local agent) | local pipe | remote:true posture, world-only takes default, source-guard, publish-gate fail-closed catalog |
| Connector/OAuth credential vault | local disk | 0600 file, atomic writes; **plaintext at rest** (`creds/vault.ts:214-268`) |
| Remote MCP connect | SSRF | hostname-string guards for link-local/metadata/loopback; token control-char rejection (`mcp-registration.ts:23-113`) |
| cwd `.env` | supply-chain | quarantine + drop protected vars (SECURITY.md) |
| Dependency tree | supply-chain | pinned/overridden CVE-relevant versions; OSV + Semgrep + gitleaks in CI |
| `tailscale` subprocess install | supply-chain | `curl | sh` of pinned URL (TOFU); argv-based invocations otherwise |

---

## 4. Where the "company brain" multi-tenant claim could break

The isolation boundary is **application-level only** (source_id + grant + takes-holder filters).
Five ways it leaks:

1. **Admission is advisory, not gating.** `checkCompanyBrainDestination` counts pre-existing
   broad grants (unscoped `read|admin` OAuth clients and stdio local writers whose
   `grant_ceiling->sourceIds` contains `*`) and reports the number in the preview —
   but `admitCompanyBrain` never refuses (`src/core/company-brain/admission.ts:146-155,190`).
   If *any* unscoped client or stdio writer already exists on the shared brain, company A's
   data is readable by it. The isolation is only as good as the operator's pre-existing grant
   hygiene.

2. **Legacy bearer tokens default to full access.** `gbrain auth create <name>` without
   `--scopes` mints `read write admin`, and a `NULL` scopes row at verify time grants admin
   (`src/commands/auth.ts:1162,125`; `src/mcp/http-transport.ts:285`). On a shared company
   brain, one careless mint = cross-tenant read+write.

3. **Unscoped legacy tokens widen to federated sources.** A legacy token with no operator-set
   `source_id` grant reads across the config's federated source set
   (`src/mcp/http-transport.ts:295-301,521-527`) — the exact inverse of the per-company slice.

4. **PGLite has no defense in depth.** Any process that can read the PGLite data dir (same OS
   user, backup, container escape) or attach stdio to the serve process bypasses every layer.
   There is no RLS, no encryption-at-rest for the DB file.

5. **Same-brain mixed schema is refused, but mixed tenants are not.** Admission refuses
   mixed-schema occupancy (`admission.ts:141-145`) yet happily co-connects company B onto a
   brain that already holds company A's source — everything rests on the read-path filters
   staying exhaustive (the `takes_list`/`query`/`search` `WHERE holder = ANY(...)` +
   `sourceScopeOpts` contract in `src/core/ops/contract.ts:382-398`). A regression there is a
   cross-tenant leak with no second boundary.

---

## 5. Findings summary (details + JSONL rows)

| id | finding | evidence | class | severity |
|---|---|---|---|---|
| F1 | `gbrain auth create` default = full `read write admin` token; NULL-scope token verifies as admin | `auth.ts:1162,125`; `http-transport.ts:285` | standard (insecure default) | high |
| F2 | `ip-address@10.1.0` nested copy ships vulnerable version (CVE-2026-42338 XSS, CVE-2026-69192 SSRF-guard) despite root override `^10.3.1`; override fails to collapse nested edge | `bun.lock` (nested `express-rate-limit@8.3.2` → `ip-address@10.1.0`) | standard (dependency) | low |
| F3 | Company-brain isolation advisory-only: `existingBroadGrants` counted, never blocks admission | `admission.ts:146-155,190` | blind_spot (multi-tenant authz gap) | high |
| F4 | `--funnel` (public internet) + `--enable-dcr[-insecure]` = self-service registration with owner-approval bypass for client_credentials | `mcp-expose.ts:63,281`; `serve-http.ts:993-999`; `oauth-provider.ts:370` | standard (exposure) | medium |
| F5 | Admin cookie 7-day lifetime, no idle timeout / re-auth for privileged admin mutations | `serve-http.ts:1414-1417,1428-1441` | standard (session mgmt) | medium |
| F6 | Connector credential vault plaintext at rest (0600 only, no encryption hook) | `creds/vault.ts:214-268` | standard (crypto) | medium |
| F7 | `gbrain connect` SSRF guard is hostname-string based: decimal/hex/trailing-dot IP forms and DNS-rebinding names bypass; `http:` to non-loopback is warn-only | `mcp-registration.ts:23-98` | blind_spot (SSRF guard gaps) | medium |
| F8 | Tailscale install path runs `curl -fsSL <url> | sh` (TOFU); no integrity check beyond TLS | `core/tailscale.ts:180-187` | blind_spot (supply chain) | low |

Strengths observed (not findings): timing-safe token compares, hashed bearer tokens, DCR
scope ceilings + owner-approval, publish-gate fail-closed catalogs, cwd-.env quarantine,
`--source-guard`, body caps, CORS default-deny, SSRF guards on link-local/metadata, and an
audit table per request. `gbrain doctor` runs on this machine (0.59.0.0; DB-backed checks
skipped because a live `gbrain serve` holds the PGLite lock).