<<<<<<< HEAD
# SECURITY-ARCHITECTURE.md — River AI client/server trust model

Static review of `river-client` **0.12.0** (Python SDK) + the documented server
contract (`docs.river.ai`, reference `petergraph/.../reference/river.md`).
Scope: trust model, API-key auth, capability scoping, session/model lifecycle,
checkpoint save/inference, deployment serving, and where "the company holds the
weights" actually holds. Findings in `data/vulns-river.jsonl` (row ids F-RIV-01
… F-RIV-12). All verdicts below are `CONFIRMED` (read directly from source) or
`SUSPECTED` (requires server-side or live verification we cannot do statically).

---

## 1. Trust model — API-key auth

River uses a **single long-lived bearer secret per principal**: the `rv_...`
API key minted in the console. It is the only credential the SDK holds.

- **gRPC path** (training, sampling, chat): the key rides as gRPC metadata
  `x-api-key` on every call — `river_client/client.py:4449-4454`:
  ```python
  return [("x-api-key", self._api_key), ("x-river-client", _CLIENT_IDENTIFIER)]
  ```
- **HTTP path** (deployments, metrics): `Authorization: Bearer <key>` —
  `client.py:4459-4463`, `metrics.py:278`.
- **Key handling in the SDK is clean**: the key is held only in
  `Client._api_key` / `RunMetricsLogger._api_key` (memory), never written to a
  config/log file, never formatted into an exception or `logger` call. A grep
  across every module (client, metrics, types, images, sampling, rl, renderers,
  tokenizers, skill) finds no log statement that includes the key or the
  metadata tuple that carries it. `health_check()` swallows exceptions and
  returns `False` (`client.py:4819-4835`), so error paths don't echo secrets.
  **CONFIRMED — good.**
- **Who the key is:** the console distinguishes personal vs team keys; the SDK
  sends the same key on both paths. There is no per-role key material (e.g.
  read-only infer vs train vs deploy) in the client — scoping is entirely
  server-side.

## 2. Per-key capability scoping

Capabilities are fetched at runtime and are **per-key**:

- `get_capabilities()` → `GetServerCapabilities` returns only the models that
  key can see (`client.py:4837-4864`); the reference doc says exactly this:
  *"Access is per-key — call `client.get_capabilities()` and pick from what it
  returns."*
- **Deployment creation is gated**: `create_deployment` is disabled by default
  and explicitly requires *"a team API key with that access; personal API keys
  cannot create deployments"* (`client.py:4955-4960`). The server rejects
  creation without team/model access.
- Training capacity, model access, and (per reference) credits are all
  per-account / per-key. The SDK never assumes a capability it didn't see
  advertised — `ServerCapabilities.require_model/require` fail closed
  (`types.py:19-38`).

**Assessment:** key → principal → capabilities is a sound one-key-per-identity
model. The weak edges are (a) one key = full blast radius for that principal
(a leaked personal key can train on any model it can see and spend credits);
(b) checkpoint cross-tenant isolation is asserted only on the server
(**SUSPECTED**, see F-RIV-06).

## 3. Transport & TLS

- Defaults are secure: `endpoint="api.river.ai"`, `port=443`, `use_ssl=True`
  (`client.py:4248-4257`). gRPC uses `grpc.secure_channel(target,
  ssl_channel_credentials())` (`client.py:4360-4364`); the deployments HTTP
  path uses `https://` via `_http_base_url` (`client.py:1106-1111`, `4456`).
- Both transports rely on the **system trust store** — no CA override or
  certificate pinning option on either path. Standard for a public SaaS SDK;
  means an attacker with a trusted-CA cert (or a hostile corporate MITM proxy)
  can observe the key + training data. **CONFIRMED** (default) / **SUSPECTED**
  acceptable-tradeoff.
- **Footgun:** `use_ssl=False` is a first-class option and silently produces
  `grpc.insecure_channel(...)` + `http://` URLs. Any caller flipping it (or
  mispointing `endpoint`/`port`) sends the API key and payload plaintext. There
  is no warning, no refusal when a non-local endpoint is paired with
  `use_ssl=False` (F-RIV-02). **CONFIRMED.**

## 4. Session / model lifecycle

- `Client.session(...)` returns a `SessionContext` context manager
  (`client.py:4575-4602`, `4137-4238`). `__enter__` calls `CreateSession`,
  then starts a **daemon heartbeat thread** (2 s cadence, RPC timeout 30 s,
  up to 3 attempts, backoff 0.5→2 s; `client.py:392-403`, `2499-2517`).
  `__exit__` always runs `_unload_all_models()` → `_stop_heartbeat()` →
  `_close_images()` (`client.py:4178-4238`), so GPU/weights/session state is
  released on scope exit.
- Heartbeat health gates long waits: transport failures tolerated 1800 s
  (matches the server's 30-min session-active window), hard rejections only
  120 s (`client.py:418-419`, `2477-2497`).
- `Model` objects are owned by the session; `create_model` sends a monotonic
  `model_seq_id`; every forward/backward/optim RPC carries a sequence number
  (`_next_seq_id()`), which is the client-side dedup hook for server-side
  ordering. **CONFIRMED.**
- Default operation timeout is **86 400 s (1 day)** (`client.py:464`) so a hung
  op looks "running" for a long time (F-RIV-11).

## 5. Checkpoint save / inference mode

- `Model.save_weights(name, mode="training"|"inference", ...)`
  (`client.py:2161-2212`):
  - `mode="training"` persists optimizer state (for continuation);
    `mode="inference"` persists **PEFT/LoRA adapters only** — no optimizer
    state, safe to serve.
  - `ttl` defaults to **1 year (server max)**; `immutable=True` and
    `expected_policy_id` are supported for policy-version pinning.
  - Name is scoped client-side to `f"{run_id}/{name}"` then sent verbatim as
    `path` in `SaveWeightsRequest` (`client.py:2197`, `3736-3781`).
- `Model.load_weights(checkpoint)` forwards the `river://` path verbatim in
  `LoadWeightsRequest` (`client.py:2214-2240`, `3783-3809`). **No client-side
  validation of the path** (empty, `..`, absolute, foreign run-id) — the server
  is the sole authority (F-RIV-05, F-RIV-06).
- **Weights never transit the client.** The checkpoint is a `river://` URI +
  step metadata (`types.py:415-427`); the SDK has **no weight-download API** —
  grep finds only save/load *references*. On River Cloud the bytes live in the
  vendor's object store, not the company's (F-RIV-07).

## 6. Deployment serving (OpenAI-compatible base_url)

- `create_deployment(checkpoint=...)` → `Deployment{base_url, model, ...}`
  (`client.py:4937-5012`, `types.py:368-396`). Gated/disabled by default;
  team key required; `Idempotency-Key` on non-GET requests; HTTP retries
  9 attempts on 408/429/5xx with jitter + `Retry-After` honor
  (`client.py:4890-4926`).
- Serving contract (reference `river.md:60-70`): point the **OpenAI** SDK at
  `base_url=deployment.base_url` with the **same River API key** in
  `Authorization`. So the served endpoint is authenticated, not a naked
  bearer URL — **SUSPECTED** (server must enforce key check on the served
  path; we can't verify from the SDK) (F-RIV-08).
- Streaming is not supported on the queued chat path
  (`chat_complete_from_checkpoint/from_training` raise on `stream=True`);
  streaming requires a deployment (`client.py:5258-5262`). So the OpenAI URL is
  the only streaming surface and is the one that needs the strictest access
  control.

## 7. "The company holds the weights" — strongest vs weakest

The product pitch ("the company holds the weights") has three readings; River's
support differs per reading:

| Claim | Strength | Evidence |
|---|---|---|
| Company controls the *adapter parameters* (their own training run, not a shared frontier call) | **Strong** | LoRA on the company's own de-identified pairs; checkpoint is `river://<run>/weights/<name>` with an inference-mode PEFT artifact (`client.py:2161-2212`); `immutable=True` / `expected_policy_id` / `TrainingDataAttestation` (sha256 source-artifact manifest, `client.py:2559-2607`) give the company a tamper-evident claim about *what was trained on*. |
| Company can *read* the weights / self-host them | **Weak on River Cloud** | No download API in the SDK; bytes are vendor-custodial in the cloud. Only the on-prem product (River Cluster, sales conversation per reference) or a served `base_url` puts them effectively in company custody. |
| Company's *data* stays private | **Medium** | Pairs must be de-identified client-side before upload (our `data/build_pairs.py` contract); in transit it's TLS; at rest + at training time it's River's custody and trust. `training_data_attestation` pins *source hashes*, not data confidentiality. |

**Net:** the strongest, defensible reading is "the company's custom model is a
dedicated artifact it owns, trained on its own data, immutable-versioned, and
deployed under its own key." The weakest is any literal "we have the bytes on
our hardware" claim while on River Cloud.

## 8. Static-review verdict summary

| ID | Area | Verdict | Severity |
|---|---|---|---|
| F-RIV-01 | API key never logged; error paths don't echo secrets | CONFIRMED (good) | INFO |
| F-RIV-02 | `use_ssl=False` plaintext downgrade footgun | CONFIRMED | MEDIUM |
| F-RIV-03 | `trust_remote_code=True` tokenizer load (RCE surface) | CONFIRMED | HIGH |
| F-RIV-04 | Unpinned `hf_hub_download` tokenizer fetch | CONFIRMED | MEDIUM |
| F-RIV-05 | Checkpoint name/path passed verbatim, no client validation | CONFIRMED | LOW |
| F-RIV-06 | Cross-tenant `river://` checkpoint isolation unverifiable client-side | SUSPECTED | HIGH |
| F-RIV-07 | "Company holds weights" — no download API on cloud | CONFIRMED | MEDIUM |
| F-RIV-08 | Deployment URL auth enforcement server-side | SUSPECTED | MEDIUM |
| F-RIV-09 | Retry may duplicate ops server-side (fresh request_id) | CONFIRMED | MEDIUM |
| F-RIV-10 | Metrics bearer key + `RIVER_CONSOLE_URL` override, no scheme check | CONFIRMED | MEDIUM |
| F-RIV-11 | 1-day default timeout + broad poll retries (credit burn) | CONFIRMED | LOW |
| F-RIV-12 | Bounded image-upload concurrency + 0700 integrity-checked cache | CONFIRMED (good) | INFO |

## 9. Findings → data/vulns-river.jsonl

Each finding is one JSONL row under the `data/README.md` contract
(`instruction` / `input` / `output` + `provenance{class, observed_at, source,
target}`, all hostnames/IPs/emails de-identified to `*.example`).

---

# GBrain Security Architecture

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
=======
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
>>>>>>> hack/ws-vuln-qm

---

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
