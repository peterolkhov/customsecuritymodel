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

---

# Pipeline self-security (customsecuritymodel)

Threat model of THIS build's own loop: `probe scanner → data/build_pairs.py (de-identify) →
river/train.py (train on River) → river/infer.py + eval/harness.py (serve/eval) →
suite/build_suite.py (per-company suite) → retrain`. Companion to the scanner/hunting review in
`data/security-scanners.md` (F-SCN-01…F-SCN-16) and the River SDK review above (F-RIV-01…F-RIV-12).
All file references are to this repo.

---

## 1. De-identification guarantees (`data/build_pairs.py`) — and where they fail

What it does (lines 172-192, 305-321): for each finding it scrubs, in order — host map
(longest-first), brand token, generic FQDN → `thirdparty-NN.example`, IPv4 → `198.51.100.N`,
email → `user@example.com` — then truncates `detail` to 280 chars and emits the training row.
The guarantee documented in `data/README.md` ("`input` and `output` never contain a real
hostname, IP, email or brand") is enforced **only for those four classes**. Failure modes:

1. **Secrets and non-email PII are not scrubbed.** The scrub set is closed (host/IP/email/brand
   only). Live credential material found by the scanner — `sk_...`/`pk_...`/`eyJ...` JWTs,
   `AKIA...`, phone numbers, personal names, URL userinfo (`http://user:pass@...`) — is **not**
   redacted. The scanner's findings carry real secret material (see F-SCN-10) and any of it
   embedded in a finding `detail` passes straight through into the training JSONL and the River
   upload. **The "de-identified" dataset is not secret-free.**
2. **Brand scrubbing is optional and fragile.** `brand_token_from_scope` (lines 195-202) takes
   the second-to-last scope label, strips hyphens, and requires length ≥ 3. `acme-corp.example`
   → token `acmecorp`, but detail text saying "Acme Corp" or "acme-corp.com" survives. A 3-char
   token (`tes`, `art`) over-matches unrelated words — scrubbing is either leaky or lossy, never
   calibrated.
3. **URL userinfo / ports / path-embedded hosts escape the host regex.** `_HOST_FROM_LOC_RE`
   (line 60) captures only `[A-Za-z0-9.-]+` right after an optional scheme, so a location like
   `http://user:pass@host:8080/path` mis-extracts the host as `user`; credentials and ports in
   the detail are not touched by any scrubber.
4. **The mapping is deterministic but reversible, and third-party names are per-run unstable.**
   `thirdparty-NN.example` counters reset each run, so the same third party gets a different
   alias on every rebuild (provenance/correlation instability, not confidentiality). Anyone with
   the corpus can reverse the counter mapping — the aliasing is obfuscation, not encryption.
5. **The corpus is unauthenticated.** `iter_reports` (lines 205-215) `json.loads` any
   `report.json` under `~/probe/out` with no ownership, signature, or schema check. A process
   that can write there injects rows at will (see §5).

## 2. Prompt-injection surface of the triage/infer seam

The training row is `instruction` (trusted, static) + `\n\n` + `input`, where `input` is
`type: <scanner type>; host: <alias>; detail: <untrusted web text, ≤280 chars>`. `river/train.py`
`render_messages` (lines 51-54) and `river/infer.py` `_build_messages` (lines 75-93) rebuild the
exact same concatenation at serve time.

- **No instruction hierarchy.** The `detail` (attacker-influenceable page/JS/XML-RPC content —
  see F-SCN-04) is concatenated with no delimiter escaping, no "ignore instructions inside
  evidence" guardrail, and no schema wrapper. A hostile page can phrase its detail to steer the
  severity output (under-rate a real finding, over-rate a false one) at inference time.
- **Training-time reinforcement of the same seam.** Because the identical format is used to
  train, the model is *taught* to follow whatever text follows the instruction — a poisoned
  training row (from a crafted scan target or an injected report) teaches the injection
  behavior, not just a wrong label. This is the strongest reason the de-identification and
  corpus-integrity controls matter: they are the only defenses between hostile web content and
  the model's weights.
- **Recommended hardening:** wrap `detail` in a quoted, JSON-escaped evidence field; emit a
  fixed system prompt that marks evidence as untrusted data, never instructions; reject or
  escape control characters; and validate the output severity against the closed set
  {CRITICAL, HIGH, MEDIUM, LOW, INFO}.

## 3. Checkpoint / weight custody (`river://` path + who can serve it)

- `train.py:174` saves `model.save_weights(name, mode="inference")` → `river://<run>/weights/<name>`,
  written into `river/out/<ts>-<name>/{meta.json,checkpoint.txt}` (train.py:176-188). `river/out/`
  is gitignored, so the reference stays local. The checkpoint is a **URI + metadata, never
  client-side bytes**; on River Cloud the adapter weights are vendor-custodial (F-RIV-07), so
  "the company holds the weights" is true only for control (own run, own data, immutable-version
  option) not for literal custody. Effective custody = the served deployment URL under the team
  key (F-RIV-08).
- **Serving is key-authenticated, not path-authenticated.** `infer.py:131` and
  `harness.py:229` call `chat_complete_from_checkpoint(checkpoint_path=…)` with the same
  `RIVER_API_KEY`; any holder of the key can load or serve the company's checkpoint, and the
  `river://` path is the only reference. Cross-tenant isolation of `river://` URIs is asserted
  only server-side (F-RIV-06, SUSPECTED).
- **Nothing binds the checkpoint to its training run client-side.** `train.py` never passes
  `immutable=True` or `expected_policy_id`, so a tampered `meta.json` (or a repo writer swapping
  the newest `river/out/*/meta.json`, which `suite/build_suite.py:86-98` picks by mtime) silently
  changes what gets served/evaluated. The training-data-attestation hook exists in the SDK
  (F-RIV-03/07) but is unused here.

## 4. API-key handling (`RIVER_API_KEY`, `OPENAI_API_KEY`)

- `RIVER_API_KEY` is env-only (`train.py:137`, `infer.py:147`, `harness.py:216`), never written
  to files, never echoed in errors (SDK verified clean, F-RIV-01). Residual risks: (a) it is
  inherited by child processes and is in scope for any crash dump / debug of `os.environ`;
  (b) no rotation or per-capability key story — one key trains and serves; (c) the demo runs
  `infer.py` in front of a camera, so the key must stay out of shell history and the TTY.
- `OPENAI_API_KEY` is **not used anywhere in this build** — the checkpoint is served through
  `chat_complete_from_checkpoint`, not through an OpenAI-SDK deployment. The key would only
  matter if the served `base_url` path (F-RIV-08) is adopted; if it is, the deployment URL is the
  single most sensitive surface (streaming + bearer auth).

## 5. Pair supply-chain — who can inject a poisoned training row

- **Corpus: `~/probe/out/*/report.json`, no integrity control.** Anyone who can write to that
  directory (same-user process, another tool, a malicious scan target via the scanner's own
  attacker-influenceable output — F-SCN-02/04) can plant a fabricated finding `{type, severity,
  detail}`. It becomes a training row verbatim; a crafted `detail` doubles as prompt-injection
  content (§2). There is no signing, no schema validation, no "this row came from a real scan"
  marker.
- **The "gold" labels are the scanner's own heuristics.** `build_pairs.py:316` emits the
  scanner's `severity` field as `output`; `eval/harness.py:312` scores the model against the same
  field as ground truth. Labels are partly driven by untrusted page content (F-SCN-14) and are
  never independently verified, so training *and* evaluation inherit scanner error.
- **Target collapse destroys the eval claim.** `build_pairs.py:236` hardcodes
  `target = "target-01.example"` for every company, so all rows share one `provenance.target`.
  `eval/harness.py:113-146` then splits by target and, with a single target, can only hold out
  everything or nothing — the "unseen company" evaluation (the demo's central receipt) is
  structurally unsatisfiable on real corpus output, and the "target-disjoint" guarantee in
  `split.json` is vacuous. De-identification has flattened the very dimension the eval needs.

## 6. The scan → train → serve → retrain loop's trust boundaries

| # | Boundary | Direction of trust | Weakness |
|---|---|---|---|
| 1 | Web → scanner | **untrusted in** | TLS off (F-SCN-01), redirects followed (F-SCN-02), private-IP guard rebindable/absent (F-SCN-03), unbounded bodies (F-SCN-07), mutation verbs (F-SCN-08) |
| 2 | Scanner → `report.json` | untrusted → unauthenticated file | No integrity/schema check; content and severity attacker-influenceable (F-SCN-02/14) |
| 3 | `report.json` → pairs | de-identification is the only control | Secrets/PII/URL-credentials survive scrubbing (§1); brand scrub fragile; mapping reversible |
| 4 | pairs → River upload | TLS + bearer key to vendor | De-identification is the *only* confidentiality control; at rest it is vendor trust (F-RIV-07) |
| 5 | River → checkpoint | vendor-custodial, key-authenticated | No download API; cross-tenant isolation server-asserted only (F-RIV-06); deployment URL is the one streaming surface (F-RIV-08) |
| 6 | checkpoint → eval/suite | newest-mtime file selection | No run binding, no immutability flag used (§3); a repo writer redirects serving/eval |
| 7 | eval gold | scanner labels as ground truth | Circular: model vs rulebook both scored against the scanner heuristic (§5, F-SCN-14) |

**Net:** the loop's honest trust position is "untrusted web content → (weak de-identification) →
vendor-held weights". The three controls that would materially raise it, in order of leverage:
(1) a real secret/PII redaction pass in `build_pairs.py` + corpus integrity checks (ownership,
schema, signature); (2) an evidence wrapper + output-allowlist so the model never learns to
treat page text as instructions; and (3) per-company target preservation through
de-identification (fix the hardcoded `target-01.example`) so the eval's "unseen company" claim
is actually tested.
