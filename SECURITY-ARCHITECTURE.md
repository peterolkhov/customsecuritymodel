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