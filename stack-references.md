# stack-references.md

Vendor/SDK references discovered during hacking hours. One block per stack piece.

## river

| field | value |
|---|---|
| vendor | River AI — fine-tune + RL open-weight models through one API (Igor Babuschkin) |
| SDK | `river-client` **0.12.0** (Python ≥3.12; `pip install river-client`) |
| transport | gRPC over TLS, default target `api.river.ai:443`, `use_ssl=True`; deployments/metrics via HTTPS |
| auth | single `rv_...` API key — gRPC metadata `x-api-key` + HTTP `Authorization: Bearer`; console keys: personal vs team (deployments require team key, gated/disabled by default) |
| capabilities | per-key: `client.get_capabilities()` returns only authorized models; `ServerCapabilities.require_model/require` fail closed |
| core loop | `Client.session(project=...)` → `create_model(base_model, lora=LoraConfig(rank=..))` → `forward_backward`/`optim_step` (or `train_step`) → `save_weights(name, mode="inference")` → `chat_complete_from_checkpoint` |
| checkpoint | `river://<run-id>/weights/<name>`; modes `training` (optimizer state) vs `inference` (PEFT adapters); TTL default 1 yr (server max); `immutable=True`, `expected_policy_id`, `training_data_attestation` (sha256 manifest) |
| serving | `create_deployment(checkpoint=..., wait=True)` → `Deployment.base_url` (OpenAI-compatible, stream) with the same key; queued `chat_complete_*` does not stream |
| retries | gRPC service-config maxAttempts 5, 0.5→8s, UNAVAILABLE only; submit wrapper UNAVAILABLE ≤1800s (1→8s backoff); HTTP deployments 9 attempts on 408/429/5xx w/ Retry-After; DEADLINE_EXCEEDED not retried on submit |
| timeouts | default op timeout 86 400s (1 d); heartbeat 2s cadence, transport tolerance 1800s, rejection 120s |
| images | `image_upload_concurrency=4` default; dedicated TLS channel per slot; 0700 sha256 content-addressed local cache |
| supply chain | tokenizers via HF: `AutoTokenizer.from_pretrained(..., trust_remote_code=True)` (hardcoded) + `hf_hub_download` (unpinned by default) — see SECURITY-ARCHITECTURE.md F-RIV-03/04 |
| weights custody | no download API in SDK; strong for control/tamper-evidence, weak for literal byte custody on River Cloud; on-prem = River Cluster (sales conversation) |
| docs | docs.river.ai (handbook; markdown available e.g. `/quickstart.md`), console.river.ai (keys/runs/deployments/usage), river.ai/changelog |
| review | static review + findings: `SECURITY-ARCHITECTURE.md`, `data/vulns-river.jsonl` (12 rows, F-RIV-01…12) |

Security-relevant notes for the build:

- `river/train.py --live` needs `RIVER_API_KEY` + `RIVER_BASE_MODEL`; use the smallest model `get_capabilities()` returns (`_pick_base`) for the fastest checkpoint.
- Keep `use_ssl=True` and never set `RIVER_CONSOLE_URL` to an `http://` or untrusted value (F-RIV-02, F-RIV-10).
- Training data must be de-identified to `*.example` before upload (data/README.md contract) — at-rest/training-time custody is River's, not the company's (F-RIV-07).
- Pin tokenizer revisions / use `local_files_only` for sealed runs to avoid unpinned HF drift (F-RIV-04).