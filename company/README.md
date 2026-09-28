# How a company uses it — `company/`

The company-facing CLI. A security engineer points it at their probe scan
`report.json` and gets three things: a severity model trained on *their* stack
(a River LoRA), a GBrain that remembers every scan, and a per-company security
suite. The orchestrator lives here (`company/run.py`); everything below is
offline by default.

## The 3-step loop

| step | command | does |
|---|---|---|
| **onboard** | `python3 company/run.py onboard --company acme --scan report.json [--train] [--name ckpt] [--max-rows N]` | first scan: de-id → pairs → LoRA → brain → suite |
| **update** | `python3 company/run.py update --company acme --scan report2.json [--train]` | every later scan: re-ingest memory + regenerate suite |
| **infer** | `python3 company/run.py infer --company acme --finding 'type: x; host: y; detail: z'` | paste a new finding → your owned model's severity |

One command does the whole first onboarding:

    python3 company/run.py onboard --company acme --scan path/to/report.json

## What happens under the hood

`onboard` runs the chain end-to-end; `update` runs the same chain but skips
training unless `--train`.

1. **Pairs** — `data/build_pairs.py` de-identifies the scan (hosts → `*.example`,
   IPs → `198.51.100.x`, emails → `user@example.com`, brands → `brand.example`)
   and stamps each finding `standard` vs `blind_spot`. Output:
   `company/out/<company>/pairs.jsonl` + `company/out/<company>/manifest.json`.
2. **Train** — `river/train.py` tokenizes those pairs into a LoRA run. Dry-run
   by default; live (`--train` + `RIVER_API_KEY`) writes
   `river/out/<ts>/checkpoint.txt` — the `river://` URI the company holds.
3. **Memory** — `memory/brain.py ingest <pairs.jsonl>` writes every finding into
   the company's GBrain (local mirror `memory/brain-local.jsonl` when `gbrain`
   is absent). Only the *de-identified pairs* ever reach the brain — never the
   raw scan.
4. **Suite** — `suite/build_suite.py --company <pseudonym> --input <pairs.jsonl>`
   emits `company/out/suites/<pseudonym>.md` (e.g. `company/out/suites/acme.example.md`):
   the standard OWASP floor + the stack-specific blind spots your model cares about.
   The pseudonym is a stable `<company>.example` slug so each company keeps its own
   suite and two companies never collide.
5. **Summary** — pairs count, severity split, checkpoint, brain facts, suite path.

## Offline vs live

Default is **offline**: `river/train.py --dry-run` prints token/batch stats
without touching the network, the GBrain sync is a local mirror, and the suite
reports "no owned model yet" (rankings are the gold/fixture labels). Nothing
needs a key.

To land a real checkpoint add `--train` plus env:

    RIVER_API_KEY=<key> RIVER_BASE_MODEL=Qwen/Qwen3.5-9B \
      python3 company/run.py onboard --company acme --scan report.json --train

Once `river/out/<ts>/checkpoint.txt` exists, `infer` and the suite
auto-discover it — severity rankings become the owned model's, and the marginal
inference cost is ~free.

## Worked example (no keys)

    make company-demo

runs `onboard` on `demo/fixtures/acme/report.json` (a fintech/payments
stack: PCI scope, checkout API, payment webhook, GraphQL admin). Expected shape:

    STEP 1/5 — pairs (de-identify scan -> training pairs)
    STEP 2/5 — train (dry-run offline; --train goes live via River)
    STEP 3/5 — brain (ingest de-identified pairs -> GBrain memory)
    STEP 4/5 — suite (generate per-company security suite)
    STEP 5/5 — summary
      company:   acme (de-identified as acme.example)
      pairs:     58  severity split: CRITICAL:6, HIGH:17, MEDIUM:18, LOW:12, INFO:5
      checkpoint:none — dry-run (no owned model yet)
      brain:     ingested 58 findings -> 113 facts (backend local)
      suite:     company/out/suites/acme.example.md

## Wiring it into CI / cron

Scan on a schedule and feed the latest report; memory + suite stay fresh. One
cron line:

    30 2 * * * python3 company/run.py update --company acme --scan /srv/scan/$(date +\%F).json

This is a hackathon single-machine flow — no k8s, no GPU needed. Training
compute is River's hosted API (`RIVER_API_KEY`), and the company holds the
resulting `river://` checkpoint URI; everything else is plain Python on one box.

The pitch (see `README.md`): every scanner checks the same OWASP floor
(standard vulns), so the differentiator is stack blind spots + compounding
memory. Your LoRA learns which findings matter *for your stack*; the GBrain
remembers across scans instead of resetting each run.