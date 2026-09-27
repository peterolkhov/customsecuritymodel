# memory/ — GBrain findings brain (PLAN #3 spine)

`memory/brain.py` is the rules-required GBrain module. It ingests a probe scan
`report.json` (or a pairs-contract `.jsonl`), de-identifies every field, and
syncs the findings into GBrain under a per-company entity ontology so
`recall <company>` answers *"what do we know about this company"* across
scans. It is the memory layer the suite generator (`suite/build_suite.py`,
which reads `memory/brain.json`) compounds on.

```
python3 memory/brain.py --self-test                 # offline, zero keys/network
python3 memory/brain.py ingest <scan.json>          # probe report.json or pairs .jsonl
python3 memory/brain.py recall <company> [query]    # what do we know about <company>
python3 memory/brain.py recall --entity findings/<type>
python3 memory/brain.py recall --entity runs/<run_id>
python3 memory/brain.py status                      # backend + local-store health
```

## Entity ontology

Every fact is written to GBrain with `--entity` in one of three namespaces:

| entity | meaning | example | what `gbrain recall <entity>` answers |
|---|---|---|---|
| `targets/<pseudonym>` | the company rollup | `targets/target-01-example` | "what do we know about this company" — one `event` fact per finding, each carrying `sev=`, `class=`, `run=` |
| `findings/<type>` | cross-company per-type rollup | `findings/exposed-env-file` | "what do we know about this finding type" — one fact per (type, severity, class) bucket per scan, with `xN` host counts |
| `runs/<run_id>` | per-run provenance | `runs/run-20260731t075900` | "what did this scan capture" — one summary fact per company per run (n findings, standard/blind_spot, severity histogram) |

The `<pseudonym>` is `target-NN.example` (the pairs-contract shape): the
report's own scope → `target-01.example`, its subdomains keep their label
(`api.target-01.example`), anything else → `target-NN.example`.
`findings/<type>` names are the raw finding types (e.g. `exposed_env_file`).

**Canonicalization.** GBrain server-side slugifies entities per segment
(`targets/target-01.example` → `targets/target-01-example`,
`findings/exposed_env_file` → `findings/exposed-env-file`). `brain.py` applies
the same canonicalization locally so the JSONL mirror and live GBrain always
agree, and `recall` normalizes your input before matching — pass either form.

## Verified flags (gbrain 0.59.0.0)

The surface below was verified directly against the CLI before this module was
written:

- `gbrain remember '<text>' --entity <e> --kind event --provenance <p>` works.
  `--provenance` is **required**. Valid `--kind` values are
  `event | preference | commitment | belief | fact` — `runlog` is **invalid**.
  Default kind in this module is `event`.
- `gbrain recall <entity>` is **positional**; `--json` returns structured
  `{facts: [...]}`. `gbrain forget <fact-id>` withdraws a fact.
- `remember`/`forget` are persistence-IPC writes and succeed even while a live
  `gbrain serve` holds the PGLite brain; plain `recall` reads lock out with
  `LiveServeLockError` until the serve is stopped.
- `--ttl` accepts duration shorthand (`30m`, `12h`) or absolute ISO 8601.
- Remembering the exact same claim again returns the existing fact id
  (fingerprint dedup). A **withdrawn** claim can never be re-remembered — so
  re-ingests use a fresh `--run-id` rather than delete-then-recreate.

## Backends and the JSONL fallback

| backend | when | recall source |
|---|---|---|
| live GBrain | `gbrain` on PATH and `gbrain recall <entity> --json` succeeds | gbrain facts |
| local JSONL mirror | gbrain absent **or** recall locked by a live serve | `memory/brain-local.jsonl` |

The local mirror is written on **every** ingest (append-only, deduped by
entity+fact), so recall is deterministic even with zero GBrain availability.
`memory/brain.json` is a plain per-company index (findings, runs, fact counts)
that `suite/build_suite.py` already reads for the "Memory (GBrain)" section.
`--self-test` runs its live round-trip through whichever backend is reachable
and reports the mode.

## De-identification and the refuse guard

Scrubbing reuses `data/build_pairs.py` (the pairs-contract scrubber) for every
field of every fact:

- hosts → `*.example` (`target-NN.example` / `label.target-01.example` /
  `thirdparty-NN.example`), IPs → `198.51.100.x`, emails →
  `user@example.com`, brand tokens → the host mapping / `brand.example`.

After scrubbing, a **refuse guard** re-scans every fact and refuses to write
anything (exit 3, nothing persisted) if a real-looking identifier survived:

- a domain not in the reserved set (`*.example`, `example.{com,net,org,edu}`,
  `*.invalid`, `*.test`, `*.localhost`, `localhost`, `example`),
- an email not on `example.com`,
- an IP outside the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `198.18.0.0/15`, loopback).

`--no-deidentify` keeps real hostnames but the guard still refuses; only the
explicit `--allow-real` override (documented UNSAFE — real infra would reach
the shared brain) bypasses it. `--dry-run` builds and guard-checks without
writing anything.

## Files

| file | role |
|---|---|
| `memory/brain.py` | CLI: ingest / recall / status / --self-test |
| `memory/brain-local.jsonl` | local JSONL mirror (the fallback backend) |
| `memory/brain.json` | plain index consumed by `suite/build_suite.py` |
| `memory/README.md` | this module doc + ontology + verified flag notes |
| `runlogs/RUNLOG-gbrain2.md` | worker run log (adapter/worker gbrain2) |