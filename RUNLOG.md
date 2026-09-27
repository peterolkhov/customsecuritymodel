# RUNLOG — adapter-1 (PLAN #1: probe findings -> pairs adapter)

Worker: adapter-1 | branch: hack/ws-adapter | repo: peterolkhov/customsecuritymodel
Contract: data/README.md (JSONL row shape must equal data/example.pairs.jsonl).
All times UTC. Source for the demo narrative.

| UTC | ACTION | FILE(s) touched | RESULT/CHECK | DECISION/REASON |
|---|---|---|---|---|
| 2026-09-27T20:35Z | Recon corpus + contract | data/README.md, data/example.pairs.jsonl, river/train.py, Makefile | Read row contract (task/instruction/input/output + provenance{source,target,observed_at,class}); train.py load_pairs expects instruction/input/output | Format must be byte-identical to example.pairs.jsonl so train.py + eval can consume output unchanged |
| 2026-09-27T20:38Z | Inspect probe corpus | ~/probe/out/*/report.json | 1040 entries, 857 reports with findings; per-report keys scope/generated/subdomains/probe/repos/findings/deep{infra,hosts,findings}; findings = {type,severity,why,detail,location}; severities CRITICAL/HIGH/MEDIUM/LOW/INFO | Findings live in 5 sections: top-level `findings`, `probe[*].findings`, `deep.hosts[*].findings`, `deep.findings`, `repos.findings` — all must be flattened |
| 2026-09-27T20:44Z | Corpus stats | ~/probe/out | 560,348 findings seen across 857 reports; top types js_hardcoded_api_key(89k)/tech_fingerprint/spa_catchall/missing_csp/...; 353 distinct types | Defaults cap=300 rows for training budget; dedupe by (target,type,detail[:200]) |
| 2026-09-27T20:55Z | Write adapter | data/build_pairs.py | --help works; dry-run emits manifest; real build emits data/out/pairs.jsonl + manifest.json | De-ident: own hosts -> target-NN.example (scope=target-01, subdomains keep label), other hosts -> thirdparty-NN.example, IPs -> 198.51.100.x, emails -> user@example.com, brand token -> brand.example. Classify by coordinator-approved blind_spot tokens. Stamped observed_at from report `generated` (parsed to ISO Z). Fallback to example.pairs.jsonl if corpus empty |
| 2026-09-27T20:58Z | Makefile targets | Makefile | added `adapter` + `adapter-dry` targets; `make help` lists them | `make adapter` is the one-command path per PLAN (#1) |
| 2026-09-27T20:59Z | Dry run | data/out/manifest.json | corpus=probe-report, 300 rows (150 standard / 150 blind_spot), severities CRITICAL6/HIGH88/MEDIUM89/LOW50/INFO67, manifest valid JSON | Dry run must emit a valid manifest (task requirement); chose stratified 50/50 class split for demo balance |
| 2026-09-27T21:00Z | Real build | data/out/pairs.jsonl | 300 rows written; keys == example.pairs.jsonl; classes 150/150 | Real corpus present -> used ~/probe/out (NOT fallback). Fallback path exercised in code review only |
| 2026-09-27T21:02Z | Leak scan | data/out/pairs.jsonl | 0 real IPs, 0 real emails, 0 real hostnames (only reserved example.com + 280-char truncation mid-host artifacts like `hub.target...`) | README rule "input/output never contain a real hostname/IP/email/brand" satisfied; truncation artifacts remain de-identified |
| 2026-09-27T21:04Z | Cross-module check | river/train.py (read-only) | `river/train.py --pairs data/out/pairs.jsonl --dry-run` -> 300 pairs -> 38 batches, tok=hf, len 51/106/208 | Proves downstream trainer consumes adapter output unchanged |
| 2026-09-27T21:06Z | gbrain milestones | gbrain (fact #198, #200) | `gbrain init --pglite` ok; `gbrain serve --http` required for persistence owner; remember -> fact #198 (build), #200 (verify) | `--kind runlog` rejected by gbrain (only event/preference/commitment/belief/fact) -> used `--kind event`, entity adapter-1 |
| 2026-09-27T21:07Z | Write RUNLOG | RUNLOG.md | retroactive + current rows | Coordinator standing order #2: log every action with UTC/action/files/check/decision |
| 2026-09-27T21:08Z | Commit + push | all | `git add -A && git commit -m 'hack: adapter-1 ...' && git push -u origin HEAD` | Standing order #1: push after every milestone |

## Handoff / next steps

- Next worker: `river/train.py --pairs data/out/pairs.jsonl --live` (needs RIVER_API_KEY + RIVER_BASE_MODEL). 300 rows, both classes, real observed_at stamps.
- `data/out/manifest.json` = "what it learned" slide source (counts per class, distinct types per class, de-ident counts).
- Refinement backlog (time permitting): smarter brand de-ident (corpus has `Le Labo`-style brands not derivable from domain), longer detail cap option, cap=0 unlimited mode for eval-set builder.
- gbrain note: persistence owner requires `gbrain serve --http` running in background; `--kind runlog` invalid -> use `--kind event`.