# RUNLOG — task gbrain-3 (memory/brain.py, PLAN #3 spine)

Worker run log for the GBrain per-company findings brain. Source for the demo narrative.
Format: `UTC | ACTION | FILE(s) | RESULT/CHECK | DECISION/REASON`

| UTC | ACTION | FILE(s) | RESULT/CHECK | DECISION/REASON |
|---|---|---|---|---|
| 2026-09-27T20:40Z | Recon: explored worktree, Makefile, data contract, gbrain CLI | Makefile, data/example.pairs.jsonl, data/README.md | `gbrain --help` OK, v0.59.0.0; fixture = 6 pairs across 5 targets | Confirm gbrain available + pair row shape before building |
| 2026-09-27T20:42Z | Recon: verified remember/recall round-trip + `gbrain call recall` structured JSON + `forget_fact` | — | remember→recall works; entity canonicalized `target-01-example`; `call recall` returns facts[] JSON | Use `call recall` for structured recall, remember with --entity/--provenance |
| 2026-09-27T20:48Z | Recon: read probe report.json shape from ~/probe/out | ~/probe/out/peaksecurity-deep/report.json | scan = {scope, generated, probe[]:{host, findings[{type,severity,detail,location}]}} | ingest must accept probe report.json + pairs JSONL |
| 2026-09-27T20:55Z | Built memory/brain.py v1 | memory/brain.py | module + CLI + self-test written | ingest/recall/--self-test; de-identify hosts to *.example |
| 2026-09-27T20:58Z | Ran self-test | memory/brain.py | `--self-test` PASS (6 facts -> recall 6) | first green; later runs regressed (see below) |
| 2026-09-27T20:59Z | Debug: re-running self-test failed 5/6 then 3/6 | memory/brain.py | decreasing remembered counts | discovered gbrain `fact_withdrawn` guard: an explicitly-forgotten claim can never be re-remembered (fingerprint sha256 of normalized claim, per source+visibility). My remember→forget self-test burned the fixture claims |
| 2026-09-27T21:00Z | Debug: content/length isolation tests | — | found gbrain rejects facts ending `(MEDIUM, standard)` / `]…` / bare-`…`-tail patterns on LONG claims | truncation collision: `_fact_text` truncation cut into shared detail, so format variants shared fingerprints; switched to `| severity=…, class=…` suffix that survives truncation |
| 2026-09-27T21:05Z | Discovered PGLite lock holder | — | `gbrain serve --http 127.0.0.1:9877` (PID 83881) holds the brain; `gbrain recall`/`stats`/`query` fail with LiveServeLockError; `gbrain remember` + `gbrain call get_page` still work (persistence-IPC delegation) | reads blocked by a stray half-started serve (not listening on 9877); cannot kill shared process; module must degrade |
| 2026-09-27T21:08Z | Diagnosed `recall` not delegation-eligible | ~/.bun/.../persistence/ipc.ts | `recall` ∉ PERSISTENCE_IPC_OPERATIONS (only writes + get_page/fetch); reads open datastore directly → lock error | implemented ledger + write-seam verification fallback for locked reads |
| 2026-09-27T21:12Z | Rework: ledger + locked-mode recall + `forget` via string id | memory/brain.py | self-test PASS x4 consecutive (locked recall); fixture ingest 6/6; real-scan ingest 39/39; offline degrade path exits 0 | degraded recall = local brain-ledger.json + re-issue remember to verify fact ids while CLI recall is locked |
| 2026-09-27T21:14Z | Dedupe recall + ledger | memory/brain.py | recall dedupes by fact id; ledger dedupes by claim on append | scan reports repeat probe entries; clean demo output |
| 2026-09-27T21:16Z | Cleanup of test pollution | — | forgot ws-gbrain-demo.example (28 unique facts); ledger trimmed to 5 fixture companies | keep shared brain demo-clean; dbg/ws-gbrain-test entities left (no ledger, recall locked) |
| 2026-09-27T21:18Z | Final verification | memory/brain.py | `--self-test` PASS (locked), fixture ingest+recall OK, real scan ingest+recall OK, no-key degrade OK | all checks green |
| 2026-09-27T21:20Z | gbrain milestone facts + git push | memory/brain.py, memory/brain-ledger.json, RUNLOG.md, Makefile | `gbrain remember … --entity gbrain-3` (facts #368-370); committed `9c530ad` + pushed `hack/ws-gbrain` | coordinator standing order: frequent push + milestone facts |
| 2026-09-27T21:22Z | Final verification sweep | memory/brain.py | self-test PASS; fixture ingest 6/6; recall works (locked); --help OK; no-key degrade exit 0; `make selftest` (river+brain) PASS | task acceptance checks all green |
| 2026-09-27T21:24Z | Final milestone + push | RUNLOG.md | gbrain remember final; committed | ship state |

## Key decisions
- **Fact format**: `finding: <type> on <host> — <detail> | sev=<SEV>, class=<CLASS>`, capped at 128 chars, never ends with a bare `…` (avoids gbrain `fact_withdrawn`/fingerprint collisions).
- **De-identify**: hosts → `*.example` by default (matches data/README contract; `--no-deidentify` to keep real hostnames).
- **Entity** = company (scan scope / provenance.target); every fact carries provenance (probe report timestamp).
- **Lock resilience**: `remember` works under the stray serve (persistence-IPC); `recall` falls back to ledger + write-seam verification and labels output "verified through the write seam". Full live recall works once the serve is stopped.
- **Self-test**: unique per-run claims via `| run=<entity>` tail suffix + TTL 30m; no burn on re-runs; passes with no keys and no network.

## Blockers / handoff
- **`gbrain serve --http 127.0.0.1:9877` (PID 83881) holds the PGLite brain and is NOT listening on 9877** — it blocks ALL CLI reads (`recall`, `query`, `search`, `stats`) for every worker. Recommend the coordinator kill it to unblock live recall for the demo; my module works regardless (write-seam verification), but the demo reads look better live.
- Minor clutter remains under entities `dbg` and `ws-gbrain-test.example` (pre-ledger debug writes; no read path to enumerate while locked).