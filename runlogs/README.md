# runlogs/ — per-worker run logs (demo narrative source)

One file per hackathon worker. Format: `UTC_TIMESTAMP | ACTION | FILE(s) | RESULT/CHECK | DECISION`.

| worker | branch | task | file |
|---|---|---|---|
| adapter | hack/ws-adapter | probe→pairs adapter | RUNLOG-adapter.md |
| gbrain | hack/ws-gbrain | per-company findings brain (gbrain CLI) | (committed from agent) |
| eval | hack/ws-eval | held-out harness + scoreboard | RUNLOG-eval.md |
| infer | hack/ws-infer | checkpoint infer CLI | RUNLOG-infer.md |
| suite | hack/ws-suite | per-company suite generator | RUNLOG-suite.md |
| stacks | hack/ws-stacks | 6 reference stacks + generated suites | RUNLOG-stacks.md |
| vuln-river | hack/ws-vuln-river | River security arch + 12 findings | RUNLOG-vuln-river.md |
| vuln-gbrain | hack/ws-vuln-gbrain | GBrain security arch + 8 findings | RUNLOG-vuln-gbrain.md |
| vuln-qm | hack/ws-vuln-qm | QM security arch + 18 findings | RUNLOG-vuln-qm.md |
| vuln-memorable | hack/ws-vuln-memorable | Memorable security arch + 12 findings | RUNLOG-vuln-memorable.md |
| arch-mine | hack/ws-arch-mine | 32 companies judged by architecture | RUNLOG-arch-mine.md |
| vuln-superset | hack/ws-vuln-superset | Superset security arch + 284 findings | RUNLOG-vuln-superset.md |
| checkpoint | hack/ws-checkpoint | wire owned river:// checkpoint into eval/infer/suite | RUNLOG-checkpoint.md |

Generated artifacts (loss curve, telemetry snapshots, etc.) live under `runlogs/artifacts/` when produced.
