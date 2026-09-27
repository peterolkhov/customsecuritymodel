# runlogs/ — per-worker run logs (demo narrative source)

One file per hackathon worker. Format: `UTC_TIMESTAMP | ACTION | FILE(s) | RESULT/CHECK | DECISION`.

| worker | branch | task | file |
|---|---|---|---|
| adapter | hack/ws-adapter | probe→pairs adapter | RUNLOG-adapter.md |
| eval | hack/ws-eval | held-out harness + scoreboard | RUNLOG-eval.md |
| infer | hack/ws-infer | checkpoint infer CLI | RUNLOG-infer.md |
| suite | hack/ws-suite | per-company suite generator | RUNLOG-suite.md |
| stacks | hack/ws-stacks | 6 reference stacks + generated suites | RUNLOG-stacks.md |
| vuln-river | hack/ws-vuln-river | River security arch + 12 findings | RUNLOG-vuln-river.md |
