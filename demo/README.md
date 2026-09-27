# demo/ — assets for the 2-min Loom + table expo

Generated live during the hackathon. Point the demo at these.

| asset | what | where from |
|---|---|---|
| `loss-full.csv` / `loss-full.jsonl` / `loss.png` | every training loss tick | `river/out/*/log.jsonl` (loss_capture daemon) |
| `telemetry.json` | fleet snapshot — 9 agents, status, cost, commits, uncommitted | `fleet_tel.py` every 60s |
| `LOOM-SCRIPT.md` | the 2-min narrative | coordinator |
| `LOOM-NARRATIVE.md` | business copy for write-up | coordinator |
