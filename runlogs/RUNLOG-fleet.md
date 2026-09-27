# RUNLOG — customsecuritymodel (research/security-fleet)

One row per action: `UTC_TIMESTAMP | ACTION | FILE(s) | RESULT/CHECK | DECISION`.

| UTC timestamp | ACTION | FILE(s) | RESULT/CHECK | DECISION |
|---|---|---|---|---|
| 2026-09-27T21:14Z | recon: worktree list + branch map | (read-only) ~/customsecuritymodel, ~/.superset/worktrees/customsecuritymodel/* | 18 worktrees; main @ d817846; 13 hack ws, lightning-calculator, obvious-sunfish, 3 research-* | map base bf95c86 for research branches |
| 2026-09-27T21:15Z | git state: status per worktree | all ws-* | ws-vuln-qm `M RUNLOG.md`; ws-vuln-superset 5 untracked; lightning-calculator `M river/train.py`; main `M demo/telemetry.json` + `M memory/brain-ledger.json` (clean after a2c8736 push) | record uncommitted per ws |
| 2026-09-27T21:16Z | secrets sweep: .env / keys / gitignore | repo-wide | no .env anywhere in repo or worktrees; .gitignore covers .env/out/runs/*.pyc everywhere; RIVER_API_KEY = env-only; no hard-coded keys | repo clean of secrets |
| 2026-09-27T21:17Z | merge-conflict marker scan | stack-references.md, SECURITY-ARCHITECTURE.md | `<<<<<<< HEAD` at line 1 of BOTH files; `>>>>>>> hack/ws-vuln-qm` at 339/429; committed at 62ac9f0, d817846, a2c8736, AND origin/main | P0: markers committed+pushed |
| 2026-09-27T21:18Z | read demo/telemetry.json + SUBMISSION.md | demo/telemetry.json, SUBMISSION.md | telemetry claims vs reality: vuln-superset uncommitted=5 ✓, vuln-qm=1 ✓, gbrain=1 ✓; GitHub URL = peterolkhov/customsecuritymodel | verify repo privacy |
| 2026-09-27T21:19Z | GitHub repo visibility check | gh api repos/peterolkhov/customsecuritymodel | `private: true`, visibility=private | submission posture OK |
| 2026-09-27T21:20Z | GBrain store audit | ~/.gbrain | 700/600 perms, no API keys; only IPC secret + persistence credentials + UUID tokens; .gitignore=`*`; not a git repo; audit violators=[] | store hygiene OK |
| 2026-09-27T21:21Z | probe corpus exposure + PROBE_LLM_API_KEY | ~/probe, ~/.zshrc | 30G probe dir world-readable (755); PROBE_LLM_API_KEY (60-char vck_*) in ~/.zshrc 644, not committed anywhere in repo | P1 exposure |
| 2026-09-27T21:22Z | superset fleet ws list | superset ws list --project customsecuritymodel | 14 workspaces listed; 4 ws branches have NO upstream (ws-arch-mine, ws-gbrain, ws-vuln-memorable, ws-vuln-superset); all hack branches 0 ahead of main (merged) | branch hygiene notes |
| 2026-09-27T21:23Z | write audit | data/security-fleet-audit.md | full report written (6 sections + risk list) | commit |
| 2026-09-27T21:24Z | write findings JSONL | data/security-fleet-audit.jsonl | 12 vuln-contract rows, ids F-FLT-01..12, unique, de-identified | commit |
| 2026-09-27T21:25Z | verify + push milestone | runlogs/RUNLOG-fleet.md, data/* | JSONL valid, ids unique, no secrets in deliverables | git add -A + commit + push origin research/security-fleet |