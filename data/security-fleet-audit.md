# Security & Fleet-Ops Audit — customsecuritymodel

Auditor: research/security-fleet agent · run: 2026-09-27T21:21Z · read-only audit of repo + fleet + secrets + submission posture.
Deliverables: this file, `data/security-fleet-audit.jsonl` (12 findings). Runlog: `runlogs/RUNLOG-fleet.md`.

---

## (a) Secrets exposure — verdict: CLEAN in repo, loose at home-dir edges

- **`RIVER_API_KEY` / `OPENAI_API_KEY`:** no `.env` file exists anywhere inside the repo or any of its 18 worktrees. `RIVER_API_KEY` is read via `os.environ.get()` only (`river/train.py:137`, `river/infer.py:147`, `eval/harness.py:216`) and is named (never valued) in docs/runlogs. No `OPENAI_API_KEY` reference anywhere. **No hard-coded key, token, or 40+ entropy string found in any tracked file.**
- **`.gitignore` coverage:** `.env`, `out/`, `runs/`, `river/out/`, `data/out/`, `__pycache__/`, `*.pyc` ignored — and the same `.gitignore` is present in **every** worktree (verified per-dir). The sole pyc (`river/__pycache__/train.cpython-314.pyc`) is untracked and contains only the env-var *name*, not a value.
- **What a clone would expose:** 54 tracked files — code, `.md`, `data/*.jsonl` corpora. Scanned for real emails (0), real hosts (1 benign: `herokudns.com` inside an example finding), real keys (0). All corpora targets are `.example` (`target-0X.example`, `gbrain.example`, `qm-core.example`, `river-sdk.example`); ws-vuln-superset corpus uses `brand-0X/repo-0X`. `demo/telemetry.json` embeds local paths + OpenCode envelopes but no secrets.
- **Home-dir edges (outside repo, flagged):** `~/probe` (30G recon corpus incl. `superset-sh-deep-exploit-ports-nuclei/report.json`, real repo clones) is world-readable `755`. `PROBE_LLM_API_KEY` (60-char `vck_*`) lives in `~/.zshrc` (`644`) and is consumed by probe tooling in `~/.superset/worktrees/probe/clarity-uranium/*` — it is **not** committed to any repo, but is recoverable by any local user.

## (b) Branch hygiene

- **Unmerged work:** all hack branches are **0 commits ahead of main** (fully merged). No unmerged feature branch.
- **Uncommitted files:** `main` — `M demo/telemetry.json` (live-refreshed, committed moments later as `a2c8736`); `ws-vuln-qm` — `M RUNLOG.md`; `lightning-calculator` (`explore-repo-contents`) — `M river/train.py` (import alias change, no secret); `ws-vuln-superset` — **5 untracked files**: `RUNLOG.md`, `data/build_vulns.py`, `data/deidentify.py`, `data/vulns-superset.jsonl`, `data/vulns-superset.manifest.json` (232-row corpus, not yet committed).
- **Merge-conflict markers:** `<<<<<<< HEAD` / `=======` / `>>>>>>> hack/ws-vuln-qm` are **committed and pushed to origin/main** at line 1/312/339 of `stack-references.md` and line 1/324/429 of `SECURITY-ARCHITECTURE.md`. Introduced by merge commit `62ac9f0` (merge: vuln-qm), still present at `d817846`, `a2c8736`, and `origin/main`. The `hack/ws-vuln-qm` side contains the QM security review that was lost on the `HEAD` side (which kept the demo-oriented intro). **Files render broken for anyone cloning the repo.**
- **Unpushed commits:** main was 29 commits ahead of `origin/main` at session start; `a2c8736` (telemetry refresh) was pushed during the audit → main now `0` ahead. All hack branches pushed (4 of them lack an upstream tracking ref entirely: `hack/ws-arch-mine`, `hack/ws-gbrain`, `hack/ws-vuln-memorable`, `hack/ws-vuln-superset`).

## (c) Worktree exposure

- Repo root `~/customsecuritymodel` and research worktrees `~/research-*` are `755` (world-listable/readable) — normal for a single-user dev box but inconsistent with the fleet's threat claim.
- `~/.superset` is `700` (good); `~/.superset/worktrees/customsecuritymodel/*` are `755` (readable). `.git` files per worktree are normal.
- 14 Superset workspaces exist for the project (per `superset ws list`), all on disk; 13 hack ws + 2 scratch ws in `.superset/worktrees`.

## (d) GBrain store + memory

- `~/.gbrain`: `700` root, files `600`. Contents: PGLite DB (`brain.pglite`), `config.json` (engine/paths only), `content/` skillpack, `persistence/` (host/stdio/cli identity JSON with **credential hashes**), `audit/` snapshot. No API keys, no model keys; only an IPC secret + UUID tokens + SHA-256 credential hashes. `.gitignore` = `*`; **not a git repo** — no accidental commit exposure. `audit/skill-brain-first-snapshot.json` `violators: []`.
- `memory/brain-ledger.json` (tracked, committed) — per-company findings facts, all `.example` de-identified, fact_id 296+; no secrets. `memory/brain.py` is the per-company findings brain CLI. Uncommitted refresh exists in ws-gbrain (`M memory/brain-ledger.json`) — matches telemetry.

## (e) Submission posture

- **GitHub URL field (`SUBMISSION.md:13`) = `https://github.com/peterolkhov/customsecuritymodel` → confirmed `private: true`** via `gh api`. ✅ Correct posture for a hackathon submission being prepared for judges.
- **demo/telemetry.json claims vs reality:** verified per-ws — `vuln-superset uncommitted=5` ✓ (5 untracked), `vuln-qm uncommitted=1` ✓ (`M RUNLOG.md`), `gbrain uncommitted=1` ✓ (`M memory/brain-ledger.json`), `vuln-memorable uncommitted=1` ✓ (`?? RUNLOG.md`), others 0 ✓. Statuses match live `git status`. Cost figures are plausible (0.02–0.17 USD). **Telemetry is accurate.**
- **Demo/* uncommitted changes:** `demo/telemetry.json` refreshes continuously (committed as `a2c8736` mid-audit); `loss-full.*` and `loss.png` are committed.

## (f) Prioritized risk list

| ID | Sev | Risk | Concrete fix |
|---|---|---|---|
| F-FLT-01 | **P0** | Merge-conflict markers committed + pushed to origin/main in `stack-references.md` + `SECURITY-ARCHITECTURE.md`; the merged QM security review is half-lost | Manually resolve both files (reconcile HEAD intro + QM body), commit the fixed merge, force-push main; verify `grep -c '<<<<<'` = 0 |
| F-FLT-02 | **P0** | `hack/ws-vuln-superset` has 5 untracked files (232-row corpus) that exist only in the worktree — loss risk, and `data/vulns-superset.jsonl` must be verified clean before it can ever be committed | Commit + push the branch, run `data/deidentify.py` residue gate first; never add without the gate |
| F-FLT-03 | **P1** | `~/probe` 30G recon corpus world-readable (755) incl. real repo clones + real findings | `chmod 700 ~/probe` (or move under `~/.superset` which is already 700) |
| F-FLT-04 | **P1** | `PROBE_LLM_API_KEY` (live `vck_*` key) stored plaintext in `~/.zshrc` mode 644 — any local user can read it | `chmod 600 ~/.zshrc`; migrate key to macOS Keychain; never paste into repo/runlogs |
| F-FLT-05 | **P1** | 4 hack branches have no upstream tracking (`ws-arch-mine`, `ws-gbrain`, `ws-vuln-memorable`, `ws-vuln-superset`) — telemetry's `unpushed: "0"` is computed against a missing ref and could mask drift | `git push -u origin <branch>` per ws (or delete merged branches) |
| F-FLT-06 | **P2** | World-readable worktrees under `~/.superset/worktrees` (755) hold pre-merge branch state | Restrict worktree parent to 700 (matching `~/.superset`) |
| F-FLT-07 | **P2** | `~/.superset/config.json` holds plaintext access + refresh tokens (perms 600, so contained) — but token at rest in plaintext | Prefer encrypted storage (`auth-token.enc` exists for exactly this); rotate tokens |
| F-FLT-08 | **P2** | No automated secret-scan gate on commit (no pre-commit hook / CI secret scan) despite a secrets-sensitive repo | Add `git-secrets`/`gitleaks` pre-commit hook + a `make secretscan` target |
| F-FLT-09 | **P2** | `ws-vuln-superset/data/vulns-superset.jsonl` de-identification is only as good as one ad-hoc pass; findings reference real orgs' infra in `detail` fields | Extend `data/deidentify.py` residue regexes (covered infra hostnames) before any commit |
| F-FLT-10 | **P2** | `demo/telemetry.json` embeds absolute local paths + cost figures — fine for private repo, but if the repo were ever flipped public these become attacker recon | Keep repo private (already true); scrub absolute paths if making public |
| F-FLT-11 | **P2** | GBrain store credential hashes live at `~/.gbrain/persistence/*.json` — correct perms now, but no documented rotation | Document rotation in `setup/README.md`; confirm store excluded from backups |
| F-FLT-12 | **P2** | Main receives auto-commits from the fleet (telemetry refresh `a2c8736`) while other branches carry uncommitted edits — no cross-branch drift check | Run `tools/reconcile`-style branch-drift check after each fleet wave |

**Overall:** repo is **secret-clean**, submission GitHub URL is **private**, telemetry is **accurate**. Two P0s (committed merge markers; untracked 232-row corpus), two P1s (world-readable probe corpus + live key in 644 zshrc), rest P2 hygiene. Highest-value single fix: **resolve + push the committed merge conflict** — it is the only thing that makes the submitted repo visibly broken.