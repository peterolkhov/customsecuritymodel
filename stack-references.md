# stack-references.md

Vendor/SDK references discovered during hacking hours. One block per stack piece.

## memorable

| field | value |
|---|---|
| vendor | Memorable — procedural memory for coding agents (memorable.sh, YC S27; founders @advaiytsane @nikhilk8754) |
| CLI | `memorable-cli` **0.5.30** (Node ≥20; `npm i -g memorable-cli` or `npx memorable-cli@latest`); `memorable --version` |
| pipeline | traces → workflow synthesis (deterministic, derived from trace, not model-written) → graph assembly (shared steps/prefixes compose; one agent's procedure recallable by all on the same store) → retrieval (exact → lexical → semantic, ~60 ms) |
| consent | fail-closed: `unset` = deny until `memorable enable`; `disable` = read-only; `forget` = deny (recall silenced); `prune` works in every mode; refusals logged to `~/.memorable/rejected.jsonl` |
| capture | hooks (Claude Code user-prompt consent-gated; codex-capture writes local traces pre-consent, `MEMORABLE=0` to disable) + `memorable record` / `ingest trace.json` / `backfill` from `~/.codex/sessions` + `~/.claude/projects` |
| extraction | one HTTPS call `POST {base}/v1/extract` (default worker domain, `MEMORABLE_API_URL` overridable) with `Bearer` workspace key + `x-memorable-client` header; payload = task_description (scrubbed, 200-char cap) + allow-listed tool args (11 fields: command/cmd/file_path/filePath/path/notebook_path/pattern/url/query/description/shell_id/bash_id, 4000-char cap each) + results reduced to exit_code/ok; corpus always empty; 30 s timeout |
| redaction | `J8()`: emails → `<email>`; `sk_/pa_/mk_/ghp_/gho_/xox*_/npm_` + 16+, `sk-` + 20+, `AKIA` → `<secret>`; key=value w/ keyword name + ≥12-char value → `<secret>`; ≥32-char mixed-case → `<token>`; ≥40-char hex → `<hex>`; home dir → `~` (gaps: F-MEM-05) |
| server-side | task title embedded server-side (`bge-m3`, 1024-d, Memorable's own CF account, no third-party); task line + steps stored in their Postgres (not E2E-encrypted; dashboard renders); embeddings deferred to gbrain provider when configured |
| backends | **local** (default, `~/.memorable/procedures.jsonl`, AES-256-GCM sealed, key from macOS keychain / `MEMORABLE_STORE_KEY` / `store.key` 0600) · **gbrain** (your gbrain DB via bun, soft-delete `delete_page`, 72 h) · **qm** (`memorable_procedures`/`memorable_mode`/`memorable_stats` JSONB tables, `MEMORABLE_DB_URL`/`DATABASE_URL`, per-scope consent `enable --scope`, org `ORG_ID`); gbrain/QM rows are NOT client-side sealed (F-MEM-10) |
| recall | `memorable recall "<task>"` (single vs chain, reciprocal-rank fusion; chain inserts missing dependencies and prints honest gaps); `show` (injection-safe render: ANSI/control-stripped, 4000/8000-char caps, data-not-instructions markers); semantic arm lazy/fail-soft with explicit CLI reporting |
| MCP | read-only stdio MCP server, 5 tools: `memorable_recall`, `memorable_show`, `memorable_list`, `memorable_status`, `memorable_explain_recall`; all `readOnlyHint`; write/capture/key/billing refused with a fixed human-terminal message |
| policy channel | server can flip `record_repos` (client sends repo `<host>/<path>`, creds/localhost stripped), `repo_blocked`, allowance `refused`/`allowance_exhausted` (exhausted ⇒ queued sessions dropped, not retried), `client_min_version`, notices |
| docs | memorable.sh/doc, memorable.sh/dash (keys under Account → "New key for an agent"), memorable.sh/dash/billing; `memorable doctor` / `eval` / `status` / `notices` for inspection |
| review | static review + findings: `SECURITY-ARCHITECTURE.md`, `data/vulns-memorable.jsonl` (12 rows, F-MEM-01…12) |

Security-relevant notes for the build:

- The scan→train→suite procedure can be recorded with `memorable record` and replayed — the side-quest beat; keep the procedure store **local** (`memorable init` default) or on the gbrain backend to stay on our side.
- `memorable enable` is required before anything is stored/sent; leave consent unset until the demo so nothing leaves the machine (F-MEM-02, F-MEM-09).
- Extraction sends only the scrubbed prompt line + allow-listed tool args; never paste a finding containing real hostnames/emails into a captured command — keep training data de-identified to `*.example` per `data/README.md` (F-MEM-01, F-MEM-05).
- `MEMORABLE_API_URL`/`MEMORABLE_API_KEY` override the endpoint wholesale; only point them at the real extraction service and never an `http://` value (F-MEM-08, F-MEM-11).
- The multi-agent shared store has no per-role ACL: any agent on the store (or MCP) reads every procedure — treat the store as team-readable, never project-secret (F-MEM-07).