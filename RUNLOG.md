# RUNLOG — ws-vuln-memorable

One row per action. Format: `UTC_TIMESTAMP | ACTION | FILE(s) | RESULT/CHECK | DECISION`.

| when (UTC) | action | files | result / check | decision |
|---|---|---|---|---|
| 2026-09-27T21:05:00Z | recon: workspace layout, git state, memorable install | ws dir, `memorable --version`, `memorable status` | memorable-cli 0.5.30 installed (`~/.nvm/.../memorable-cli`); consent unset (fail-closed), extraction not configured; local backend only | static review of installed bundle is possible |
| 2026-09-27T21:08:00Z | read reference doc + README + data contract | reference/memorable.md, memorable-cli README, data/README.md | ref doc claims: "prompt + allow-listed tool args only leave machine; transcript/session_id/emails/cwd/file contents never sent; embeddings server-side" | treat claims as hypotheses; verify against bundle |
| 2026-09-27T21:12:00Z | static review of bundled CLI (dist/cli.js) | memorable-cli/dist/cli.js | found redaction fn J8 (email/secret/token/hex rules), allowlist h2 (11 fields), per-field 4000-char cap, results reduced to exit_code/ok, corpus always "" | extraction payload minimization CONFIRMED good |
| 2026-09-27T21:16:00Z | static review: MCP server + consent + encryption + backends | dist/cli.js | 5 read-only MCP tools, unknown/write refused; consent unset=deny, disable=read-only, forget=deny; local AES-256-GCM (keychain/env/file); gbrain/QM rows plaintext JSONB (mZ strips NULs only) | architecture doc material |
| 2026-09-27T21:20:00Z | static review: hooks, traces, record_repos, repo_blocked, doctor surface | dist/cli.js | codex-capture hook writes ~/.memorable/traces pre-consent (gated only by MEMORABLE=0); server can flip record_repos; repo host/path de-identified (creds/localhost dropped); /v1/embed + /healthz endpoints | finding set drafted (F-MEM-01..12) |
| 2026-09-27T21:24:00Z | write deliverables | SECURITY-ARCHITECTURE.md, data/vulns-memorable.jsonl, stack-references.md | 12 findings F-MEM-01..12 (4 good, 8 findings); JSONL validated with node JSON.parse per line | commit + push |
| 2026-09-27T21:27:00Z | validate JSONL | data/vulns-memorable.jsonl | 12/12 rows parse (node + python), all de-identified with *.example, ids unique F-MEM-01..12, no live domains/emails | valid |
| 2026-09-27T21:28:00Z | gbrain remember milestone | gbrain 0.59.0.0 | fact #389, entity=memorable, provenance "hackathon 2026-09-27 ws-vuln-memorable static review" | remembered |
| 2026-09-27T21:29:00Z | commit + push | all | hack: vuln-memorable <summary> | done |