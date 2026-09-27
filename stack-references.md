# stack-references.md

One-line stack summaries per external tool used in this build, for quick recall. Append-only.

---

## gbrain

**What:** Garry Tan's open-source memory/knowledge layer (`github.com/garrytan/gbrain`, MIT).
Explicit facts **with sources**, corrections/withdrawal, shared across agents. ~100 ops,
contract-first in `src/core/operations.ts`; memory verbs `recall` / `remember` / `entity` /
`synthesis` (+ `volunteer_context` push surface). BrainBench P@5 49.1%, R@5 97.9% (graph on).

**Stack:**
- **Runtime:** Bun >= 1.3.11 (single binary; NOT on npm — the npm "gbrain" is unrelated and
  shadows the binary; install from GitHub only). TypeScript ESM, `src/cli.ts` entry.
- **Storage:** dual engine — embedded **PGLite** (WASM Postgres, `@electric-sql/pglite@0.4.3`
  pinned, local file, single-writer lock via a vendored C `native/locks` ABI) or **Postgres**
  (Supabase recommended; `postgres@3.4.9` postgres.js driver with a repo patch). Schema in
  `src/core/pglite-schema.ts` / `src/schema.sql`; JSONB writes via `executeRawJsonb`
  (`src/core/sql-query.ts`).
- **HTTP/MCP:** `express@5.2.1` + `@modelcontextprotocol/sdk@1.29.0` (OAuth router:
  `/authorize /token /register /revoke`), `hono@4.13.7`, `jose@6.2.2`, `express-rate-limit`,
  `cookie-parser`. Transports: stdio, legacy HTTP bearer, OAuth HTTP, Tailscale expose
  (`gbrain mcp expose`; `--funnel` for public internet / cloud agents).
- **AI:** `ai@^6`, `@ai-sdk/*` gateways, `openai@4.104.0`, keyless start (harness
  subscription covers the model), optional cloud embedding/synthesis.
- **Ops:** `zod` validation, `chokidar` file watching, tree-sitter WASM code-intel.
- **Routing axes:** brain (DB — `host` vs mounted) × source (repo slice — `--source`,
  `.gbrain-source`, `GBRAIN_SOURCE`) × transport × OAuth scope (`read|write|admin|sources_admin|
  users_admin|agent|skill_*`).

**Security posture (v0.59.0.0, static review 2026-09-27):** OAuth scope hierarchy + DCR
ceilings (self-registered clients capped `read write` / `read`), sha-256-hashed bearer tokens,
timing-safe compares, per-source + per-takes-holder read scoping (app-layer, no RLS),
cwd-`.env` quarantine, CI: OSV-Scanner + Semgrep + gitleaks, attestation-verified release
binaries. Main gaps: `gbrain auth create` defaults to full admin, company-brain admission is
advisory on pre-existing broad grants, `--funnel`+DCR footgun, 7-day admin cookie, plaintext
credential vault. See `SECURITY-ARCHITECTURE.md` + `data/vulns-gbrain.jsonl`.

**Usage for this project:** per-company findings brain — ingest scan JSON → entities;
`gbrain remember "<fact>" --provenance "<src>" --entity <slug>`; `gbrain recall <slug>`
(positional, no `--entity` flag on 0.59.0.0); `gbrain entity <name>` for zero-LLM cards;
keyless start = no model keys needed. Team mode: `gbrain mounts add`, `gbrain mcp expose`.