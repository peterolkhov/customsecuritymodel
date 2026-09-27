# SECURITY-ARCHITECTURE.md — Superset (the orchestration cockpit)

> **Scope.** Security architecture of Superset — the multi-agent orchestration
> cockpit this session runs on. Written from the **static reference only**
> (`reference/superset-ufo.md`) plus the existing recon report
> (`~/probe/out/superset-sh-deep-exploit-ports-nuclei/`). **Nothing here was
> re-scanned or probed live**; every finding referenced below is already in the
> report and is reproduced de-identified (hosts → `*.example`).
>
> **Legend.** `[ref]` = stated in the static reference. `[obs]` = observed in
> the recon report. `[infer]` = inference from the above, flagged as such.

---

## 1. What Superset is (one paragraph)

Superset is a **local-first host service per org** for running *many coding
agents at once*. `[ref]` It is an ELv2 source-available macOS app (plus mobile)
that says "Bring Any Agent. Orchestrate Them All." — Claude Code, Codex, Codex
Code/OpenCode, or any agent — each task gets an **isolated git worktree**, you
fan out 100+ agents against a status board, schedule them with **automations**
("daily-triage", "changelog-draft"), drive them from remote machines over
**SSH**, and control it all from a **CLI + SDK + MCP** surface. Local-first,
SOC 2, and it claims to never proxy model calls. `[ref]`

This is the product's defining trust posture: **the orchestration plane lives
on your laptop, not in a cloud control plane.** All the interesting security
questions are about the boundary where that local plane meets: the org's git
remotes, the agents' credentials, the SSH targets, and the MCP/SDK clients that
can drive it.

---

## 2. Trust model — who trusts what

```
                    ┌─────────────────────────────────────────────┐
                    │          TRUSTED (the local plane)          │
                    │                                             │
                    │  macOS app + host-service (Fastify/tRPC)    │
                    │  per-org workspace db · git worktrees       │
                    │  agent credential store (per workspace)     │
                    │  automations (scheduled agents)             │
                    │  CLI / SDK / MCP server on localhost        │
                    └──────────────┬──────────────────────────────┘
                                   │
        ┌───────────────┬──────────┼───────────────┬──────────────────┐
        │               │          │               │                  │
        ▼               ▼          ▼               ▼                  ▼
   git remote      agent vendors  remote host     MCP clients /      browser /
   (GitHub/GL)     (model APIs)   (SSH box)       SDK apps            cloud sync
   TRUSTED-VIA-    TRUSTED-       TRUSTED-        SEMI-TRUSTED       SEMI-TRUSTED
   CREDENTIALS     VIA-API-KEY    VIA-SSH-KEY     (no auth needed    (session / magic
   (write scope)   (model calls   (full agent     to drive)          link / cookies)
                    never proxied) shell access)
```

**High-level posture:**
- The **local host service is the root of trust.** Whoever can talk to it can
  read workspaces, list running agents, and read agent state. Its default trust
  boundary is *the local machine* — any process that can reach the service can
  drive it. `[infer]`
- **Git remotes are trusted-via-credentials.** A worktree is a real clone; an
  agent with the workspace's git credentials can push. The remote is the
  *escalation target* for anything that compromises a worktree (a malicious PR
  body or README is code the agent will read and act on — prompt injection
  over git). `[infer]`
- **Model calls are never proxied** — the agent talks to its model vendor with
  its own API key. That is good (no MITM of model traffic) but means **the
  agent's key is the second root of trust**: it is stored where the local
  service can read it and used by third-party agent binaries. `[ref][infer]`
- **Remote hosts are trusted-via-SSH-key** and, once connected, are inside the
  orchestration plane (workspaces survive laptop sleep because work happens on
  the remote). A compromised remote host = a compromised workspace + the
  agent's credentials on that host. `[ref][infer]`
- **MCP/SDK/CLI are semi-trusted:** the product *wants* to be agent-drivable,
  so these surfaces are deliberately open to anything that can reach them.
  `[ref]`

---

## 3. Workspaces as git worktrees — the isolation boundary

Each agent task gets its own **git worktree**: a separate working directory
sharing one repo object store. `[ref]`

**What it does and doesn't isolate:**

| layer | isolated? | notes |
|---|---|---|
| working tree / files | ✅ per task | agents don't stomp each other's files |
| git object store | ❌ shared | worktrees share `.git/objects`; a hostile checkout only affects its own worktree, but `.git`-adjacent metadata is common `[infer]` |
| credentials | ✅ per workspace | each workspace carries its own credential set `[infer]` |
| model context / logs | ✅ per agent | status board, runs, loss/telemetry are per-agent |
| localhost service | ❌ shared | every agent in the org shares the one host service `[infer]` |

**Where the boundary could break (workspaces):**
1. **Worktree === trust-by-default for the agent.** The agent treats the
   worktree's contents as instructions. A repo with attacker-influenced files
   (PR description, `.claude/` or `.agents/` skill dirs, `AGENTS.md`, issue
   text) is *input the agent executes on*. `[infer]` — this is the classic
   agent prompt-injection boundary, and the recon corpus shows repos carrying
   `AGENTS.md`/`.claude/`/`.codex/`/`.superset/` config (observed in the
   cloned repos). `[obs]`
2. **Secret history is the worktree's dirty secret.** The recon report found
   **237 repo_secret_history + 9 repo_secret_tree + 11 repo_secret_file**
   findings across the org's public repos `[obs]` — real provider keys
   (Stripe, Anthropic, AWS, GitHub tokens, JWTs) sitting in git history. Every
   new worktree is a fresh clone that **re-downloads those secrets**; an agent
   that searches the history (or a `git log -S` bug-hunt) can surface live
   credentials. A standard OWASP suite misses this because it checks the *web
   app*, not the *repo object store* the orchestration plane is built on.
   (class: **blind_spot**)
3. **`repo_posture_noscanning` / `repo_posture_noprotection`** — secret
   scanning + push protection off `[obs]` means the org's agents are *actively
   producing* new leaks (an agent `git commit`ing a `.env` is the exact
   incident the control gap exists to stop). This is a **blind_spot**: the
   weakness is the *absence of a control*, not a reachable bug.

---

## 4. Agent-credential handling

Two credential classes live on the local plane:

- **Agent vendor keys** (Anthropic/OpenAI/etc.) — never proxied; the agent
  uses them directly. `[ref]`
- **Per-workspace credentials** — the org/remote git tokens, registry tokens,
  and any secrets the automations or agents need, scoped per workspace. `[infer]`

**Where the boundary could break (credentials):**
1. **Secret-in-history is a *credential supply chain* issue for this product.**
   The recon corpus's 237 history findings include *the kind of keys agents
   use*: `ghp_`/`ghs_`/`ghu_` (GitHub tokens — exactly what a coding agent
   writes with), `sk-ant-*` (Anthropic — the model key), `AKIA/ASIA`,
   `sk_test_*`, JWTs. `[obs]` An agent that finds a committed token can use it
   as its own credential — the orchestration plane amplifies a repo hygiene
   problem into a live-credential problem. **blind_spot** class: the finding
   type is invisible to web-OAST-style scans.
2. **`repo_secret_file`** — secret-named files *in the working tree*
   (`.../secrets/secrets.ts`, `.npmrc`, `.env.sample`, `credentials.ts`,
   workflow secret-test files) `[obs]` are exactly what an agent triaging a
   task would open first. The report grades these HIGH. They're a
   **blind_spot** for a *scan-trained* model too if the trainer never sees
   repo-tree evidence — the custom model's job is to recognize "this path is a
   credential store" from the path shape alone (no value needed).

---

## 5. Remote hosts via SSH

`superset connect gpu-box` (SSH); workspaces survive laptop sleep because the
work can run on the remote. `[ref]`

**Where the boundary could break (SSH remotes):**
1. **The SSH box inherits the whole orchestration trust set.** If a remote
   host is compromised, the attacker sits where the agent's credentials,
   git state, and (potentially) the relayed MCP surface live. `[infer]`
2. **The recon report's own org shows the subdomain type this breaks into:**
   `ssh.target-16.example` and `mail.target-16.example` served a *shared-host
   default vhost* (cert for an unrelated third-party site) — broken TLS /
   vhost misconfig on the "ssh" name. `[obs]` For Superset-as-a-product, the
   analogous risk is `superset connect <name>` resolving to a host whose SSH
   fingerprint is wrong or whose key is stale — no pinning story in the
   reference. `[infer]`
3. **Remote = your credentials on someone else's disk.** SSH agent forwarding
   or key storage on the remote expands the blast radius of any remote-host
   compromise to "everything the org does on that box." `[infer]`

---

## 6. MCP / SDK / CLI surface

`superset new "task" --agent claude`, `superset ls`, `superset status`; the
product is agent-drivable via **MCP**. `[ref]`

**Where the boundary could break (MCP):**
1. **The recon report found a live unauth MCP endpoint** (`tools/list` at
   `/mcp` returns 200 with no auth, exposing `docs_search`, `docs_read`);
   `[obs]` **HIGH**. The *product*'s MCP server is localhost, so the threat
   model is "any local process can drive it" — but the *pattern* the recon
   shows (MCP servers shipped without auth) is the product's own surface if it
   is ever exposed or bridged. The finding is **blind_spot**: `mcp_tools_unauth`
   is not on a standard checklist, and for an orchestration product the cost is
   "anonymous caller enumerates + drives the tools an agent runs" (prompt
   injection into tool args, tool abuse).
2. **`unauth_api_200`** — `/api/search` answers anonymous on the docs host.
   `[obs]` Same shape as the MCP finding: an *enumerable, driver-less* API on
   the orchestration vendor's own estate. `[infer]`
3. **tRPC surface (`packages/trpc/src/router/environment/...`) `[obs]`** — the
   local host service is Fastify/tRPC `[infer]`; tRPC procedures are
   callable without REST ceremony, so a local process can invoke procedures by
   name. If any procedure lacks auth on its side, the boundary is "localhost
   only," which is often *not* the real boundary on a shared or remote-exposed
   machine. `[infer]`

---

## 7. Automations

Scheduled agents ("daily-triage", "changelog-draft") that open PRs for review.
`[ref]`

**Where the boundary could break (automations):**
1. **Automations run with the workspace's credentials on a schedule — no human
   in the loop at trigger time.** The only gate is the PR review. So the
   *input* to an automation is the highest-value injection target: a triage
   automation reading today's issues is a prompt-injection sink for anyone who
   can file an issue. `[infer]`
2. **Automations are where "the model learned it" meets "the model is trusted
   to act."** A custom-model security suite (this project) run *as an
   automation* is exactly the flywheel: scan → triage → new pairs → LoRA →
   scoreboard PR. The security control and the attack surface are the same
   object — worth stating explicitly in any demo.

---

## 8. The recon findings that map to this architecture (de-identified)

Priority classes from the corpus, mapped to the boundary they stress:

| finding (de-identified) | count | severity | class | boundary stressed |
|---|---|---|---|---|
| `repo_secret_history` | 33 rows (237 raw) | INFO | **blind_spot** | workspace / credential store (§3.2, §4.1) |
| `repo_posture_noscanning` / `repo_posture_noprotection` | 22/22 | MEDIUM | **blind_spot** | credential supply chain (§3.3, §4.1) |
| `repo_secret_file` | 11 | HIGH | **blind_spot** | workspace tree / agent reads (§4.2) |
| `repo_ci_risky` (pull_request_target) | 4 | MEDIUM | **blind_spot** | automation/CI boundary (§7) |
| `git_commit_sha_leak` | 15 | HIGH | **blind_spot** | deployed-code identity → CVE targeting |
| `mcp_tools_unauth` | 3 | HIGH | **blind_spot** | MCP surface (§6.1) |
| `api_post_csrf` | 12 | MEDIUM | **blind_spot** | serverless POST endpoints, no Origin/CSRF check |
| `sentry_dsn_telemetry_injection` | 12 | MEDIUM | **blind_spot** | telemetry poisoning / alert fatigue |
| `posthog_analytics_injection` | 8 | MEDIUM | **blind_spot** | analytics poisoning, feature-flag abuse |
| `firebase_firestore_open` | 4 | CRITICAL | **blind_spot** | brand-derived project, anonymous read+write |
| `csp_unsafe_https_script` | 7 | MEDIUM | standard | XSS floor on the app |
| `clickjacking_live` | 2 | MEDIUM | standard | login-UI framing on the app |

**Why the split matters for the product:** the *standard* rows (CSP, framing,
HSTS) are the floor every scanner finds. The *blind_spot* rows are the ones a
generic OWASP suite misses and the ones that describe *this* architecture's
failure modes — git-history secrets, disabled secret scanning, unauth MCP,
unauth serverless POSTs, telemetry injection. That is the "what the custom
model learned" argument, in one table.

---

## 9. Bottom line

The trust boundary that matters for Superset is **not the web app — it's the
local orchestration plane and its git/credential/SSH/MCP spokes.** The recon
report's highest-count findings (git-history secrets, disabled secret
scanning) are precisely the places where that plane touches the outside world,
and every one of them is invisible to a standard web checklist. For a security
suite that wants to be *custom to an orchestration product*, those rows are the
training signal; for the demo, they are the "compare on unseen tasks" receipt.