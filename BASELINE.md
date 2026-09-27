# BASELINE.md — the security baseline every scanner checks, and what it misses

> Anchor data for the **generic floor vs owned model** contrast. Every number below is drawn
> from committed artifacts in this repo — `eval/scoreboard.html`, `data/security-corpus.md`,
> `data/security-scanners.md`, `data/security-fleet-audit.md` — so the picture is reproducible,
> not vibes.

## The baseline claim

OWASP's Top 10 is a free, open, community-standard list — not proprietary. Burp, ZAP, Semgrep,
Snyk all build rules against the same list. So every scanner converges on the same coverage, and
every company inherits the same blind spots: the stack-specific issues no generic rule set knows
about — a payment-webhook replay, an unauthenticated GraphQL mutation, an MCP auth gap. Catching
those means hand-writing custom tests, which takes security engineers weeks per company. Almost
nobody does it. This file is the receipts for that argument.

## Anchor 1 — the corpus baseline (what real findings look like)

Sampled from real probe runs (2026-08/09): 27 reports, **52,748 findings**, 212 distinct finding
types (`data/security-corpus.md` §1).

| severity | count | share |
|---|---|---|
| CRITICAL | 84 | 0.2% |
| HIGH | 4,416 | 8.4% |
| MEDIUM | 12,365 | 23.4% |
| LOW | 7,027 | 13.3% |
| INFO | 28,856 | **54.7%** |

- **Over half of every scan is INFO noise** — the noise that drowns triage.
- **The dangerous types are the tail.** By HIGH/CRITICAL count: `unauth_api_200` (1,279 H),
  `js_hardcoded_api_key` (879 H), `broken_access_control` (302 H), `repo_dep_vuln` (250 H),
  `js_key_in_bundle` (200 H), `payment_price_tampering` (69 H), `ssrf` (66 H).
- **By count, the noise wins:** `repo_secret_history` (11,660), `api_post_csrf` (4,157),
  `spa_catchall` (2,427), `tech_fingerprint` (2,270), `missing_csp` (1,335).
- **Why it matters:** a count-ranked baseline ranks the wrong things — it scores the noise, not
  the danger. Same type, wildly different real severity (`data/security-corpus.md` §3: the 200 is
  not the finding; the response body decides).

## Anchor 2 — the rulebook-floor scorecard (the generic baseline on unseen targets)

From `eval/scoreboard.html` — 300 pairs → 244 train / 56 held-out, target-disjoint, seed 4.
The committed board is **STUB MODE**: the "model" row is a majority-class placeholder, NOT the
owned model; the owned row is pending `RIVER_API_KEY`.

| method | overall acc | standard acc | blind-spot acc | within-1-step agree |
|---|---|---|---|---|
| generic rulebook floor | 28/56 (**50%**) | 12/27 (44%) | **16/29 (55%)** | 44/56 (79%) |
| stub model (placeholder) | 22/56 (39%) | 12/27 (44%) | 10/29 (34%) | 44/56 (79%) |

Earlier class-slice run (150 train / 150 eval, all blind-spot rows): rulebook **49%** vs stub **25%**
(`runlogs/RUNLOG-checkpoint.md`, 21:28Z).

**The picture:** on the standard floor both rows do fine (44%). On the blind-spot rows — the
stack-specific ones that hurt — the generic baseline is a coin flip (55%, or 49% on the
all-blind-spot slice). That coin flip is the opening the owned model exists to close.

## Anchor 3 — why the baseline can't fix itself (scanner convergence)

`data/security-scanners.md` — 16 findings (F-SCN-01…16) on the scanner/hunting framework that
produced the corpus:

- Every tool builds rules against the same public OWASP list → coverage converges. That is the
  business of scanners; it is also why the blind spots are *shared*, not per-vendor.
- F-SCN-14: the scanner's own heuristic severities become the model's gold labels — there is no
  ground truth to train a generic rule set against for stack-specific classes.
- F-SCN-04/02: scanner output is attacker-influenceable — untrusted page text flows verbatim into
  findings, and through `build_pairs.py` into the training data. The baseline's evidence quality
  is the ceiling for any model built on it.

## What the baseline structurally cannot see (blind-spot taxonomy, condensed)

From `data/security-corpus.md` §4 — stack-specific classes that never appear in a generic
rulebook:

- **Fintech / BNPL / payment:** unauth MCP `tools/call` on API-docs hosts; live payment-provider
  SECRET in client JS; payment-method IDOR on incrementing user IDs; invoice/receipt endpoints
  gated by tenant header, not auth; Wayback-archived payment surface behind a WAF.
- **Health / health-device:** Next.js `/_next/data/<buildId>` middleware bypass (auth on `/api`
  but not data routes); `/actuator/env` exposing env/DB vars; production Firebase RTDB public
  read; subdomain takeover on device staging.
- **D2C / retail / marketplace:** live payment SECRET in client JS; GraphQL field-name oracle
  with introspection off; `__NEXT_DATA__` server-side secrets; checkout-as-a-service surface on
  staging; Fastly/Cloudflare dangling CNAMEs.
- **AI-SaaS / infra / dev-tools:** unauth MCP across docs hosts (read-only tools = MEDIUM,
  exec/data tools = HIGH); `consul/v1/agent/self` exposed; unauth write-path on ops endpoints
  (400-vs-401 asymmetry); open DCR OAuth registration with wildcard redirects.
- **OSS / email-infra:** live third-party OAuth tokens + env-style API keys in git history — the
  worst place to leak, since every clone reads them.

## How to read the contrast

- The **baseline** (Anchor 2's rulebook row) is the cheapest possible "customization" — it is
  what every company already has, whether they bought it or not.
- The **owned model** replaces that row with weights trained on *this company's* own scan
  findings: a per-stack severity judge, evaluated on unseen targets, at minutes/dollars cost —
  and the company holds the weights.
- To fill the owned row on the real corpus:
  `export RIVER_API_KEY=<rv_...>` then
  `python3 eval/harness.py --pairs data/out/pairs.jsonl --checkpoint river://c1f3375c-3877-488c-99f9-3660cb9b0a3d/sampler_weights/company-model-v1 --held-out-class blind_spot`
  (overwrites `eval/scoreboard.html` with the real owned-model row).

## Sources

| artifact | what it holds |
|---|---|
| `eval/scoreboard.html` | held-out rulebook vs model, per class (STUB MODE) |
| `data/security-corpus.md` | 52,748-finding severity split + blind-spot taxonomy |
| `data/security-scanners.md` | 16 scanner/hunting findings (F-SCN-01…16) |
| `data/security-fleet-audit.md` | 12 fleet/ops findings; repo secret-clean; 2 P0 |
| `runlogs/RUNLOG-checkpoint.md` | class-slice eval run (49% vs 25%) + re-run command |