# Loom Narrative — business copy

## The exigence

Security scanning is a commodity, and the commodity is standardized. OWASP's
Top 10 — a free, open, community-standard list of the most critical web
application security risk categories — is what every tool builds against
(Burp, ZAP, Semgrep, Snyk…). So all scanners converge on the same coverage,
and every company ends up with the same blind spots: the stack-specific issues
no generic rule set knows about — a payment webhook replay on a fintech, an
unauthenticated passwordless-login mutation on a GraphQL app, an MCP auth gap
on an open-source project. Catching those means hand-writing custom tests,
which takes security engineers weeks per company. Almost nobody does it.

## The genesis

What if customization stopped being a hiring problem and became a training run?

A River LoRA on the company's own scan findings learns what matters *for that
stack* — in minutes, for dollars, and the company holds the weights. One
company's findings → one owned model → one suite that reflects that company,
not the industry average.

## How we did it

1. **Pairs.** Real probe corpus (857 reports, ~180k findings) → 300
   de-identified training pairs. Half are the standard floor, half are blind
   spots generic suites miss.
2. **Train.** A single River API session: Qwen-9B + LoRA on the company's own
   findings. Loss 20 → 0.00002 in ~7 minutes. The entire marginal cost of a
   custom security model is that run.
3. **Own.** `chat_complete_from_checkpoint` — a severity judgment from weights
   we own, not a rented frontier call. Findings never leave.
4. **Remember.** Every scan's findings land in the company's GBrain. Scan once,
   recall forever. "What do we know about this company?" compounds across runs.
5. **Prove.** Target-disjoint held-out: rulebook floor vs owned model on unseen
   tasks. The scoreboard is the receipt that it's *better*, not just *yours*.
6. **Multiplayer.** Per-company model → per-company suite, generated not
   hand-tuned. Fintech gets its webhook-replay check; the open-source project
   gets its MCP-auth check.

## How River made it possible

The owned-checkpoint story is the whole point, and River is the only API that
makes a per-company model this cheap and this fast: a 300-pair LoRA converging
in minutes on a 9B base, saved as weights the company can hold, served through
`chat_complete_from_checkpoint` for live inference. The economics matter: the
owned model's marginal inference cost is ~free after training.

## How Superset made it possible

Superset ran the operation: 9 parallel agents across 9 workspaces, each with
its own branch — adapter, GBrain, eval, suite, infer, plus security
architectures for GBrain/QM/River and stack/suite generation. Every agent
pushed to GitHub as it went and kept a timestamped RUNLOG. This page, the
scoreboard, and the fleet telemetry are the proof surface.