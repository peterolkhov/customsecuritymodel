# customsecuritymodel

**Every security scanner checks the same public baseline.** OWASP — the Open Worldwide Application Security Project, a nonprofit — publishes the OWASP Top 10, a free, community-standard list of the most critical web application security risk categories. It is not proprietary: any vendor (Burp, ZAP, Semgrep, Snyk…) builds rules against it. So every scanner converges on the same coverage, and every company ends up with the same blind spots — the stack-specific issues no generic rule set knows about: a payment-webhook replay, an unauthenticated GraphQL mutation, an MCP auth gap. Catching those means hand-writing custom tests, which takes security engineers weeks per company. Almost nobody does it.

The trick that makes it cheap: **train a small model on the company's own scan findings.** A River LoRA on their probe output learns which findings matter *for their stack* — in minutes, for dollars, and the company holds the weights. Customization stops being an engineer hiring problem and becomes a training run.

## The product

A multiplayer security test suite per company:

- **Standard vulns** — the floor. What every suite already checks.
- **Blind spots** — the things teams *should* be paying attention to but aren't, selected per stack by the owned model instead of a rented frontier call.
- **Memory** — every scan's findings land in the company's GBrain; the suite compounds instead of resetting each run.
- **Presentation** — Superset pages, live.

## Build order (hackathon, hacking 1:30–5:00)

1. `river/` — the training module. Pairs → LoRA → checkpoint → smoke. **First thing live.**
2. `data/` — probe findings → instruction pairs (adapter + format contract).
3. `suite/` — standard + blind-spot check definitions, per-company selection.
4. `memory/` — findings → GBrain per company; recall drives retraining.
5. `pages/` — Superset pages for the judge-facing story.

## Status

Hackathon build, 1:30–5:00 PM PT. Live so far:

- `river/` — trained a real checkpoint on 300 de-identified pairs (loss 20 → ~1e-4 in ~10 min). Checkpoint: `river://c1f3375c-3877-488c-99f9-3660cb9b0a3d/sampler_weights/company-model-v1` (base Qwen/Qwen3.5-9B, 300 pairs), smoke-tested.
- `data/` — adapter turns the probe corpus (857 reports) into `data/out/pairs.jsonl`; plus sponsor vuln findings (river, gbrain, qm, memorable, superset).
- `memory/` — per-company findings brain wrapping the `gbrain` CLI (rules-required).
- `suite/` — per-company suite generator + 6 reference stacks (fintech, ecommerce, health, gbrain/qm/river open-source).
- `eval/` — target-disjoint held-out harness + `scoreboard.html`.
- `demo/` — loss curve, fleet telemetry, 2-min Loom script + narrative.
- [`BASELINE.md`](BASELINE.md) — the baseline security data this project contrasts against: corpus severity split (52,748 findings, 54.7% INFO), the rulebook-floor scorecard, and the blind-spot taxonomy.
