# customsecuritymodel

**[OWASP](https://owasp.org/) is every company renting the same logic.** OWASP — the Open Worldwide Application Security Project, a nonprofit that publishes the OWASP Top 10, the industry-standard list of the most critical web application security risks (2025 edition: broken access control, security misconfiguration, injection, cryptographic failures, and more) — is the shared baseline every security suite checks against. Every company gets the same checklist, the same severities, the same misses. Getting a security suite that actually fits your stack means weeks of security engineers hand-tuning rules — customization is the expensive part, so almost nobody gets it.

The trick that makes it cheap: **train a small model on the company's own scan findings.** A River LoRA on their probe output learns what matters *for their stack* — in minutes, for dollars, and the company holds the weights. Customization stops being an engineer hiring problem and becomes a training run.

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

- `river/` — trained a real checkpoint on 300 de-identified pairs (loss 20 → ~1e-4 in ~10 min). Checkpoint: `river://…/sampler_weights/company-model-v1`, smoke-tested.
- `data/` — adapter turns the probe corpus (857 reports) into `data/out/pairs.jsonl`; plus sponsor vuln findings (river, gbrain, qm, memorable, superset).
- `memory/` — per-company findings brain wrapping the `gbrain` CLI (rules-required).
- `suite/` — per-company suite generator + 6 reference stacks (fintech, ecommerce, health, gbrain/qm/river open-source).
- `eval/` — target-disjoint held-out harness + `scoreboard.html`.
- `demo/` — loss curve, fleet telemetry, 2-min Loom script + narrative.
