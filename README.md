# customsecuritymodel

**OWASP is every company renting the same logic.** The same checklist, the same severities, the same misses. Getting a security suite that actually fits your stack means weeks of security engineers hand-tuning rules — customization is the expensive part, so almost nobody gets it.

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

Skeleton + River module. Everything else lands piece by piece during hacking hours.
