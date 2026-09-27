# Loom Script — 2 min demo (record ~4:00 PT)

Target: judges, table expo loop (~90s pitch, video is the "full" version).
Business style. Show, don't tell. Every claim backed by something on screen.

---

## 0. Hook (0:00–0:12)

> "Every company on Earth rents the same security checklist. OWASP is the same
> logic, the same severities, the same misses. So when your stack is weird —
> GraphQL in front of your payments, a status page on a vendor you stopped
> paying — the generic suite misses exactly the thing that will hurt you."

Screen: split — left `data/example.pairs.jsonl`, right a generic "checklist" image.

## 1. The genesis / exigence (0:12–0:30)

> "Customizing a security suite for YOUR stack takes weeks of security-engineer
> time. Almost nobody does it. So what if customization stopped being an
> engineer hiring problem — and became a training run?"

> "Train a small model on the company's own scan findings. Minutes, dollars, and
> the company holds the weights. That's the whole thesis."

Screen: the product one-liner card + `PLAN.md`.

## 2. How we did it — the pipeline (0:30–1:00)

> "Here's the live run, from this hackathon. We took a real probe corpus — 857
> reports, ~180k raw findings — and turned it into 300 de-identified training
> pairs. Each pair is a finding and the severity a company's stack should assign.
> Half are the standard floor, half are blind spots the generic suites miss."

Screen: `data/out/pairs.jsonl`, the manifest, de-identification in action.

> "Then one API call. A River LoRA on Qwen-9B, trained on the company's own
> findings. Watch the loss curve — from 20 to 0.00002 in 7 minutes. That's the
> entire cost of a custom security model: dollars, not engineer-months."

Screen: `loss.png` animating / `loss-full.csv`.

## 3. The River bit — owned weights (1:00–1:20)

> "This is a real checkpoint, trained live during the hackathon. Every finding
> now gets a severity from a model that has read THIS company's stack — not from
> a rented frontier call. The company owns the weights. No findings leave."

Screen: `river/out/<ts>/meta.json`, `smoke.json` (chat_complete_from_checkpoint),
then `river/infer.py --checkpoint ...` pasting a finding → severity.

## 4. The memory + scoreboard (1:20–1:45)

> "Findings land in the company's GBrain — required by the rules, and the moat.
> Scan once, remember forever. 'What do we know about this company?' across scans."

Screen: `memory/brain.py recall <company>` answering across scans.

> "And here's the receipt that the custom model is better, not just yours —
> target-disjoint held-out. Rulebook floor vs the owned model on unseen tasks."

Screen: `eval/scoreboard.html`.

## 5. The multiplayer claim (1:45–1:58)

> "Because the model is per-company, every company gets a different suite —
> generated, not hand-tuned. Fintech gets its payment-webhook replay check. The
> open-source project gets its MCP-auth check. That's the product."

Screen: `suite/<company>.md` for 2-3 different companies + `stack-references.md`.

## 6. Close (1:58–2:00)

> "Customization is no longer a hiring problem. It's a training run.
> **customsecuritymodel** — run it on your stack."

---

## What's on screen when (assets checklist)

- [ ] `data/out/pairs.jsonl` + manifest (adapter)
- [ ] `loss.png` / `loss-full.csv` (live convergence)
- [ ] `river/out/<ts>/meta.json` + `smoke.json` (real checkpoint)
- [ ] `river/infer.py` live severity call
- [ ] `memory/brain.py recall` (GBrain, rules-required)
- [ ] `eval/scoreboard.html` (held-out comparison)
- [ ] `suite/<company>.md` ×2-3 + `stack-references.md`
- [ ] live fleet telemetry (agents, cost, commits) — `demo/telemetry.json`