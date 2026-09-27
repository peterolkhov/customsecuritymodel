# Submission — due 5:00 PM PT

Form: https://docs.google.com/forms/d/e/1FAIpQLSdiU5L7PhlkD7HQQouQKPSlm7WrobkdJuvSZLoi6O7jXRWKiQ/viewform

## The fields

| field | status | value |
|---|---|---|
| Email | ✅ | polkhovets@gmail.com |
| Team Name | ⬜ | TBD — pick something |
| Member Names + Emails | ⬜ | Peter Olkhovets, polkhovets@gmail.com (+ teammates if any) |
| Project Description | ✅ draft below | — |
| Github URL | ✅ | https://github.com/peterolkhov/customsecuritymodel |
| **Demo Video URL** | ⬜ | **required — Loom. Record by ~4:30 while everything works, NOT during judging.** Script below. |
| Side Quest | ⬜ | see picks below |
| Anything else | ✅ draft below | — |

## Side-quest picks

Tick every sponsor we genuinely wired — a shallow claim is worse than none:

- **River AI** — yes, it's the core (River prize = 50k/25k/15k credits; River's own judging guide is below).
- **GBrain** — yes (required by rules anyway; per-company findings brain).
- **Superset** — yes if `pages/` lands (presentation + parallel workspaces).
- **Memorable** — yes if the scan→train procedure gets recorded (`memory/procedures/`).
- **QM / UFO** — only if actually wired; skip otherwise.

## Project Description (draft — trim to their box)

> OWASP is every company renting the same security logic — same checklist, same severities, same misses. Real customization per stack costs weeks of security-engineer time, so nobody gets it.
>
> We make the custom part a training run: a River LoRA trained on the company's own scan findings learns what matters for *their* stack in minutes, and they hold the weights. On top: a multiplayer test suite (standard floor + per-stack blind spots the generic checklists miss), a GBrain per company so every scan compounds, and the whole build rendered as timestamped, replayable artifacts.
>
> Security teams stop renting judgment. They own it.

## Demo video (~90s, Loom screen record — do it BEFORE submission)

1. The claim: "every security suite runs the same rented logic; here's a company owning theirs" (10s)
2. `data/` pairs file — the training examples, standard vs blind_spot rows (River asks to see these) (15s)
3. Training running / `river/out/*/meta.json` + `log.jsonl` loss lines — it happened live (20s)
4. Scoreboard or held-out comparison: rulebook floor vs owned model on unseen targets (River: "compare results on unseen tasks") (25s)
5. `gbrain recall` — the company's brain remembers the scan (10s)
6. Close: "customization was an engineer hiring problem; now it's a training run" (10s)

## River's stated judging guide (river.ai/own-your-intelligence-hackathon)

> "The best showcase of using a custom model wins."
> 1. **Demo the experience** — what did you build, who is it for?
> 2. **Explain what the model learned** — show your training examples or reward signal.
> 3. **Show why it helps** — compare results on unseen tasks, share what you learned.

Their reference example (style_chat.py) is a **live-retrain loop** — adapter reloads mid-session. They like seeing training happen, not a static artifact.

## Anything else (draft)

> Every build step is logged and replayable — runs carry timestamps, durations, exit codes and the claim each step supports. Ask to see the build timeline.

## Logistics

- **River credits:** get them at the River booth FIRST — unused credits expire end of day.
- **Deadline order:** video (4:00–4:30) → form (4:45) → table judging (5:00–5:45). The form needs the video URL, so the video can't be last.
