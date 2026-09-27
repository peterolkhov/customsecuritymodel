# Megaplan — what a win looks like, and the order to build it

Hacking window: **1:30 → 5:00 PM PT** (3.5 hrs). Video ~4:00, form ~4:45, judging 5:00–5:45.

River's win condition: *best showcase of a custom model* — demo the experience, show what the
model learned, compare on unseen tasks. Rules condition: **must use GBrain**. Those two sentences
are the plan.

## The spine (cannot ship without)

| # | piece | file | why it's load-bearing |
|---|---|---|---|
| 1 | probe findings → pairs adapter | `data/build_pairs.py` | Turns the real corpus (`~/probe/out`) into training JSONL: de-identify to `*.example`, classify `standard` vs `blind_spot`, stamp `provenance.observed_at`, emit a manifest. **River asks to see training examples — this IS the "what it learned" slide.** |
| 2 | real River run | `river/train.py --live` (exists) | The owned checkpoint. Needs `RIVER_API_KEY` from the booth (credits expire EOD) + `RIVER_BASE_MODEL`. Kick off by ~2:15 so it lands by ~3:00. Artifacts already: `river/out/<ts>/meta.json` + `log.jsonl` loss ticks. |
| 3 | GBrain memory | `memory/brain.py` | **Rules require it.** Per-company findings brain: ingest scan JSON → entities; `gbrain recall` answers "what do we know about this company" across scans. Flags verified on 0.59.0.0 (recall is positional). |
| 4 | eval → scoreboard | `eval/harness.py`, `eval/scoreboard.py` → `scoreboard.html` | River ask #3 — "compare on unseen tasks." Target-disjoint held-out: rulebook floor vs owned model (frontier row optional). This is the receipt that the custom model is *better*, not just *yours*. |

## The product surface (the "who it's for" — River ask #1)

| # | piece | file | note |
|---|---|---|---|
| 5 | per-company suite generator | `suite/build_suite.py` | Reads the company's brain + owned model → emits `suite/<company>.md`: N standard checks + M blind spots ranked by the model. This is the *multiplayer* claim — every company gets a different suite, generated, not hand-tuned. |
| 6 | infer CLI | `river/infer.py` | Thin `chat_complete_from_checkpoint` wrapper: paste a finding → get the company's severity. Used live in the demo + video. |

## The flywheel beat (the close)

| # | piece | note |
|---|---|---|
| 7 | second-scan compounding | Re-scan, sync to GBrain, `recall` shows it knows scan 1 + scan 2. Optional v1→v2 retrain if the first checkpoint was fast. |
| 8 | Memorable procedure | Record scan→train→suite once, `memorable recall` replays it. Side-quest tick; only after the spine is green. |

## Presentation + submission

| # | piece | note |
|---|---|---|
| 9 | `pages/` Superset surface | Judge-facing story rendered as pages; Superset side-quest tick. Cut first if compressed. |
| 10 | Loom (~90s, SUBMISSION.md script) | Record 4:00–4:30 while everything still runs. |
| 11 | Form | 4:45. Needs video URL first. |

## Timeline

| t (PT) | do |
|---|---|
| 12:00 | Doors. **River booth for credits first.** Discord/keys/sponsor pings. |
| 1:30 | Hacking starts. `#1` adapter on real corpus → `data/out/pairs.jsonl`. |
| ~2:15 | `#2` `river/train.py --live` — training runs in background. |
| 2:15–3:15 | While training: `#3` gbrain module, `#4` eval harness, `#6` infer CLI. |
| ~3:15 | Checkpoint lands → run eval → scoreboard.html. |
| 3:15–4:00 | `#5` suite generator, `#7` second-scan beat, `#8` memorable if smooth. |
| 4:00–4:30 | `#10` record Loom (everything still warm). |
| 4:30–4:45 | `#9` pages only if ahead; `#11` submit form. |
| 5:00 | Freeze. Judging. |

## Cut order (if compressed, drop top-first)

`pages/` → memorable → frontier comparison row → v2 retrain → suite polish.
**Never cut:** GBrain (rules), a real checkpoint (River), held-out comparison (River), the video (form).

## Fallbacks

- River queue/fail: dry-run + fixture smoke exists today; show `meta.json` from the attempt + tokenized batch stats honestly labeled.
- Corpus missing: adapter still runs on `data/example.pairs.jsonl`; suite generates for the fixture company.
- GBrain install issues: `gbrain init --pglite` verified in 2s prep-side; `remember`/`recall` flags verified.
