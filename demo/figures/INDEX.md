# demo/figures/ — the judge-facing image drop

Every figure is regenerated from live data by `make figures` (demo/make_figures.py +
demo/why_figure.py). If new eval runs or retraining land, re-run that target and re-copy
the PNGs here — nothing below is a hand-pasted number.

## The arc (matches the page structure: problem → solution → proof)

| # | file | the claim it carries | paste it at |
|---|------|----------------------|-------------|
| 1 | `why-owned-model.png` | **Hero.** Left: on the company's 150 held-out blind spots, the generic rulebook is exact on 46% — and its only answer for unknown types is MEDIUM, so real HIGHs get buried (30/33 api_key, 16/18 graphql_introspection) while INFO noise inflates (32/32 spa_catchall). Right: the fix is a 7m19s, ~$0.08 LoRA on the company's own pairs. | The top of the main page — the whole pitch in one image |
| 2 | `eval-results.png` | **Proof it works on unseen tasks.** On 97 findings across 23 targets the model *never saw* (sponsor + arch-mine corpora): the owned LoRA beats the generic floor on blind spots (16/48 vs 15/48) and on within-one-step agreement (73% vs 67%). | The "why it helps / compare on unseen" section — River's rubric item #3 |
| 3 | `calibration.png` | **The shape of the error.** Severity-step deltas on the same held-out rows: the rulebook's misses pile up at +2 (stamps MEDIUM/HIGH on types it doesn't know); the model's cluster at ±1. ±1-of-gold: model 87% vs rulebook 67%. | Right after eval-results.png — answers "ok but *how* is it better?" |
| 4 | `blind-spot-gap.png` | **The mechanism of the gap, standalone.** Same dumbbell as the hero's left panel — use when a page section needs just the "rulebook stamps MEDIUM on the unknown" argument without the training panel. | The problem/"every scanner rents the same baseline" section |
| 5 | `pipeline.png` | **Customization is a funnel, not a hiring problem.** 857 probe reports → 300 de-identified pairs → 191 pseudonym companies → 76 steps → 8¢ → 1 owned checkpoint. | The "how it works / cost" section or the video's economics beat |
| 6 | `loss.png` | **It really trained.** Per-step loss + rolling median, log scale, start 19.4 → min 2e-4, 76 steps. Raw receipt for "watch training happen" — River's reference demo style. | The training-run section / anywhere a live-receipt screenshot would go |

## Caveats to keep straight when pitching

- `eval-results.png` is honest, not a blowout: rulebook edges the model on *overall* exact-match
  (31/97 vs 29/97). The story is "competitive on the floor's turf, better on blind spots, more
  often close" — don't oversell overall accuracy.
- The model emitted no parseable severity on 15/97 eval calls (n=82 in calibration.png) — a
  decoding/format fix, not a training failure. Know it before a judge asks.
- `pipeline.png`'s "857 reports" is the corpus count from the adapter runlog; everything else on
  that chart is live-computed from data/out/pairs.jsonl + river/out/*/meta.json.

## Files

- PNGs: this dir. Index rendered as cards: `index.html` (self-contained, open in any browser).
- Regenerate: `make figures` then `cp demo/*.png demo/figures/`.
