# Page style guide — business presentation for Superset Pages

Source of truth for every page we publish. Judges skim in ~90s; the page is a
pitch deck, not a scrollback. Every rule below exists because a version of this
page violated it.

## 1. One figure, one claim

- Every stat/figures answers one question. If a number needs a sentence to
  explain what it means, cut it.
- Every figure is **traceable**: a source caption (`source: data/vulns-river.jsonl`,
  `source: river/out/<ts>/meta.json`). "Backed up easily" means a reader can
  point at the number and find the file that produced it.
- **No orphan numbers.** A stat with no source, no label, or no context is
  noise. Delete it.

## 2. Charts must be self-explanatory

- **Every chart has axes + labels.** Title, x-axis label, y-axis label, units.
  No exception. A curve with no axes communicates nothing.
- Log scale where the story is "order-of-magnitude drop" — but label it
  (`y-axis: loss (log scale)`).
- Annotate the point that matters: `"loss 20 → 1e-5"` labeled on the curve,
  not just stated in prose.
- Add source + parameters under the chart (base model, pairs, steps) as a
  caption, not as prose.

## 3. Kill the wall of text

- **Paragraphs are forbidden on the page.** Use: headline → one-line
  claim → bullets → table → chart.
- The problem statement fits in **two sentences max**, each under 20 words.
- Never paste a finding's raw text. A finding is one row in a table with a
  **short label** + severity + source. The detail lives in the repo, not the page.
- If a section needs more than ~5 lines of prose, it's a chart or a table.

## 4. The arc: problem → solution → proof

Judge's questions, answered in order:

1. **What's the problem?** (2 sentences, concrete)
2. **What did you build?** (one line: the product)
3. **Why is it real?** (the proof: checkpoint exists, loss converged, eval held-out)
4. **Why is it theirs?** (per-company, owned weights, memory)

Sections below the fold are evidence, not argument.

## 5. Aggregate, don't enumerate

- **Costs are a single number** (`total agent burn: $X`), with a `source:
  demo/telemetry.json` caption. A per-agent cost table is only shown if the
  reader's job is to compare agents — for a pitch it isn't.
- Fleet/agents = one stat (count), not a table, unless the table is the point.

## 6. Headline numbers at the top

4 stats max. Each is: number (large), label (short), source (tiny caption).
No stat mixes two units (`50+284` is two claims pretending to be one).

## 7. Typography / layout

- `class="auto"` (or `dark` if the page has baked-in colors) — never default.
- One accent color from `--sp-chart-*`; charts share the palette.
- Use the theme tokens (`--sp-surface`, `--sp-border`) — don't invent a palette.
- Wide data tables get their own `overflow-x: auto` container.
- No emoji icons. No gradients. No center-everything.

## Checklist before publish

- [ ] Every chart has axes + labels + units
- [ ] Every stat has a `source:` caption
- [ ] No prose paragraph over 2 lines
- [ ] No raw finding text on the page
- [ ] Costs aggregated to one number
- [ ] Problem (2 sentences) → solution (1 line) → proof
- [ ] Passes policy check: no fetch, no eval, no remote scripts