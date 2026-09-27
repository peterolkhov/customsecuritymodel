# data/

The contract between scan output and the River model. One JSONL row = one training/eval example:

```json
{
  "task": "severity",
  "instruction": "Given this finding, assign a severity for THIS company's stack.",
  "input": "<evidence only — hosts pseudonymised to *.example>",
  "output": "<the label / judgment text>",
  "provenance": {"source": "probe-report", "target": "target-01.example", "observed_at": "2026-09-27T00:00:00Z"}
}
```

Rules:

- `input` and `output` never contain a real hostname, IP, email or brand — `*.example` only.
- `provenance.observed_at` timestamps every row; the build story needs per-row "when".
- Rows split into **standard** (the OWASP-style floor every suite checks) and **blind_spot** (stack-specific things teams miss — the rows that justify a custom model).

`example.pairs.jsonl` is a 6-row fixture for `--self-test`. The probe-corpus
adapter is `data/build_vulns.py` (report.json -> pairs); `data/vulns-superset.jsonl`
is the mined superset-sh corpus (284 rows, 200 blind_spot / 84 standard), with
`data/deidentify.py` doing hosts->`*.example`, secret VALUE -> described TYPE,
and a residue gate.
