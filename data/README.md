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

`example.pairs.jsonl` is a 6-row fixture for `--self-test`. The probe-corpus adapter (`probe report.json -> pairs`) lands next.

## `arch-mine.jsonl` — architecture-derived blind spots (no scanning)

`data/arch_mine.py` characterizes the *existing* probe corpus (DNS/mail/DMARC/DNSSEC,
CDN/WAF, hosting origin, SaaS footprint, JS/config-leak signals) and derives the
vulnerabilities the architecture implies — pure analysis, zero network calls. One
row per target, `provenance.class = "blind_spot"`, all fields de-identified to
`*.example`. `ARCH-MINE.md` is the human-facing demo table (target slug | industry
guess | architecture signals | top derived vuln(s) | severity).

Rules in `derive()` are deterministic (no LLM): e.g. `dmarc weak + dkim/SPF missing
-> domain_spoofing`, `dangling DNS -> subdomain_takeover`, `js_hardcoded_api_key ->
js_credential_exposure`. Corpus-wide baselines (no DNSSEC, no MTA-STS, verification
tokens) are kept in the derived set but never headline a row, so each company gets
its own stack-specific signal.

`data/vulns-superset.jsonl` is the mined superset-sh corpus (284 rows, 200 blind_spot
/ 84 standard) produced by `data/build_vulns.py` (report.json -> pairs), with
`data/deidentify.py` doing hosts->`*.example`, secret VALUE -> described TYPE,
and a residue gate.
