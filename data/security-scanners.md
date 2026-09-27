# Security review — probe scanner + hunting framework

Static review of two tools that feed the customsecuritymodel pipeline:

1. **probe-web scanner** — `~/probe-web/scanner/` (`quick_probe.py` + `quick_probe_lib.py` +
   `mcp_probe.py`, `s3_public_probe.py`, `supabase_rls_probe.py`, `stack_fingerprint.py`), plus the
   sibling `~/probe/probe-web/scanner/quick_probe.py` (urllib/dig variant).
2. **hunting framework** — `~/probe/hunting/` (`llm.py`, `oversight.py`, `hunt.py`, `lib.py`,
   `scanner.py`, `policy.py`, `chain_analysis.py`, `high_impact.py`, `smart_detect.py`,
   `identity.py`, `scope.py`, and the `deep_*.py` modules).

Findings: `data/vulns-scanners.jsonl` (F-SCN-01 … F-SCN-16). All evidence cites `file:line`.
No live targets were touched; everything below is read from source.

---

## 1. Per-target summary

### 1.1 probe-web scanner (`quick_probe_lib.py`, `quick_probe.py`, satellites)

A 90-second, parallel, high-yield web scanner. Sound parts: deadline-bounded probes, capped
response bodies (`MAX_BODY`, `MAX_BUNDLE_TOTAL`), a one-time private-IP guard on the target,
and evidence objects that truncate secret material. Sound overall design, with five real gaps:

- **TLS verification is disabled globally** (`verify=False` on every request, warnings silenced).
- **Redirects are followed by default**, so a hostile scanned page can SSRF the scanner itself
  into link-local/metadata endpoints, and the returned data lands in findings.
- **The private-IP guard is check-once** (DNS-rebindable) and only exists in the entry point.
- **Phase 2 is dead code**: `quick_probe.py` references three `qpl.*` probes that do not exist,
  so every scan crashes after phase 1 and the SSRF/IDOR/injection/payment probes never run.
- **Dig is invoked with the operator-supplied domain as a raw argv item** (option injection).

### 1.2 hunting framework (`llm.py`, `oversight.py`, `hunt.py`, `scanner.py`, `high_impact.py`, `deep_*.py`)

A bug-bounty orchestration layer: scoped host list → parallel high-impact scan → policy remap →
LLM oversight judge → bounty draft. Sound parts: deadline/timeout discipline, read-only intent
on most probes, per-hunt scope filtering, idempotency-conscience (dedupe), and a clean separation
of the policy remap from raw probe output.

The framework's risks cluster around **one design choice**: it pipes *untrusted web content*
into an *LLM judge*, and around **several operational choices** (mutation-capable probes, unbounded
downloads, world-readable secret-bearing outputs, env-carried API keys, process-kill by pid file):

- **Prompt injection into the oversight judge** — raw page/JS/XML-RPC text reaches the model
  verbatim through finding `detail`/`evidence` (F-SCN-04), and the "trusted" `CONTEXT.md` policy
  block is itself an unauthenticated file (F-SCN-16). The verdict is a single steerable call with
  no programmatic gate (F-SCN-13).
- **The scanner is an SSRF proxy** (redirects followed, private-IP guard absent in this framework)
  and can OOM itself on unbounded bodies (F-SCN-02/03/07).
- **Auto-mutating verbs** (PUT/DELETE/POST coupon/verb-tamper probes) fire at third-party
  production systems off a URL heuristic (F-SCN-08).
- **Key handling** — `PROBE_LLM_BASE_URL` can redirect the live API key with no scheme check;
  the key is exported to every child process for hours (F-SCN-05/06).
- **Secret-bearing output files** (report.json, hunt.log, oversight-raw.txt) are default-permission
  and unencrypted (F-SCN-10).
- **The scanner's own severities become the "gold" training labels** of the custom model — the
  circularity at the heart of F-SCN-14.

---

## 2. Top findings (ranked)

| ID | Severity | Finding |
|---|---|---|
| F-SCN-02 | **HIGH** | Redirect-following turns the scanner into an SSRF proxy; internal/metadata responses flow into findings and reports |
| F-SCN-04 | **HIGH** | Attacker-controlled page text reaches the oversight LLM verbatim → verdict steering (prompt injection) |
| F-SCN-01 | MEDIUM | `verify=False` on every data-collection request (both frameworks) |
| F-SCN-03 | MEDIUM | Private-IP guard check-once (rebindable) / absent in hunting scanner |
| F-SCN-05 | MEDIUM | `PROBE_LLM_BASE_URL` env override redirects the live provider key (no scheme check) |
| F-SCN-07 | MEDIUM | Unbounded body reads OOM the hunting scanner |
| F-SCN-08 | MEDIUM | Automatic PUT/DELETE/POST mutations against third-party production systems |
| F-SCN-09 | MEDIUM | Undefined phase-2 probes crash the probe-web scan → highest-value probes never run |
| F-SCN-10 | MEDIUM | Secret-bearing reports/logs/raw model output written world-readable |
| F-SCN-13 | MEDIUM | Oversight verdict is a single steerable LLM call, no programmatic gate |
| F-SCN-14 | MEDIUM | Scanner heuristic severities become the model's gold labels (no ground truth) |
| F-SCN-06 | LOW | Provider key in every child-process environment for hours |
| F-SCN-11 | LOW | `dig` option injection via crafted domain |
| F-SCN-12 | LOW | hunt.pid trust → same-user process-kill primitive |
| F-SCN-15 | LOW | Raw page text interpolated into bounty.md (markdown/report injection) |
| F-SCN-16 | MEDIUM | Untrusted `CONTEXT.md` treated as authoritative policy in the judge prompt (suspected) |

---

## 3. Which findings matter most for the customsecuritymodel build

The build's pipeline is **scan → de-identify (`build_pairs.py`) → train on River → serve → eval**.
Three scanner findings are load-bearing for that loop:

1. **F-SCN-04 / F-SCN-02 — scanner output is attacker-influenceable.** The scanner emits
   untrusted web content that flows verbatim into (a) findings `detail`/`evidence`, (b) the
   oversight judge prompt, and (c) — through `build_pairs.py` — the *training data of the owned
   model* (`input` = `type: …; host: …; detail: <page text>`). A malicious scanned page can both
   **poison training rows** (teach the model to follow embedded instructions) and **steer
   inference** at triage time, because the infer seam concatenates the untrusted detail with the
   trusted instruction and the model has no instruction hierarchy. This is the single most
   important cross-cutting risk for the owned model.

2. **F-SCN-14 — labels are the scanner's own heuristics.** The model's gold severities come from
   `make_finding` tables and ad-hoc rules (some driven by untrusted page content). The eval
   harness scores model-vs-rulebook against the same heuristic labels, so a "win" can be
   overfitting the scanner, not learning ground truth. The demo's blind-spot claim rests on this
   label source.

3. **F-SCN-10 — the scanner's secret-bearing output is the raw material of the corpus.**
   `build_pairs.py` reads `report.json` files that can hold live keys, key prefixes, and
   enumerated emails; the de-identification layer scrubs only hosts/IPs/emails/brand and does
   **not** redact secrets, so anything embedded in a finding `detail` passes through into the
   training JSONL and the River upload.

The rest (TLS-off, SSRF-of-scanner, mutation probes, key exfil via base-url override, unbounded
downloads, dead phase-2) matter for whoever operates the fleet; the first two are the ones that
degrade the *model's* integrity and the confidentiality of its training data.

Full pipeline-level treatment (de-identification guarantees, the triage/infer injection seam,
checkpoint custody, API keys, pair supply-chain, loop trust boundaries) is in
`SECURITY-ARCHITECTURE.md` → `## Pipeline self-security (customsecuritymodel)`.