# Company flow — the 60-second demo (table expo / Loom)

A judge watches one terminal. Every command is offline. `#` lines are spoken copy.

```console
# "Every scanner checks the same OWASP floor. Customizing used to take a
#  security engineer weeks per company. We made it one command."

$ make company-demo
STEP 1/5 — pairs (de-identify scan -> training pairs)   58 findings -> 58 pairs (49 standard, 9 blind_spot)
STEP 2/5 — train (dry-run offline; --train goes live)   58 pairs -> 8 batches/epoch
STEP 3/5 — brain (ingest de-identified pairs -> GBrain)  ingested 58 findings -> 113 facts (backend local)
STEP 4/5 — suite (generate per-company security suite)   wrote company/out/suites/acme.example.md
STEP 5/5 — summary
  company:   acme (de-identified as acme.example)
  pairs:     58  severity split: CRITICAL:6, HIGH:17, MEDIUM:18, LOW:12, INFO:5
  checkpoint:none — dry-run (no owned model yet)
  suite:     company/out/suites/acme.example.md

# "Same flow, second company — a different stack, a different suite."

$ python3 company/run.py onboard --company ledgerway --scan demo/fixtures/ledgerway.com/report.json
  company:   ledgerway (de-identified as ledgerway.example)
  pairs:     60  severity split: CRITICAL:6, HIGH:20, MEDIUM:20, LOW:11, INFO:3

$ make company-selftest                                  # offline check: fixture -> pairs -> brain -> suite
$ python3 company/run.py status --company acme           # checkpoint / brain facts / suites / gbrain
$ python3 company/run.py infer --company acme --finding 'type: graphql_introspection; host: admin.acme-corp.com; detail: introspection enabled in prod'
  # (once a checkpoint exists: YOUR owned model's severity, not a rented frontier call)
```

**Why this is the product:** generic suites converge on the same blind spots for
every company; a LoRA trained on *this* company's own findings learns what
matters for *this* stack — in minutes, for dollars, with weights the company
holds, and memory that compounds scan over scan.