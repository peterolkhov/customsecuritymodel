# RUNLOG — customsecuritymodel (hack/ws-stacks)

One row per action: `UTC_TIMESTAMP | ACTION | FILE(s) | RESULT/CHECK | DECISION`.

| UTC timestamp | ACTION | FILE(s) | RESULT/CHECK | DECISION |
|---|---|---|---|---|
| 2026-09-27T21:04:00Z | recon: probe corpus inventory, report.json schema, pair contract | data/README.md, example.pairs.jsonl, ~/probe/out | 1040 target dirs; report.json = scope/generated/findings[] with type/severity/detail/location; pairs contract confirmed | use 3 observed refs (affirm=fintech, 3sixteen=d2c, alivecor=health) |
| 2026-09-27T21:07:00Z | gather de-identified finding detail from 3 reference targets | (read-only) ~/probe/out/{affirm-com-deep-payment,3sixteen-com-deep,alivecor-com-deep-exploit}/report.json | 1166 / 30 / 1652 findings; high-signal types: mcp_tools_unauth, clerk_dev_instance_in_prod, shopify_ucp_surface, oauth_grant_type_abuse, grpc_reflection_exposed, sandbox_escape_surface | use observed types + stacks to author suite checks |
| 2026-09-27T21:09:00Z | import suite/build_suite.py from ws-suite; fixture smoke | suite/build_suite.py, suite/smoke.example.md | build_suite.py runs offline (model=none, brain=none) on example.pairs.jsonl; 6 rows | keep generator; rm smoke artifact |
| 2026-09-27T21:12:00Z | author + emit 6 per-company pairs inputs (de-identified, *.example only) | data/suite-inputs/{ledgerway,northbridge,pulsepath,gbrain-oss,qm-oss,river-sdk-oss}.example.jsonl | 10-12 rows each; all hosts *.example; no real host/IP/email/key; provenance.class standard|blind_spot stamped | verified contract + de-id scan clean |
| 2026-09-27T21:13:00Z | run build_suite.py per company → suites | suite/*.example.md (6 files) | ledgerway 11, northbridge 10, pulsepath 11 (regen → 12), gbrain-oss 10, qm-oss 10, river-sdk-oss 10 numbered checks; headers render | pulsepath rebuilt at 7/5 for 12 |
| 2026-09-27T21:16:00Z | author stack-references.md | stack-references.md | 6 reference stacks (slug, stack, 8-12 checks standard+blind_spot), 3 observed references cited with finding counts, de-identified | write as source-of-truth reference doc |
| 2026-09-27T21:20:00Z | verify markdown render + de-ident scan; README for suite-<slug> | suite/*.md, data/suite-inputs/*.jsonl | 10-12 checks/file, H1 per file; grep flagged only generic product names (Plesk, pk_test_ prefix) — no real data | commit |