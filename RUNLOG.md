# RUNLOG — hack/ws-vuln-river

Task: vuln-river — security architecture + static review of River AI client/server contract.
Format: `UTC_TIMESTAMP | ACTION | FILE(s) | RESULT/CHECK | DECISION`

| UTC | ACTION | FILE(s) | RESULT/CHECK | DECISION |
|---|---|---|---|---|
| 2026-09-27T21:10:00Z | start | RUNLOG.md | workspace scanned, git branch hack/ws-vuln-river clean | proceed |
| 2026-09-27T21:10:49Z | read sdk | river_client/{client,metrics,types,images,tokenizers,sampling,skill,_nested_codec,__init__}.py, _proto/* | SDK 0.12.0 located; client.py 5493 lines; gRPC + HTTPS surfaces mapped | continue |
| 2026-09-27T21:12:00Z | read reference | petergraph/.../reference/river.md, data/README.md, example.pairs.jsonl | contract: instruction/input/output + provenance{class,observed_at}; pair shape confirmed | emit findings per contract |
| 2026-09-27T21:15:00Z | review (static) | river_client/client.py:4248-4463, 4472-4521, 4561-4602, 4937-5012, 5235-5345 | auth=x-api-key gRPC + Bearer HTTP; use_ssl default True/443; retry UNAVAILABLE≤1800s; no key logging | key findings F-RIV-01/02/09/11 |
| 2026-09-27T21:18:00Z | review (static) | river_client/tokenizers.py:136-140,72; client.py:4290; images.py:108-180 | trust_remote_code=True; hf_hub_download unpinned; image store 0700+sha256 | findings F-RIV-03/04/12 |
| 2026-09-27T21:20:00Z | review (static) | client.py:2161-2240,3736-3809; types.py:368-422 | checkpoint path verbatim (no client validation); river:// refs only; no download API | findings F-RIV-05/06/07/08 |
| 2026-09-27T21:22:00Z | review (static) | metrics.py:39-73,266-294 | bearer key to metrics console endpoint; RIVER_CONSOLE_URL override no scheme check | finding F-RIV-10 |
| 2026-09-27T21:25:00Z | write | RUNLOG.md | session log initialized; every subsequent action appended | maintain one row per action |
| 2026-09-27T21:28:00Z | write | SECURITY-ARCHITECTURE.md | trust model + review + findings map (F-RIV-01..12) drafted | emit findings JSONL next |
| 2026-09-27T21:32:00Z | write | data/vulns-river.jsonl | 12 finding rows per data/README.md contract | validate JSONL |
| 2026-09-27T21:35:00Z | check | data/vulns-river.jsonl | python json validate: 12 rows, keys present, class standard|blind_spot, targets *.example, no IP/email/foreign host | pass; de-identified console.river.ai -> 'metrics console endpoint' |
| 2026-09-27T21:37:00Z | write | stack-references.md | river block appended (SDK/auth/transport/checkpoint/serving/custody/notes) | push milestone |
| 2026-09-27T21:41:00Z | commit+push | all deliverables | git commit hack: vuln-river security architecture + static SDK review; branch hack/ws-vuln-river pushed to origin | milestone verified |
| 2026-09-27T21:42:00Z | gbrain remember | memory | fact #251 saved, entity=vuln-river, kind=event, provenance=runlog | recall-able milestone |