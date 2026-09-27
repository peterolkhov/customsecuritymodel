# RUNLOG — vuln-qm

Task: security architecture + static vuln hunt on QM (YC's multiplayer agent harness).
Source: `/Users/peterolkhovets/yc-hackathon/qm` @ b6abeaf (2026-09-26). All timestamps UTC.

| when | action | file(s) | result/check | decision |
|---|---|---|---|---|
| 2026-09-27T21:17:21Z | read SECURITY.md + reference qm.md + data contract | SECURITY.md, qm.md, data/README.md | posture model, known limitations, JSONL contract understood | proceed with static hunt |
| 2026-09-27T21:17:21Z | explore src/ tree: sandbox, sessions, memory, credentials, policy, api | src/** | map of execute/egress/memory/keychain/acl surfaces | delegate 3 deep-dive audits |
| 2026-09-27T21:17:21Z | keychain/credentials audit (subagent) | src/credentials/* | F1-F21: AES-GCM at rest, env-only key, base64 file creds, unbounded principalId connector route | verified top signals |
| 2026-09-27T21:17:21Z | permission/acl/capability audit (subagent) | src/auth, src/resolution, src/api | aud-less session-cap, source-only memory/principals routes, historical-scope file access, slack TOCTOU | verified top signals |
| 2026-09-27T21:17:21Z | execute path/stores/webhooks audit (subagent) | src/tools, src/sessions, src/config.ts | default memory session/run store, SECURITY_SCREEN_BACKEND=off default, regex-only execute gate, masking gaps | verified defaults |
| 2026-09-27T21:17:21Z | verify defaults + npm audit | src/config.ts:1040,1058,1359,1439,1432; npm audit --omit=dev | posture auto, screen off, memory stores; **audit clean 0 vulns** | record dep posture as positive |
| 2026-09-27T21:17:21Z | write SECURITY-ARCHITECTURE.md + data/vulns-qm.jsonl + stack-references.md | repo root, data/, stack-references.md | 18 findings, both classes; JSONL validated | push milestone |
| 2026-09-27T21:17:59Z | validate JSONL + gbrain remember + push | data/vulns-qm.jsonl, SECURITY-ARCHITECTURE.md, stack-references.md | 18 rows valid (10 standard / 8 blind_spot); npm audit 0; artifacts written | push milestone |
