# Step 6 Public retirement slice

Starting commit: `8cf278b85df8769476c5652a17747674e726a61e`. Original baseline: `68a4a3bc` in `/private/tmp/sg-ui2-step6.QsSmLw/baseline`; checksum-verified and unchanged.

Public rules and legacy tokens are extracted without redesign. Shared defaults remain available to app consumers at their original source positions through explicit import anchors. Public routes retain the app boundary; frozen UI 1 is the only legacy reference.

## Ownership before CSS edits

Updated `tools/cascade-map.mjs` ownership and effective main/lazy order before capturing `cascade-before.json`. `cascade-after.json` records the new owner in load order.

| Source | Rules moved | Remaining rules unchanged |
|---|---:|---:|
| `src/styles/base.css` | 327 | 192 |

Preserved 1345 declaration/selector pairs including conditional and state rules. Consolidated 0 identical repeats and 0 adjacent identical blocks. Different values, fallbacks and priorities remain. No selector was removed due to coverage reachability.

Scratch evidence: `/private/tmp/sg-ui2-step6.QsSmLw/gate-public/`: migration manifest, declaration verifier, before/after cascade maps and fast logs. Static maps are review aids, not browser passes. All affected routes and public isolation remain due at checkpoint B.

No visual baseline/tolerance, severity colour, behavior or unrelated defect is changed. Staging/human reviews waived; accessibility review open. The final version switch and bridge removal remains after checkpoint B.

Post-commit fast gate on `7d98e7c8dccd6a7dc19dc28c5ebf43cac20d0dcc`: 787 passed / 0 failed / 0 skipped in 84 files (31 scope tests); lint 0 errors / 2 existing warnings; typecheck passed. Tested frontend tree: `b95f22382fb0250b5c1f548538955203acaa2b6d`.

Post-commit fast gate on `bab2276bb060e6f67c3e4e421bcbf6c62d7246ac`: 787 passed / 0 failed / 0 skipped in 84 files (31 scope tests); lint 0 errors / 2 existing warnings; typecheck passed. Tested frontend tree: `806521eeec733a6d923895ae360c773034fae1df`.

Checkpoint B attempt 1 caught a missing semicolon on the serialized font import in base.css. Fixed the terminator and added a scope assertion before the corrected public fast gate. Original failure logs remain in `/private/tmp/sg-ui2-step6.QsSmLw/gate-checkpoint-b-attempt-1/`; its browser steps also hit sandbox EPERM on local port binding. The next host run uses local-server permission.
