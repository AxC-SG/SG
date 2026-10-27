# Step 6 Connect retirement slice

Starting commit: `342c8be7f0935d2f37e048cb49442cb7518aa6ba`. Original baseline: `68a4a3bc` in `/private/tmp/sg-ui2-step6.QsSmLw/baseline`; checksum-verified and unchanged.

Connect base follows Governance base and precedes presentation sheets. Shared provider/configuration controls retain their consumers; the feed catalog is eager. Connector reveal uses private ui2-connect-reveal; original reduced-motion state is preserved.

## Ownership before CSS edits

Updated `tools/cascade-map.mjs` ownership and effective main/lazy order before capturing `cascade-before.json`. `cascade-after.json` records the new owner in load order.

| Source | Rules moved | Remaining rules unchanged |
|---|---:|---:|
| `src/styles/base.css` | 121 | 1138 |
| `src/styles/shared.css` | 46 | 200 |
| `src/styles/cve-workbench.css` | 9 | 80 |
| `src/styles/connect.css` | 115 | 0 |
| `src/styles/eol.css` | 4 | 8 |
| `src/styles/ai-security.css` | 22 | 0 |
| `src/pages/platform-feed-catalog.css` | 54 | 0 |

Preserved 1341 declaration/selector pairs including conditional and state rules. Consolidated 5 identical repeats and 3 adjacent identical blocks. Different values, fallbacks and priorities remain. No selector was removed due to coverage reachability.

Scratch evidence: `/private/tmp/sg-ui2-step6.QsSmLw/gate-connect/`: migration manifest, declaration verifier, before/after cascade maps and fast logs. Static maps are review aids, not browser passes. All affected routes and public isolation remain due at checkpoint B.

No visual baseline/tolerance, severity colour, behavior or unrelated defect is changed. Staging/human reviews waived; accessibility review open. The final version switch and bridge removal remains after checkpoint B.

Post-commit fast gate on `6089638c3bdafbb34ec73e7d57684b0f86a7b328`: 783 passed / 0 failed / 0 skipped in 84 files (27 scope tests); lint 0 errors / 2 existing warnings; typecheck passed. Tested frontend tree: `c57a0fa14626f854eceb7b91c9a566edc717842b`.
