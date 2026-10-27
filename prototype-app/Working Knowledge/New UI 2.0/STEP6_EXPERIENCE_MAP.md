# Step 6 Experience retirement slice

Starting commit: `b0a029b1b2608535e9f9892dd7b38f057451a0e0`. Original baseline: `68a4a3bc` in `/private/tmp/sg-ui2-step6.QsSmLw/baseline`; checksum-verified and unchanged.

Experience owns dashboard, Campaign and operations layouts, including exposure grids shared with Inventory. Its zero-specificity base loads before Inventory base and family presentation. Public/auth-entry markup and shared app/shell defaults remain for public/final extraction.

## Ownership before CSS edits

Updated `tools/cascade-map.mjs` ownership and effective main/lazy order before capturing `cascade-before.json`. `cascade-after.json` records the new owner in load order.

| Source | Rules moved | Remaining rules unchanged |
|---|---:|---:|
| `src/styles/base.css` | 620 | 519 |
| `src/styles/shared.css` | 21 | 179 |
| `src/styles/cve-workbench.css` | 8 | 74 |
| `src/styles/vuln-repo.css` | 115 | 0 |
| `src/styles/exposure-dashboard.css` | 111 | 0 |

Preserved 3501 declaration/selector pairs including conditional and state rules. Consolidated 2 identical repeats and 6 adjacent identical blocks. Different values, fallbacks and priorities remain. No selector was removed due to coverage reachability.

Scratch evidence: `/private/tmp/sg-ui2-step6.QsSmLw/gate-experience/`: migration manifest, declaration verifier, before/after cascade maps and fast logs. Static maps are review aids, not browser passes. All affected routes and public isolation remain due at checkpoint B.

No visual baseline/tolerance, severity colour, behavior or unrelated defect is changed. Staging/human reviews waived; accessibility review open. The final version switch and bridge removal remains after checkpoint B.

Post-commit fast gate on `4f968a4475525f1983634364e5df369d1aeab0b7`: 785 passed / 0 failed / 0 skipped in 84 files (29 scope tests); lint 0 errors / 2 existing warnings; typecheck passed. Tested frontend tree: `96583ccefaad89b8bc5fc57b83623997dba3c510`.
