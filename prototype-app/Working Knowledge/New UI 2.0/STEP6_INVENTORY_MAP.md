# Step 6 Inventory retirement slice

Starting commit: `0f1671086bcbfbaa8370f8cdbbface0ed859e250` (verified CVE slice). The original baseline remains the run on `68a4a3bc` in `/private/tmp/sg-ui2-step6.QsSmLw/baseline`; all three retained files match `source.json`.

## Ownership captured before CSS edits

`tools/cascade-map.mjs` now has Inventory focus and explicit ownership by source sheet. Its main/lazy lists reflect the App imports and the anticipated Inventory base. `cascade-before.json` was captured before any Inventory CSS edits, with no Inventory base present.

| Source | Rules moved to `ui2/inventory-base.css` | Rules kept with existing owners |
|---|---:|---|
| `base.css` | 377 | 1262 rules, including navigation/flyouts, public pages, shared app controls and Campaigns |
| `cve-workbench.css` | 1 | 89 shared app/layout rules |
| `eol.css` | 181 | 12 shared filter/chip and connector responsive rules |
| `vuln-repo.css` | 34 | 115 dashboard rules |
| `finding-detail.css` | 5 | No rules; import stub retained for the final entry-point slice |
| `ai-security.css` | 61 | 250 policy, connector and remaining shared AI rules |

Selected roots cover Inventory shells and overview, host/software/AI details, software-identity controls, upgrade recommendations, lifecycle badges/drawers, quality review and slug suggestions, overview columns, AI dependency graphs, Inventory severity/coverage widgets and their Inventory ancestor overrides. Matching is on leading owned classes; shell navigation and policies/connectors remain with their owners. No selector was discarded because coverage or a search did not reach it.

## Consolidation and cascade

- Migrated 659 rules into the app-scoped Inventory base; merged six adjacent blocks with identical declarations by grouping their selectors. Different values, fallback declarations, conditional states and priorities are retained.
- The new base uses `:where(html[data-ui='2'])`, preserving original selector specificity. No exact unconditional Inventory presentation replacement justified dropping a declaration, so none was dropped on that basis.
- Import order is primitives, Inventory base, Findings base, CVE base, then every family presentation sheet. Inventory base must precede Findings base: `.inventory-shell` and `.ai-security-page` can be on the same element, with equal specificity; the existing Findings grid must keep winning over the Inventory flex default. The stronger Inventory-specific AI widget selectors retain their precedence. No animation ownership changes are needed.
- Shared lifecycle/quality/host/software controls remain available on direct loads of other app families. Existing Findings, CVE and Inventory presentation sheets remain intact. The CVE scope assertion protecting the Inventory dashboard panel now checks its new Inventory owner; the assertion is retained.
- All 35 affected routes are selected for this shared base, including public isolation. Added scope assertions for direct-load layout, narrow overview columns, lifecycle tones, graph positioning, retired definitions and preserved navigation/connector/policy owners.
- The recorded Inventory focus/disabled-source-order issue remains open. No unrelated defect, token colour, visual baseline or tolerance is changed.

## Evidence and limits

Scratch evidence: `/private/tmp/sg-ui2-step6.QsSmLw/gate-inventory/`.

The before/after cascade maps record effective order and selected ownership; zero selected legacy ownership entries remain. `migration-manifest.json` records each selected selector, source line, conditional context and declaration, and the six merged rule blocks. `migration-verification.json` verifies 2424 retained declaration/selector pairs and every remaining rule in all six source sheets against the starting commit.

Static overlaps are review aids, not browser regression counts. The fast slice gate is recorded in S6 of `CLEANUP_PROGRESS.json`. Full visual/affected-route/axe/live/build/coverage/bundle checks remain due at checkpoint B immediately before final version-switch/bridge removal, then at Step 8. No browser or live pass is claimed here. Staging and human reviews remain waived; accessibility review remains open.

Post-commit fast gate on `0285f459c7aa5d5ff31c19a18e20e6c9080436e7`: lint 0 errors / 2 existing warnings; typecheck passed; Vitest 779 passed / 0 failed / 0 skipped in 84 files, including 23 scope tests. Tested frontend tree: `2e5df120491d1ac39f8b73022e652b27d5917dd1`. Only ledger and handoff/map evidence is amended afterward.
