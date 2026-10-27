# Step 6 CVE retirement slice

Starting commit: `dbe0bab16f894379610db773a73b7dc1ac55be96` (verified Findings slice). The Step 6 starting baseline remains the run on `68a4a3bc` in `/private/tmp/sg-ui2-step6.QsSmLw/baseline`. All three retained files match `source.json`; this slice does not replace that baseline.

## Ownership captured before CSS edits

`tools/cascade-map.mjs` now has a CVE focus and explicit legacy ownership. Its main list follows `styles/index.css`, `ui2/index.css`, then the App imports for finding-detail and AI security. DataTable, Findings, feed-catalog and XYFlow sheets remain in the conservative lazy tail. The new CVE base loads after Findings base and before all family presentation sheets.

| Source | Rules moved to `ui2/cve-base.css` | Rules kept with existing owners |
|---|---:|---|
| `base.css` | 31 | Shell, public, Inventory, Campaign and all other roots |
| `shared.css` | 77 | Shared app controls and other families |
| `cve-workbench.css` | 1089 | 90 shared control/layout rules, including confirm dialogs, segmented controls, column toggles, and responsive shell/filter/dashboard layouts |
| `vuln-repo.css` | 61 | 149 dashboard and Inventory rules |

Ownership includes CVE/organization records, investigation steps and criteria, record-detail tabs, notification drafts, Intelligence controls, AI solution details and the shared investigation markdown table. Only leading owned classes move: Inventory/dashboard ancestor overrides stay in their source. Selected, hover, focus, disabled, responsive and permission-dependent styles are retained without using coverage as a deletion filter.

## Consolidation and shared consumers

- Migrated 1,258 rules behind `:where(html[data-ui='2'])`, preserving specificity, values, priorities, conditional context and source-relative order. The stronger presentation selectors in `ui2/cve.css` remain unchanged.
- Removed six declarations superseded by unconditional CVE presentation rules with the identical selector body/property. Removed nine identical repeated declarations and one identical spin-keyframe definition. Different values and fallbacks remain.
- Private animation names are `ui2-cve-spin` and `ui2-cve-slide-in`. Shared `rise-in` stays in the legacy sheet for its remaining base.css consumer.
- Shared CVE detail classes used by tenant/platform AI policies, Inventory details and Campaigns keep their existing selectors behind the zero-weight app boundary. General app controls remain shared. Raw legacy colour values/token fallbacks are preserved; this slice does not redesign them or remove the bridge.
- `cve-base.css` maps to all 35 affected routes, including public isolation, because its components have consumers outside CVE. Added scope checks for direct-load controls, private animation names, retired definitions and preservation of other owners. Existing assertions remain.

## Evidence and limits

Scratch evidence: `/private/tmp/sg-ui2-step6.QsSmLw/gate-cve/`.

`cascade-before.json` was captured with no CVE base present and before migration. `cascade-after.json` records the resulting effective order. `migration-manifest.json` records every selected rule/declaration and its superseding declaration where applicable. `migration-verification.json` verifies 5,052 retained declaration/selector pairs and unchanged remaining rules: base 1,637; shared 263; cve-workbench 90; vuln-repo 149. No selected legacy ownership entries remain.

Static overlap counts compare subjects/properties; they include different ancestor contexts and expected presentation overrides. They are review aids, not browser regression counts. The fast slice gate is recorded in S6 of `CLEANUP_PROGRESS.json`. Full browser, visual, axe, live, coverage and bundle checks remain due at checkpoint B immediately before final version-switch/bridge removal, then at Step 8. No visual baseline or tolerance changed. Staging and human reviews remain waived; accessibility review remains open.

Post-commit fast gate on `c0d4f6f94bb946dc182abc0fe579e2d2bd53a9b8`: lint 0 errors / 2 existing warnings; typecheck passed; Vitest 777 passed / 0 failed / 0 skipped in 84 files, including 21 scope tests. Tested frontend tree: `6ff0d340d8c282bfa078017dbfd659c5ea9a0102`. Only ledger and handoff/map evidence is amended afterward.
