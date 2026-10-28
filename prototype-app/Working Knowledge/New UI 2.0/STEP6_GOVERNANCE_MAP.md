# Step 6 Governance retirement slice

Starting commit: `c81822c2b66bbc295b86d700ce5a6651cba7e405` (verified Inventory slice). The original Step 6 baseline remains the run on `68a4a3bc` in `/private/tmp/sg-ui2-step6.QsSmLw/baseline`; all three retained files match `source.json`.

## Ownership captured before CSS edits

`tools/cascade-map.mjs` now has Governance focus and explicit ownership by source sheet. `cascade-before.json` was captured before any Governance CSS edits, with no Governance base present. The updated main/lazy lists include the anticipated base in effective order.

| Source | Rules moved to `ui2/governance-base.css` | Rules kept with existing owners |
|---|---:|---|
| `base.css` | 3 | 1259 shared app, public, shell, connector and Experience rules |
| `shared.css` | 17 | 246 shared app and operations rules |
| `user-management.css` | 62 | No rules; import stub retained until the final entry-point slice |
| `ai-security.css` | 230 | 22 connector layout, run/scope and reduced-motion rules, plus their reveal keyframes |

Ownership covers tenant-creation form layout, the shared console frame/navigation, tenant user/role/invite/audit cards and portaled dialogs, platform/tenant AI policy catalog/studio/detail, and shared AI security controls. Connector and operations roots remain with their owners. No selector is discarded because coverage or a search did not reach it.

## Consolidation and cascade

- Migrated 312 rules behind `:where(html[data-ui='2'])`, preserving specificity, values, priorities and conditional contexts. One pair of adjacent rules with identical declarations is grouped (narrow user form and audit row); different values/fallbacks remain.
- Import order is primitives, Inventory base, Findings base, CVE base, Governance base, then all family presentation sheets. This retains shared AI policy roots after the CVE/Findings defaults while keeping the stronger existing Governance presentation intact. No exact unconditional presentation replacement justified dropping a declaration.
- Console and shared AI controls retain consumers on other app pages. User-management dialogs remain available on cold loads; their actions, focus behavior, auth/role gates and queries are unchanged. This is CSS ownership only.
- `ai-security-reveal`, its connector animation and reduced-motion rule remain in `ai-security.css` for Connect. No animation is moved or renamed in this slice.
- All 35 affected routes are selected for the shared base, including public isolation. Scope tests cover hidden policy workspaces, disabled controls, portaled dialogs, responsive forms, retired definitions and remaining connector/operations owners. The Inventory assertion protecting the policy hero now checks its Governance owner; the assertion is retained.

## Evidence and limits

Scratch evidence: `/private/tmp/sg-ui2-step6.QsSmLw/gate-governance/`.

The before/after cascade maps record effective order and ownership; zero selected legacy ownership entries remain. `migration-manifest.json` records every selected selector, source line, context and declaration, plus the grouped responsive rules. `migration-verification.json` verifies 1156 retained declaration/selector pairs and every remaining rule in all four source sheets against the starting commit.

Static overlap counts are review aids, not browser regression counts. The fast slice gate is recorded in S6 of `CLEANUP_PROGRESS.json`. Full visual/affected-route/axe/live/build/coverage/bundle checks remain due at checkpoint B immediately before final version-switch/bridge removal, then at Step 8. No browser or live pass is claimed here. No visual baseline, tolerance, token colour, behavior or unrelated defect changes. Staging and human reviews remain waived; accessibility review remains open.

Post-commit fast gate on `66916f0abb8e3c12ed855ac915cbb2df8c505af9`: lint 0 errors / 2 existing warnings; typecheck passed; Vitest 781 passed / 0 failed / 0 skipped in 84 files, including 25 scope tests. Tested frontend tree: `8c1e1a7f0b5e6c024f0907fed758e89ec542c6a3`. Only ledger and handoff/map evidence is amended afterward. `keyframe-verification.json` also confirms the original keyframes in all four source sheets are unchanged.
