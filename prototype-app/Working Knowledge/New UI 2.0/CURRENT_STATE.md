# Current UI 2.0 state

Updated October 28, 2026 against source commit `eedc8a0864cadf7c0cd0e55ec733f4637ff6622a` plus this documentation cleanup. This records source completion separately from release qualification.

## Implemented state

- UI 2.0 is the only tenant/platform/auth presentation. `VITE_UI_VERSION`, `uiVersion.ts`, `UiVersionPresentation`, `legacy-bridge.css`, compatibility aliases and superseded app/page stylesheets are retired.
- `main.tsx` eagerly imports `styles/index.css`. Public defaults load first, then canonical app tokens, shared app/shell/primitives, family base/presentation, table controls and XYFlow vendor CSS in deterministic order. All active app families use this entry.
- `presentationBoundary.ts` and router-aware `PresentationBoundary` own `data-ui="2"` outside `/demo`; login/setup/invites use UI 2.0. Direct load, links and Back/Forward preserve that boundary. `scoutai-theme` and the mounted app's dark default remain; public surfaces retain their intentional light local palette.
- Supported workflows reuse existing feature queries, request helpers, types, calculations, roles/entitlements and mutation handlers. No API, auth, tenancy or database migration was introduced by presentation retirement.
- Proven-unused mock/retired page code and unused direct dependencies were removed in S3. `/fix-intelligence/*` still redirects to `/findings`; typed compatibility route helpers remain. Runtime evidence, generic Azure, SCCM JDBC, Fix Intelligence and unsupported patch pipelines remain contained.
- Active browser tooling lives in `frontend/e2e/`: deterministic fixtures, route map, family journeys, visual/axe/journey baselines, artifact boundary checks and live journeys. Quality and scheduled sweep workflows test UI 2 only. Frozen UI 1 baselines are historical.
- Later commits `2f5abf42`, `6bb3376e`, `26c3bc26`, `1faab124` and `eedc8a08` corrected universal selectors/stored theme, public/auth dark contrast and canvas/header palettes, adjusted the scope expectation and refreshed inspected dark auth snapshots. Do not revert those fixes to match older family maps or counts.

For exact current ownership and commands, see [styles and rollback](../../docs/ui2-styles-and-rollback.md). For all future screens use [the UI development standard](../../docs/ui-development-standard.md); shared-pattern departures require approval with pros/cons and an affected-screen consistency plan.

## Historical evidence and remaining qualification

`IMPLEMENTATION_PROGRESS.json` records original phases; `CLEANUP_PROGRESS.json` records S0–S7, checkpoint A/B, retirement decisions, waivers and measurements. Preserve their original dates and source attribution. Their old `nextUnit`, personal scratch paths and deleted-file references are historical and may no longer be runnable. No fresh final release gate is inferred from the user's statement that the migration is complete.

| Evidence | Recorded scope and limitation |
|---|---|
| Cleanup S0/S1/S3/S4 | Candidate import, real local backend checks, unused-code removal and shared foundation consolidation recorded as verified |
| S2 tooling | Implemented in `frontend/e2e/` and CI, while the ledger still says `in_progress`; reconcile outstanding evidence rather than auto-closing it |
| Step 5 decision/checkpoint A | Retirement authorized with recorded staging/human-review waivers and deferred-check plan; frozen UI 1 artifact retained |
| Checkpoint B | 737 fixture checks passed; 140 visual plus 140 affected snapshots passed; no new axe violations relative to its baseline; local live evidence 250 passed and 2 outbound ServiceNow provider skips. Results apply to the checkpoint sources, not later fixes |
| Final retirement fast gate | 801 tests in 84 files passed, including 35 scope checks, on the recorded final-slice source before subsequent public/auth fixes; not a branch-tip full qualification |
| Step 7 | Source baseline archived and verified; documentation/archive work completed |
| Accessibility | Baselines retain known findings; full accessibility closure is not recorded. The historical focus-ring defect was fixed before retirement; do not list it as still unfixed solely from the old decision package |
| Final branch-tip qualification (Step 8) | Not recorded as complete in the retained ledger: fresh quality/build/coverage, browser/visual/axe sweeps, live persistence/failure/retry, keyboard/real zoom, performance/bundle, backend/Postgres, applicable CI and verified-artifact rollback evidence remain separately attributable to the candidate |
| Deployment/release | No deployment or release approval is implied by migration or documentation completion |

Do not turn missing evidence, unavailable accounts/data or provider skips into passes. Staging and human review were explicitly waived in the recorded development decision; preserve those waivers and their scope rather than silently reinstating or expanding them.

## Documentation cleanup on October 28

The migration folder was reduced to the previous-state record, implemented plans, this current-state record, index, two historical evidence/decision ledgers, two archive/checksum/manifest sets and six qualification/rehearsal scripts with their README. The original final plan supplied by the user remains byte-identical; its tracked duplicate `CLEANUP_PLAN.md` was removed.

Removed 107 obsolete tracked files and generated/ignored material: standalone mock/reference app and its dependency/build trees, start/continue prompts, intermediate family/decision maps, superseded behavior/source-hash/route checklists, duplicate checkpoints/screenshots/logs, and five obsolete diagnostic/gate wrappers. The removed tracked files are recoverable from Git at the source commit above. In total, 12,299 files (397,357,874 bytes, about 379 MiB) of obsolete/generated material were removed; these are filesystem totals, not an app bundle reduction.

The remaining six scripts support still-open final qualification or the retained rollback artifact; their inputs and limits are in [tools/README.md](tools/README.md). They must not be mistaken for already-executed final gates. Active CI fixtures and baselines were retained under `frontend/e2e/`.

All four `CLAUDE.md` files and all existing `prototype-app/docs` guides were aligned with the new presentation and linked to the required development standard. Historical backend/domain material remains; the UI migration does not authorize redesigning those contracts. The unrelated pre-existing deleted mockup and untracked correlation PDF were left untouched.

The archive verifier now supports both manifest layouts (P0's named root and the frozen build's tar-root paths). Both retained archives pass SHA-256/per-file verification: 320 source entries and 86 frozen-build entries.

## Verification of this cleanup

- `npm run lint`: passed, 0 errors and 2 existing warnings (`PageFreshnessStatus.tsx` Fast Refresh export and `ConfigurationsPage.tsx` effect dependency).
- `npm run typecheck`: passed.
- `npm run build`: passed, including the production credential/bundle guard.
- Targeted Vitest: 68 tests passed in `styles/ui2/scope.test.ts`, `lib/presentationBoundary.test.ts` and `app/PresentationBoundary.test.tsx`.
- Both retained archives pass whole-archive/per-file integrity checks (320 and 86 entries). Deliberately tampered per-file hashes in copies of both manifest formats fail verification as expected.
- All 174 local Markdown file targets in the docs, CLAUDE guidance and retained Markdown handoff resolve. The original final plan and both evidence ledgers remain byte-for-byte intact; the unrelated pre-existing changes remain untouched. `git diff --check` passes.

This was documentation/artifact cleanup with an archive-root compatibility fix and stale source-comment updates. Full frontend coverage, live backend journeys, pinned-container visual/axe runs, backend/PostgreSQL checks and remote CI were not rerun for this cleanup; it does not close Step 8 or certify a release. No app workflow, runtime presentation rule or API changed.
