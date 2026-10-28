# ScoutGrid UI 2.0: final qualification and cleanup plan

## Context

This plan replaces the two drafts, `~/Downloads/Cleanup.md` and `~/Downloads/Backend + Cleanup.md`. The order is:

1. Protect the candidate.
2. Check it against the real backend.
3. Turn the existing scripts into repeatable gates.
4. Clean up.
5. Qualify for retirement.
6. Retire the legacy styles one family at a time.
7. Archive and document.
8. **Qualify the final branch tip after retirement.**

Two decisions you made:
- **Candidate:** the 15 files from the other worktree are imported first, using the validated combined patch and manifest.
- **CSS timing:** only the foundation styles are consolidated before retirement. Each other style family is made self-contained and has its legacy rules removed in its own slice, after the retirement decision.

What I confirmed in this checkout:
- `feat/ui2-phase-8-qualification` is at `ea815ef9` with no uncommitted changes.
- The floors in `frontend/vitest.config.ts:24-27` are 49.4/46.7/38.9/38.1. The 49.7/47.2/39.5/38.6 floors depend on the imported files.
- The browser scripts are in `Working Knowledge/New UI 2.0/browser-fixtures/`. They load Playwright through `PLAYWRIGHT_DIR` and axe through `AXE_PATH`.
- Only `findings-journey.mjs:203` and `live-journeys.mjs:745` set a failing exit code. The other journeys, `route-sweep.mjs` and `axe-audit.mjs` only report failures (for example `cve-journey.mjs:271`).
- `vike`, `vike-react` and `@resvg/resvg-js` appear only in `frontend/package.json`.
- The retired-page and mock candidates have no consumers in `frontend/src`.
- `/fix-intelligence/*` redirects to `/findings` (`frontend/src/App.tsx:1259`).
- `frontend/src/app/routes.ts` keeps the `fix-intelligence` helpers.
- The style switch is in `frontend/src/lib/uiVersion.ts` and `frontend/src/main.tsx:12`.
- UI 2.0 styles are imported at `frontend/src/styles/index.css:9`.

Rules that apply to every step:
- No changes to APIs, DTOs, auth, tenant scoping, or the **database schema and migrations**. Writing disposable test data to the qualification tenant is allowed and needed for persistence checks.
- No customer data. No external delivery except to an approved test endpoint.
- No database resets.
- **No push, merge or deploy.** Publishing to the remote needs separate approval.
- Each step is a separately reviewable local commit.
- Never lower coverage floors or remove assertions.

---

## Step 0: Import and protect the candidate

1. Create a local branch `feat/ui2-cleanup` from `ea815ef9`.
2. Check the validated combined patch and manifest against their hashes. Apply the patch, including all 3 untracked files. Confirm every file in the manifest matches its recorded hash after applying.
3. Commit locally with the message "Import UI 2.0 review fixes", so the reviewed work stays separate from later fixes. Keep the patch, manifest and hashes in a location that is not temporary or git-ignored.
4. Run `npm run lint && npm run typecheck && npm run build && npm run test:coverage`. Expect 759 tests in 84 files and floors of 49.7/47.2/39.5/38.6. Record any difference.
5. Create the cleanup ledger at `Working Knowledge/New UI 2.0/CLEANUP_PROGRESS.json`, using the format of `IMPLEMENTATION_PROGRESS.json`. Each unit records its files, evidence, tests, screenshots, limitations and how to reverse it. Statuses stay separate for fixture, local authenticated, staging and release.
6. Record the starting numbers: source files and lines, direct dependency count, and raw and gzip CSS/JS sizes for both UI versions.

**Exit:** the candidate is committed locally and recoverable from the archived patch, the gates pass, and the starting numbers are recorded.

## Step 1: Requalify against the real local backend (cleanup entry gate)

Reuse `live-journeys.mjs`. Report **fresh pass, fail and skip counts for this commit**. Don't reuse the historical 238/242.

1. **Identify the backend before starting anything:**
   - its git commit, and that it includes `fix/pre-ui2-defects` (tenant-schema reconciliation, null-provider handling, demo SLA thresholds)
   - that the database and tenant are the disposable qualification ones
   - that the schema is ready

   Something listening on port 8080 doesn't prove any of this.
2. Run the frontend with `VITE_UI_VERSION=2` through the existing proxy, on an allowed origin.
3. Sign in through the login form only. Use one session per account per run.
4. Run all journeys in both themes. Persistence checks must reload the page or use a fresh browser session.
5. **Classify every skip:**
   - **Documented limitation (does not block):** an external provider integration that isn't available in this environment.
   - **Pending (blocks the gate for that scenario):** missing test data or accounts, such as AI-BOM declared resources, read-only accounts or entitlement-restricted accounts. Provide the data or accounts through supported ingestion or with approved accounts. Until then, the scenario stays pending and does not count toward the gate.
6. Defects:
   - Fix frontend integration bugs in their own commits, each with a regression test.
   - Keep backend defects in separate changesets.
   - Get approval before changing security-sensitive or tenant-scoping code.

**Exit:** every critical scenario passes on the **candidate commit that results from Step 0 plus any integration fixes**. Record that commit's hash in the ledger. The only exceptions are listed provider limitations. No scenario that needs data or an account is still pending.

## Step 2: Turn the scripts into real gates (can run alongside Step 1)

1. Move `browser-fixtures/` to `prototype-app/frontend/e2e/` with `git mv`.
   - `e2e/` is outside the coverage `include: ['src/**']`.
   - Give it its own ESLint scope.
   - Update `CLAUDE_START_HERE.md`. Leave historical commands in the ledger unchanged.
2. Install exact-pinned dev dependencies `@playwright/test` and `axe-core` with `npm install -D`.
   - Replace the `createRequire(PLAYWRIGHT_DIR)` lookup with `import { chromium } from '@playwright/test'`.
   - Replace `AXE_PATH` with `createRequire(import.meta.url).resolve('axe-core/axe.min.js')`. The scripts are ES modules (`.mjs`), so a bare `require` isn't defined.
   - Keep `CHROMIUM_PATH` as an optional override only.
3. **Add failure handling to every script.** Each fixture journey, `route-sweep.mjs` and `axe-audit.mjs` ends with `process.exitCode = failed.length ? 1 : 0`, the pattern in `findings-journey.mjs`.
   - Route sweep fails on any route error, console error or unexpected request.
   - Add `e2e/axe-compare.mjs`. It compares accessibility violations between a run and the reviewed baseline, keyed by **route + theme + rule + affected element**, not by total counts. It fails on any new violation, and on any serious or critical one that cleanup introduced. Pre-existing violations are listed individually in a baseline file in the repo.
4. **Two-version build and serve** (`e2e/build-artifacts.mjs`):
   - **UI 2:** build with `VITE_UI_VERSION=2 npm run build`, then copy `dist/` to `e2e/.artifacts/ui2`.
   - **UI 1:** build with `VITE_UI_VERSION= npm run build`, explicitly empty so it never inherits `2` from the shell or a `.env` file. Copy `dist/` to `e2e/.artifacts/legacy`.
   - Both builds run the bundle-security check.
   - Each artifact folder is served by its own static server on its own `127.0.0.1` port, serving that copied folder (not the shared `dist/`).
   - After serving, run a **route-aware** `data-ui` check:
     - **UI 2 build:** app and auth routes have `data-ui="2"`. The excluded marketing, blog and demo routes don't have it. This matches the public-route isolation fix.
     - **UI 1 build:** no route has the attribute.
   - `e2e/fixtures.mjs` fails on any unexpected `/api` request.
5. **Deterministic runs:**
   - Use one fixed time for both `page.clock` and the fixture data.
   - Set the locale to `en-US` and the timezone to `UTC`.
   - Disable animations.
   - Don't mask scores, IDs, selected states or controls.
   - **Fonts:** bundle the same font files the app already uses (the families behind `--font-display` and the body font). Don't change any font just to make screenshots stable.
6. **Visual baselines** (`e2e/visual.spec.ts`):
   - Use `toHaveScreenshot({ maxDiffPixelRatio: 0.001 })`.
   - Keep **separate baseline folders for UI 1 and UI 2**.
   - Generate baselines only inside the `mcr.microsoft.com/playwright:v<X.Y.Z>` image, **where X.Y.Z equals the pinned `@playwright/test` version**. A check fails if the two versions don't match.
   - Update baselines only with `npm run e2e:update`, and include inspected before/after evidence.
7. **npm scripts:**
   - `e2e:build`
   - `e2e:journeys`
   - `e2e:sweep`: the route sweep plus axe compare
   - `e2e:visual`
   - `e2e:update`
   - `e2e:affected -- --routes <list>`: runs the chosen routes at 390px and 1280px in both themes and both versions, with screenshots and axe compare
   - `e2e:live`: needs credentials and is never part of default CI
8. **CI** (`.github/workflows/quality.yml`): add a `frontend-e2e` job that runs on Node 20 in the matching Playwright image with 2 workers.
   - **Every PR:** `e2e:journeys` and `e2e:visual` for both versions.
   - **PRs that change CSS or presentation:** also `e2e:affected` for the routes mapped to the changed files. The file-to-route map lives in `e2e/affected-routes.json`, with conservative fallbacks:
     - Changes to `tokens.css`, `primitives.css`, `shell.css`, `legacy-bridge.css`, `styles/index.css` or `base.css` run every family's routes plus the public-route isolation checks.
     - **A presentation file missing from the map runs the full `e2e:sweep`.** It never silently runs zero routes.
     - The selection fails if it resolves to an empty route list.
   - **Nightly or on demand:** the full `e2e:sweep` at 390/768/1280/1440px in both themes.
   - Upload artifacts and keep them for 14 days.
   - Leave the existing jobs unchanged.

   CI runs remotely only once publishing is approved. Until then, run the same commands locally in the same container.

**Exit:** a fresh clone runs `npm ci && npm run e2e:build && npm run e2e:journeys` with no personal paths or credentials, and every script fails with a non-zero exit when it finds a failure.

## Step 3: Remove proven unused code and dependencies (after the Step 1 gate)

1. **Inventory.** List the 33 candidates in the ledger, each labelled remove, retain, or defer with a reason. Check each one across:
   - the entry points
   - re-exports, type imports and dynamic imports
   - assets, routes and CSS imports
2. **Batch A:** remove `vike`, `vike-react` and `@resvg/resvg-js` with `npm uninstall`, with no other upgrades.
3. **Batch B:** remove `src/components/mockData.ts` and the three `src/features/inventory/*Mock.tsx` files.
4. **Batch C:** remove `src/pages/{FixIntelligencePage,FixDetailPage,FixListPage,PatchDashboardPage}.tsx`.
   - Keep the `/fix-intelligence/*` redirect and the `routes.ts` helpers.
   - Make sure a test covers the redirect.
5. **Later batches:** the remaining candidates, removed by dependency closure (a file goes only when everything that uses it is also gone).
   - Remove their CSS and assets only when nothing kept uses them.
   - Keep API methods, auth helpers and compatibility types.
6. After each batch:
   - Run the frontend gate and `e2e:journeys`.
   - Record the coverage numerator and denominator.
   - Report source reductions separately from bundle reductions.

## Step 4: Consolidate foundation styles only (before retirement)

Scope: `src/styles/ui2/{tokens,primitives,shell}.css` and the tab strips.
- Before editing, map which declarations win and how imports are ordered. Check both cold direct links and navigation sequences.
- Merge duplicate UI 2.0 rules where they mean the same thing.
- Move hardcoded colors into tokens without changing what any status or severity color means.
- Turn static inline styles into classes. Leave behaviour-driven positioning and sizing alone.
- Keep the legacy declarations and the `legacy-bridge.css` fallbacks.
- Keep the earlier fixes: full identifiers, public-route isolation, bounded tab underlines, and the contrast tokens from `01353de5`.
- Update `src/styles/ui2/scope.test.ts`: keep the scope checks, and replace rule-count assertions with ownership and route-boundary checks.
- Don't remove a selector just because one coverage run never reached it. Check selected, expanded, failed, disabled, permission-dependent and narrow states.

**Exit:** `e2e:affected` passes (390 and 1280px, both themes, both versions, no new accessibility violations), along with the frontend gate and the affected live journeys.

## Step 5: Retirement qualification and decision

1. Rerun all of `e2e:live` on the cleaned candidate and report fresh counts.
2. Gather evidence for each gate:
   - Authenticated staging, including persistence, failure and retry.
   - Full responsive and keyboard review at the 4 widths plus a real 200% browser zoom.
   - Human visual approval.
   - Accessibility review.
   - Performance and bundle comparison with Step 0.
   - Backend `mvn verify` and `-Ppostgres-it`.
   - CI on this exact commit, once publishing is approved.
   - A rollback rehearsal on current data using the retained release artifact.
3. **Freeze the UI 1 reference.** Build UI 1 from the qualified Step 5 commit and record it in the ledger:
   - the commit hash
   - a sha256 for each file and for the archive
   - its storage location, which must not be temporary or git-ignored

   This one artifact is both the frozen comparison reference and the rollback artifact. The UI 1 visual and axe baselines from this point are kept as historical evidence.
4. Get an **explicit written decision** to end the legacy presentation and rollback by rebuild. This decision **permits the retirement work. It does not approve the resulting artifact.**

## Step 6: Retire the legacy styles one family at a time (after the decision)

0. **Change the version testing at the start of this step.**
   - Stop requiring a new UI 1 build from the changing source. Once a family's legacy rules are gone, that build may legitimately break.
   - The current UI 2 candidate is tested against its own expectations: its visual baselines, journeys, axe baseline and boundary checks.
   - Where a comparison with legacy is needed, serve the **frozen Step 5 UI 1 artifact** after checking its sha256. Don't rebuild it.
   - Remove the UI 1 rebuild from `e2e:build` and CI in the first Step 6 commit.
1. **One slice per family, in this order:**
   1. shared foundations and shell
   2. Findings and AI Findings
   3. CVE
   4. inventory
   5. governance
   6. connectors and remaining screens
   7. public marketing, blog and demo extraction

   **Within each slice:**
   - Copy into the family's `ui2/*.css` file the layout and state declarations it still needs from the legacy sheets.
   - Consolidate duplicates using the Step 4 rules.
   - Run `e2e:affected` (UI 2) and the affected live journeys **with the legacy rules still loaded**.
   - Then remove that family's superseded legacy rules **in the same slice**.
   - Run the checks again.
   - Never delete legacy styles in bulk before every family has passed its own slice.
2. **Public slice:** move the public rules and their tokens into a dedicated sheet without redesigning them. Check the public routes before removing any shared legacy definition.
3. **Final slice, once every family is self-contained:**
   - Create one deterministic app stylesheet entry point.
   - Remove the remaining legacy imports and aliases, then `legacy-bridge.css`.
   - Remove `resolveUiVersion` and `VITE_UI_VERSION` (`uiVersion.ts`, `main.tsx`, `vite-env.d.ts`).
   - Keep the route-aware boundary between the app and the public routes, `data-ui="2"`, and `scoutai-theme`.
   - Replace the version-switch tests with boundary tests covering direct load, link navigation, Back and Forward.
   - Remove the UI 1 baselines from active CI, but keep them in the repo as historical evidence. Add permanent public-route isolation checks.

## Step 7: Archive and document

- Replace `checkpoints/P0-baseline-frontend-src/` with a versioned `.tar.gz`, its checksum and a **per-file manifest of path and sha256**.
- Add `e2e/verify-archive.mjs`. It extracts to a scratch folder and checks every file against the manifest. Note that `verify-baseline.py` checks behaviour baselines and is not an archive check.
- Delete the expanded copy only after `verify-archive.mjs` passes.
- Document which stylesheet owns what, how tokens are used, the e2e commands, and the rollback process (the frozen Step 5 artifact and its checksum).

## Step 8: Final qualification of the branch tip

Step 5 qualified a different candidate. This step qualifies the **current branch tip**, which includes Step 7. Any later commit means rerunning this step.
1. Run the full frontend gate, `e2e:journeys`, `e2e:visual` and the full `e2e:sweep` at all 4 widths and both themes, plus a real 200% zoom.
2. Rerun all of `e2e:live` and report fresh counts. Skips are classified under the Step 1 rules.
3. Staging: authenticated journeys, plus visual and accessibility checks of the retired-presentation build.
4. Human visual approval and keyboard review of the final build.
5. Performance and bundle comparison with Step 0 and Step 5.
6. Backend `mvn verify` and `-Ppostgres-it`. CI on the exact commit, once publishing is approved.
7. A rollback rehearsal using the frozen Step 5 artifact, after checking its sha256.
8. Close ledger items one at a time. Gates without evidence stay open.

**Exit:** every gate has evidence for the exact branch tip. Release still needs its own separate approval.

---

## Verification (every slice)

- `npm run lint && npm run typecheck && npm run test:coverage`
- Run `npm run e2e:build` for both versions through Step 5. From Step 6 on, build UI 2 only, plus the checksum-verified frozen UI 1 artifact wherever a comparison is needed.
- `npm run e2e:journeys && npm run e2e:visual`
- `npm run e2e:affected -- --routes …` for CSS or presentation changes
- `npm run e2e:live` for any family whose backend behaviour the slice touches
- Report the coverage numerator and denominator.
- If a slice changes behaviour unexpectedly, revert only that slice and log the defect separately.

## Critical files

- `prototype-app/frontend/package.json` and `package-lock.json`
- `prototype-app/frontend/vitest.config.ts`, `eslint.config.*`
- `prototype-app/frontend/e2e/*`, moved, plus the new `build-artifacts.mjs`, `axe-compare.mjs`, `visual.spec.ts`, `affected-routes.json` and `verify-archive.mjs`
- `.github/workflows/quality.yml`
- `prototype-app/frontend/src/styles/index.css`, `src/styles/ui2/*.css`, `src/styles/ui2/scope.test.ts`
- `prototype-app/frontend/src/lib/uiVersion.ts`, `src/main.tsx`, `src/vite-env.d.ts`, `src/App.tsx`
- `prototype-app/Working Knowledge/New UI 2.0/CLEANUP_PROGRESS.json` (new), `CLAUDE_START_HERE.md`
