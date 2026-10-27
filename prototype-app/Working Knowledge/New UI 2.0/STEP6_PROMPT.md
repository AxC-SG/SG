# Prompt to start Step 6 in a fresh session

Paste everything below the line into a new Claude Code session opened in `~/Desktop/AI Projects/SG`.

---

Read the plan at `prototype-app/Working Knowledge/New UI 2.0/CLEANUP_PLAN.md` (the approved UI 2.0 qualification and cleanup plan, Steps 0–8; a copy of `~/.claude/plans/recursive-coalescing-lighthouse.md`). Then read the ledger at `prototype-app/Working Knowledge/New UI 2.0/CLEANUP_PROGRESS.json` (units S0–S5), `STEP5_DECISION.md`, and `tools/README.md`. Follow the plan step by step and stop at every gate.

Repo: `~/Desktop/AI Projects/SG`. GitHub: AxG-SG/SG is the only repo (AxonCyber-SG/SG is retired, and local `origin` may still point there). Push only by URL to `https://github.com/AxG-SG/SG.git`, and don't change remotes without asking.

**Rules (unchanged):**
- No push, merge or deploy without my explicit approval each time.
- No changes to APIs, auth, tenant scoping, or the database schema and migrations. Writes of disposable test data to the qualification tenant are allowed.
- No customer data, no database resets, no external delivery except to approved test endpoints.
- Never lower coverage floors or remove assertions. Each slice is a separate local commit.
- Report fresh pass, fail and skip counts. Never present skips as passes.
- If a check fails intermittently, diagnose it (find the exact lines or test); don't rerun until it passes.
- Only one session may work in this checkout at a time.
- No risky shortcuts.
- Use simple language with me.

**DONE:**
- Steps 0–3: merged to main (PR #22, PR #23 = merge commit `ce85819a`).
- Step 4: merged to main in PR #24 (merge commit `47ab4728`, parents `ce85819a` and `a3f1d1db`). Gate on `6cba0983`, recorded in S4.
- Step 5: branch `feat/ui2-step5-qualification`, draft PR #25 into main. It holds the Step 5 records, the frozen UI 1 build, the keyboard focus fix `3f3faa89` and the Invite-focus fix `c29515d8`, which are the only app changes; checkpoint A passed on `c29515d8`. Merge #25 with a merge commit, only with my approval. Evidence is in S5. Frozen UI 1 build: `checkpoints/UI1-frozen-a3f1d1db.tar.gz`, sha256 `f040137d4956b5bcc68133b89b2eb1f28136a456561a76f7236200352c81a707`.

**CHECK FIRST, and stop if any is missing:**
1. The Step 5 decision. It's recorded in S5 `decision` and `userDecisions`: proceed to retirement; staging and human review are waived. Report it back to me in one line. Don't ask again.
2. Checkpoint A: the full gate passed on `c29515d8` (the focus fix `3f3faa89` plus the Invite-focus fix `c29515d8`, the Step 5 tip). It's recorded in S5 `focusFixGate`. Confirm the Step 5 branch tip still has the same `frontend/` tree as `c29515d8`; if it doesn't, report and stop.
3. PR #25 (Step 5) state and CI on AxG-SG/SG (report each job).
   - If #25 is merged: fetch AxG-SG main, confirm it contains the Step 5 tip, and create `feat/ui2-step6-retire-legacy` from main.
   - If #25 is not merged: create `feat/ui2-step6-retire-legacy` from the `feat/ui2-step5-qualification` tip, and say so. Ask me before merging #25.
4. The open and waived gates in S5 (staging waived, human reviews waived, accessibility review open). Report them as they are. Don't mark them done.

**NEXT: STEP 6 (retire the legacy styles one family at a time), per the plan:**
- **Step 6.0, the first commit:**
  - Stop requiring a new UI 1 build. Remove the UI 1 rebuild from `e2e:build` and from CI (`.github/workflows/` is on the never-touch list, so show me the exact diff and get approval first).
  - The UI 2 candidate is tested against its own baselines, journeys, axe baseline and boundary checks.
  - Where a legacy comparison is needed, serve the frozen Step 5 artifact after checking its sha256 (`tools/rollback-rehearsal.mjs` shows how). Never rebuild it.
- **For each family** (findings, cve, inventory, governance, connect, experience; then the public slice; then the final slice):
  1. Before editing, map the family's legacy rules and what supersedes them (`tools/cascade-map.mjs` is the Step 4 version; update its `main`/`lazy`/`foundation` lists).
  2. Consolidate duplicates using the Step 4 rules.
  3. Remove that family's superseded legacy rules in the **same slice**.
  4. Run the fast checks (below) and commit. Never delete legacy styles in bulk across families in one commit.
- **Public slice:** move the public rules and their tokens into a dedicated sheet without redesigning them. Check the public routes before removing any shared legacy definition.
- **Final slice:** one deterministic app stylesheet entry point. Remove the remaining legacy imports and aliases, then `legacy-bridge.css`, then `resolveUiVersion` and `VITE_UI_VERSION` (`uiVersion.ts`, `main.tsx`, `vite-env.d.ts`). Keep the route-aware app/public boundary, `data-ui="2"` and `scoutai-theme`. Replace the version-switch tests with boundary tests (direct load, link navigation, Back, Forward). Remove the UI 1 baselines from active CI but keep them in the repo. Add permanent public-route isolation checks.
- **Checks (my decision 2026-10-27, `checkDeferral` in the ledger):**
  - **Per slice:** one local commit, then the fast checks only: lint, typecheck, and vitest including `scope.test.ts` (about 2 minutes). Report the counts. Pushing a branch with a PR runs CI.
  - **Checkpoint B, right before the final slice** (the one that removes the version switch and `legacy-bridge.css`): the full gate.
    - `tools/host-gate.sh` with the checkpoint A baseline
    - `tools/ctr-gate.sh` (e2e:visual, plus e2e:affected for all routes changed since the Step 6 start, at 390 and 1280px, both themes)
    - the live journeys
    - CSS bundle sizes against Step 0 and Step 5

    Then stop for me.
  - **Step 8:** the full final qualification, as the plan says.
- Checkpoint A's probe outputs are in this Mac's old session scratch folder, which a fresh session can't use. Before the first slice, run `tools/host-gate.sh` once on the Step 6 starting commit with no baseline, and keep its `probe-*.json` and `state-new.json` (as `state.json`) in your scratch folder as the `GATE_BASELINE` for checkpoint B. The probe files are about 23 MB each; never commit them.

**Environment notes:**
- **Container-only checks:** `e2e:visual`, `e2e:update` and `e2e:affected` run only inside `mcr.microsoft.com/playwright:v1.63.0-noble` (native arm64) under Podman. `check-playwright-image.mjs` stops them on the host by design. Use `tools/ctr-gate.sh` (`GATE_WORK`, `AFFECTED_BASE`); it works on a `git archive` copy with its own node_modules volume `sg-ui2-node-modules`.
  - Podman's network is slow: fill `$GATE_WORK/npmcache` on the host first (see the script header).
  - x86 emulation crashes Chromium.
- **vitest and Podman:** never run vitest while the Podman VM is up (`podman machine stop` first).
- **Visual baselines:** update them only with `npm run e2e:update`, and inspect the before/after diffs. Never loosen tolerances.
- **Known visual flake:** the UI 1 `/platform/tenants` screenshot can fail "two consecutive stable screenshots" under two workers. The full-page capture re-runs table layout (S4 `findingsForLaterSteps`). A fix in the harness, a warm-up screenshot, needs my approval.
- **Coverage timing variation:** 300ms search-debounce timers in `CampaignsPage.tsx` (217, 237) and `CampaignDetailPage.tsx` (270, 340). `host-gate.sh` saves `coverage-summary.json` per run, so you can find what moved.
- **caffeinate:** always wrap long runs in `caffeinate -ims`.
- **Backend tests:** run `mvn -Ppostgres-it verify` **from a git archive copy that includes `prototype-app/backend` and `.github`**, not from the checkout. `application.yml` imports `backend/.env.local`, which breaks `OsvIntegrationE2ETest` locally (S5 `findingsForLaterSteps`). The ITs create their own `vulnwatch_it_*` databases.
- **Backend for live runs:** `cd prototype-app/backend && mvn -DskipTests spring-boot:run -Dspring-boot.run.profiles=local,postgres`. `.env.local` points at the disposable DB `scout_ui2_qual` on Postgres 16, port 5432; psql is at `/opt/homebrew/opt/postgresql@16/bin/psql`. Verify the backend identity yourself before any live run:
  - the git commit, and no backend changes
  - the process path
  - the `pg_stat_activity` database
  - platform Flyway V8, and `tenant_ui2_qual_2.tenant_schema_history` V6 with `ui2-qual-2` ACTIVE
- **Frontend for live runs:** `VITE_UI_VERSION=2 npx vite --port 5180 --strictPort --host 127.0.0.1`. After the final Step 6 slice the switch is gone, so drop the variable.
- **Live run:** `LIVE_CREDENTIALS=~/.config/scoutgrid-qual/qual-tenant-owner2.json LIVE_PLATFORM_CREDENTIALS=~/.config/scoutgrid-qual/qual-platform-owner.json caffeinate -ims node e2e/live-journeys.mjs --base http://127.0.0.1:5180 --out <scratch> --label live --themes dark,light`.
  - Never print credential values.
  - The expected result is 250/250 with 2 skips (outbound ServiceNow).
  - Tenant `ui2-qual-2` uses AUTO finding generation, so the CVE journey normally takes the duplicate branch. `--cve <id>` targets a CVE with unfound components.

**Logged for later, don't fix unless I approve:**
- UI 2 overflow at 768px on `/configurations/sla` and `/configurations/suppress`.
- UI 2's extra serious axe violations (80 color-contrast, 12 scrollable-region-focusable).
- Keyboard focus on the public `/demo` pages (`a.nav-link-cta`, `a.btn.btn-primary`): legacy, never UI 2-styled. Handle it in the public slice if I approve.
- Declared-resource and setup-action rows on `/inventory/ai/declared-resources` open only by mouse.
- `useAdvisoryEquivalencesQuery` has no caller (kept as data-access code).
- `findings-list.css` is lazily loaded but its `.fpl-*` rules are used on other pages: the cold link vs navigation difference on `/vuln-repo/vulnerabilities` and UI 1 inventory widgets. Fix it in the family slices or the final entry point.
- `ui2/inventory.css:98` overrides the primitives focus/disabled styles on Inventory pages by source order.
- `/platform/operations` returns 403 for quality/summary and 400 for performance-scorecard for a platform owner.

Leave my untracked `UI2-Final-Implementation-Plan.md` and `Scout_Normalisation_and_Correlation.pdf` alone.
