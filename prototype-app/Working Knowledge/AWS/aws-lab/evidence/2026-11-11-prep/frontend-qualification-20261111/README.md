# Frontend candidate qualification repair — November 11, 2026

**Local frontend qualification passed. No new AWS resources, publication, Git commit or push occurred.** This work follows the [integrated lab preparation](../integrated-lab-20261111/README.md) and repairs the frontend blocker identified on application candidate `cd741250faf4a098d1519f073f7e38a0f503016e`. It does not complete Part 1 or qualify live Cognito, S3, RDS or customer workflows. [Verification summary](verification-summary.json)

## Defects and source repair

The [scheduled CI run 42965698489](https://github.com/AxC-SG/SG/actions/runs/42965698489) reported 70 new serious/critical accessibility comparison entries and 22 screenshot failures. Its retained artifact was downloaded to private temporary storage and inspected before editing.

- The public/auth logo link named only “Scoutgrid home,” while its visible text included “– AI Security.” The accessible name now includes that visible wording. Existing public and login tests assert the complete link name.
- The organization-CVE and Intelligence tables rendered impact badges with fixed light-palette colors. Their dark-theme contrast included ratios of 2.25:1 and 2.65:1. They now use the existing family-owned `--cve-impact-*` variables, which resolve through the canonical light/dark tokens.
- Shared investigation badges used fixed blue/green/amber colors. They now use the existing `--dp-accent`, `--dp-success` and `--dp-warning` tokens for text, tint and border. The selected Intelligence scope button uses the existing `--dp-accent-fg` token instead of white on the light purple dark-theme accent.

No authorization, API, tenant routing, data fetching, business state, component library, theme architecture or public/app boundary was changed. The React review confirmed that the repair reuses existing tokens and component behavior. The [narrow source patch](frontend-repair.patch) contains only this repair and its browser checks; it excludes the workspace's extensive unrelated changes.

The source patch was applied to an isolated copy of the previously verified `cd741250faf4` source; all 12 patched source files match the workspace byte for byte. The [frozen overlay](frontend-repair-overlay.tar.gz) contains those 12 files and the 22 reviewed PNGs, with SHA-256 `2edc14d5998e578a9e1c5802d1e7a52b944bed3f1f522d847e49b52880a33ec3`. Its [manifest](frontend-repair-overlay-manifest.json) records every member hash. Apply only to a reviewed isolated candidate copy; this does not stage or commit the dirty workspace.

## Browser timing defects

The initial local run captured one Findings loading frame and reported three Operations Pipeline orphans whose entire content was `Loading page...`. It also read several journey states before their async transition completed. The original evidence remains in `/private/tmp/scoutgrid-browser-qualification-20261111/`.

`waitForPageReady` in `e2e/browser.mjs` now requires a visible main landmark and no visible leading “Loading…” state. Visual capture, route inspection and axe auditing call it after navigation. This addresses lazy route/query mounting after network idle; screenshot tolerance remains unchanged. The [browser probe](readiness-probe.json) verified that the helper waits for delayed content, ignores hidden loading copy and rejects a page that remains visibly loading. [Reproduction script](readiness-probe.mjs)

The inventory journey waits for the expected `/exposure` redirect before asserting denial of unentitled AI inventory. The connector journey waits for the expected initial setup and GHSA failure status. Its Copilot Studio locator now selects the exact “Configured organizations” heading rather than ambiguously matching both the heading and “Loading configured organizations…”. The original assertions and strict API fixtures remain in force; no failure was added to a known-failure baseline.

## Reviewed screenshot refresh

All 22 historical screenshot failures reproduced byte for byte against the actual images from the CI artifact. Source history and existing interaction tests explain the differences:

| Cases | Count | Existing source represented by the refreshed baseline |
| --- | ---: | --- |
| `/demo`, `/demo/blog`, `/demo/request`, `/login`, `/setup`; dark/light, 1280/390px | 20 | November public-site redesign, current BrandMark and visible AI Security tagline, navigation disclosure menus, blog content/layout, legal/footer text and shared auth header. The public redesign is recorded in [038e1ea7](https://github.com/AxC-SG/SG/commit/038e1ea7f9f75121a70fd30881b0ede3fa56f731), with Company/contact/blog updates in [0c7136c1](https://github.com/AxC-SG/SG/commit/0c7136c1921c96ac3667a6a52329bd5cbfae9830). |
| `/vuln-repo`; dark/light, 1280px | 2 | Existing BrandMark and Needs Attention caption/subscore wording. Dashboard tests already verify the distinct drill-down targets. The dashboard source last changed in [7b94a22a](https://github.com/AxC-SG/SG/commit/7b94a22a4a1165f016727b005f1f7225be226716). |

Only these 22 PNG baselines were replaced with their reviewed, pinned-image actual captures. **150 other UI 2 baselines stayed byte-identical.** The Findings loading-frame capture was excluded. Legacy screenshots, the accessibility baseline and the journey baseline were untouched. No screenshot masking or tolerance increase was introduced; `maxDiffPixelRatio` remains `0.001`.

The [snapshot manifest](snapshot-manifest.json) records before/after hashes and the retained images. [Comparison sheets](visual-review/) and representative full-size CI pairs were inspected. This is Codex's automated visual/source-history review, not an invented new human design approval. The source repair makes no new layout or shared-pattern departure.

## Verification

The isolated test copy matches all 752 included workspace frontend files byte for byte. Its [source manifest](frontend-source-manifest.json) hashes the entire included frontend tree; `.env*` values are excluded. The manifest identity is a content hash, not a Git commit. [Changed-source manifest and React review](source-repair-manifest.json)

Used Linux/amd64 and the same pinned Playwright browser/system-font image as CI:

`mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27`

The image provides Node 24.20.0 and the lockfile installs Playwright 1.63.0/axe-core 4.14.0. Dependencies were installed with `npm ci` in the isolated copy. Local host Node 26 and macOS node_modules were not used for these gates.

| Check | Result | Evidence |
| --- | --- | --- |
| Lint | 0 errors; the two existing warnings remain | [Final lint](lint-final.log) |
| TypeScript, production-bundle guard, build | Passed | [Build log](quality-build.log) |
| Build presentation boundary | 15 direct routes and 20 public/link/history checks passed | [Build log](quality-build.log) |
| Unit/coverage | 113 files, 1,159 tests passed; configured floors retained | [Coverage run](coverage.log), [coverage summary](coverage-summary.json) |
| Coverage values | Lines 60.44%, statements 57.82%, functions 49.96%, branches 49.88% | [Summary](coverage-summary.json) |
| Browser runner contracts | 5/5 passed | [Runner checks](runner-checks.log) |
| Readiness probe | Three positive/negative conditions passed | [Probe](readiness-probe.json) |
| Visual comparisons, updates disabled | **172/172 passed** | [Final comparison](visual-final.log) |
| Functional journeys | **823/823 latest assertions passed**, zero known/new failures | Findings 67, CVE 94, governance 168 and experience 264 passed in [initial suite](journeys.log). Inventory 108 passed in [targeted recheck](journeys-recheck.log); connector 122 passed in the [final connector recheck](connect-final.log). The three initial async-state failures and intermediate ambiguous locator error are preserved. |
| Route matrix, 390/768/1280/1440px, both themes | **780/780 page checks passed**, including 172 navigation checks; zero orphan, overflow, page/console/request or boundary/landmark violations | [Summary](route-summary.json), [dark](route-dark-final.log), [light](route-light-final.log), [full route records](routes/) |
| Full axe audit/comparison, same width/theme matrix | **0 new regressions**; all 70 original new entries absent | [Summary](accessibility-summary.json), [audit output](accessibility-after.json), [comparison log](axe-final.log). No partial-width substitution. |

The final route and accessibility components run concurrently through [this scratch orchestrator](run-verification-part.mjs), serving the same immutable fixture build and invoking the original repository scripts. The two affected functional journeys were rechecked through [this scratch orchestrator](rerun-journeys.mjs). Neither script is part of the application or replaces a gate's assertions.

The full audit contains 379 remaining known per-element comparison entries across 242 violation rows, against 2,345 baseline entries. Passing means no new regression against that unchanged baseline, not zero accessibility defects. The comparison reports 1,966 resolved baseline entries. All eight theme/width combinations were audited.

## Release boundary and next step

These are local results for an uncommitted source repair. The four successful main-push workflows and scanned backend archive recorded under `cd741250faf4` remain historical evidence for that exact source; they do not transfer to this changed frontend or test harness.

Next, isolate and review this narrow patch and its 22 baselines on a new candidate commit. Run Quality, Trivy, Semgrep and Performance Governance on that exact candidate, capture the new retained image/archive manifest and paired frontend configuration/hash, and obtain independent candidate approval. Preserve the existing unrelated work. Keep `github_publisher = null`; no unrestricted GitHub OIDC publication is enabled.

The confirmed lab domains and two operator emails remain in the integrated preparation record. Live certificate/DNS access, runtime/enrollment secret references, complete scoped operator policies, reviewed run budget/cleanup authorization, actual image publication/digest, bootstrap and AWS workflow qualification are still required. Production capacity/recovery, cutover and stabilization remain open under the [master plan](../../../../AWS_MASTER_MIGRATION_PLAN.md).
