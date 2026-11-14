# CI simplification and speed plan

Agreed November 14, 2026, after two independent reviews of the full pipeline and of the `backend-postgres` job. Nothing here is implemented yet. Every phase changes `.github/workflows/`, the live ruleset or repository settings, which are on the never-touch list, so each PR needs explicit owner approval.

## Status

| Item | State |
|---|---|
| Secret scanning and push protection | Enabled November 14 |
| CodeQL default setup (4 languages) | Re-enabled November 14; confirm fresh PR and `main` analyses |
| Live ruleset requires `AWS backend candidate` | Applied November 14 |
| PR A: Phase 1 repository files | Open |
| PR B: Phase 2 | In progress |
| PR E: Phase 6.1–6.2 | [#83](https://github.com/AxC-SG/SG/pull/83), measuring |
| PRs C, D, F | Waiting on A, B and E |

## Where we are

| | Today | Target |
|---|---|---|
| Check rows on a PR (PR #82) | 22 | about 11 |
| Required status checks | 5, plus a CodeQL rule that has no analyses behind it | 1 (`Quality gate`) plus a working CodeQL rule |
| Backend PR wait | 24–30 min (`backend-postgres`; the next-longest job is 8m17s) | about 9–13 min |
| Docs-only or frontend-only PR | Full suite runs | Only the relevant jobs |

Run-time numbers come from runs 43577894006 and 43556944542. Fork and template numbers are modelled, not measured.

## Decisions

| # | Decision | Choice |
|---|---|---|
| D1 | Static analysis (SAST) | Re-enable CodeQL **default setup** for Actions, Java/Kotlin, JavaScript/TypeScript and Python, the state verified on October 28 (see [CI security](ci-security.md)). It went empty after the move from `AxG-SG` to `AxC-SG`. Keep Semgrep until CodeQL has passed on two PRs and on `main`, then decide whether to retire it. Default setup ignores `.github/codeql/codeql-config.yml`. This is a personal-account repo with no custom properties, so delete that file unless we switch to a CodeQL workflow. |
| D2 | Up-to-date branches before merge | **Keep.** This was a deliberate choice ([reliability plan](ci-reliability-plan.md)). Phases 2 and 6 make each re-run cheap. |
| D3 | Full performance certification | Move off PRs: run on `main`, nightly and on demand. A regression is caught after merge, and publishing stays blocked until it's fixed. |
| D4 | End-state merge gate | One required `Quality gate`, plus the native CodeQL code-scanning rule. |

## Phase 1: fix controls that aren't working (PR A plus settings)

- [ ] **1.1** Turn on repository secret scanning and push protection. This is a repository setting for the owner. Keep gitleaks.
- [ ] **1.2** Re-enable CodeQL default setup with the four languages (D1). Confirm new analyses appear on a PR and on `main`. Delete the unused `codeql-config.yml`.
- [ ] **1.3** Make `AWS backend candidate` (the image that actually runs on ECS) a required check. Update `required-main-ruleset.json`, the expected set in `test-ci-contracts.py` and the live ruleset together, so `ci-contracts` doesn't fail.
- [ ] **1.4** Add Maven (`/prototype-app/backend`) and Terraform (`/prototype-app/infrastructure/terraform/standard` and `modules/standard-network`) to Dependabot, grouping minor and patch updates.

**Done when:** CodeQL analyses dated after this change appear on a PR and on `main`; push protection shows enabled; the ruleset lists the ECS check; Dependabot opens a grouped Maven PR.

## Phase 2: run each job only when its files change (PR B)

- [ ] **2.1** Extend `classify-changes.py` to output separate flags: `frontend`, `backend`, `infrastructure`, `policy` and `security`.
  - `.github/**`, unknown paths or an empty file list → everything runs.
  - `prototype-app/backend/**`, `scripts/**`, `policy-packages/**`, `test-fixtures/**` and `sample-data/**` → backend and `backend-postgres`.
  - `prototype-app/frontend/**` and `.nvmrc` → frontend and `frontend-e2e`.
  - `prototype-app/infrastructure/**` → Terraform and lab-script tests.
  - Markdown in `docs/`, `Working Knowledge/` and `README.md` → static checks and secrets only.
- [ ] **2.2** Update `check-quality-gate.py` so a job may skip only when its own flag says it isn't needed. Missing, cancelled or failed results still fail the gate.
- [ ] **2.3** Replace the classifier and gate tests with a path-to-flags table and tests for failure, cancellation, a missing result and a skip that wasn't allowed.

**Done when:** a docs-only PR runs only static and secret checks; a frontend-only PR skips both backend jobs; a `.github` change runs everything; an unknown path runs everything. Of the last 25 merged PRs, about 1 in 4 would have skipped `backend-postgres`.

## Phase 3: remove duplicate work and merge small jobs (PR C, after Phase 1 is live)

- [ ] **3.1** Make each Trivy scan run once: `exit-code: 1`, SARIF written in the same run, and the upload in an `always()` step. Run the Spring advisory check once. The ECS candidate scan already runs once.
- [ ] **3.2** Retire `Trivy images gate`. It scans the backend `default-runtime` target, which nothing deploys since Render was retired, and `frontend/Dockerfile.ci`, which Vercel doesn't use. Keep the `default-runtime` target for local `docker build`. Reuse the ECS image build.
- [ ] **3.3** Upload Trivy SARIF to the code-scanning tab, granting `security-events: write` only to that job.
- [ ] **3.4** Merge `ci-contracts`, `terraform`, `migration-validation`, `migration-boundaries` and `policy-packages` into one `static` job. Keep each as its own named step, and run the Terraform steps only for infrastructure changes.
- [ ] **3.5** Merge `validate-migrations.py` and `check-migration-integrity.py` into one checker. It must keep the union of their rules: filenames, substantive SQL, version collisions with the base branch, and no edits, deletes or renames of applied migrations. Write comparison tests first. Drop the reset branch that points at the archived `development-v1-baseline-reset.md`. Keep `check-tenant-ddl.py` and the migrator environment tests separate.
- [ ] **3.6** In `test-ci-contracts.py`, replace checks of exact YAML text and command counts with checks of structure. Keep the behaviour tests: gate, selection, Maven reports, AWS archive and certification scripts.
- [ ] **3.7** Remove the `docs-check` job, which only warns, and the sentence in the PR template that refers to it.

**Done when:** every rule above still has a test that fails when the rule is broken, and PR #82's 22 rows have dropped by about 8.

## Phase 4: one workflow and one gate (PR D, coordinated)

- [ ] **4.1** Make `quality.yml` the single workflow for PRs and `main`. Keeping that filename limits changes to the publisher. Jobs: `changes`, `static`, `frontend`, `frontend-e2e`, `backend`, `backend-postgres`, `security` (gitleaks, Trivy filesystem, ECS image build, inspection, scan, and the archive on `main`), `semgrep` until D1 is settled, and `Quality gate`.
- [ ] **4.2** Update `aws-publish-candidate.yml`, which has the `trivy.yml` and `semgrep.yml` workflow names hard-coded. Check `quality.yml` and `performance-governance.yml` for the source SHA, and take the image archive from the `quality.yml` run. Keep the archive and manifest checks and the scoped publishing role.
- [ ] **4.3** Change the live ruleset in two steps so nothing goes unenforced: make `Quality gate` cover the security jobs and merge; then remove `Trivy filesystem gate`, `Semgrep SAST gate`, `AWS backend candidate` and `Performance gate` from the required list.
- [ ] **4.4** Delete `trivy.yml`. Move its weekly schedule to a scheduled run of the security job against `main`. Delete `semgrep.yml` only if D1 retires Semgrep.

**Done when:** a temporary PR with a deliberately failing job is blocked; a PR where a job is correctly skipped can merge; a lab publish from a `main` run passes the publisher's qualification.

## Phase 5: performance cadence (part of PR D)

- [ ] **5.1** Remove the `pull_request` trigger from `performance-governance.yml`. Keep `main`, nightly and on-demand runs. The publisher still requires it for the exact SHA.
- [ ] **5.2** Keep the million-component Postgres test and the SIGTERM tests in the suite for now. Phase 6 may move them to their own parallel job.

## Phase 6: make `backend-postgres` faster (PRs E and F; independent of Phases 1–5)

These change `pom.xml` and test support code, not workflows, so they can start straight away.

- [ ] **6.1** Lower the Spring context cache from 12 to 3. Each class gets its own database, so contexts are almost never reused.
- [ ] **6.2** Trial `forkCount` of 2 and 3 in one PR and measure both.
  - Run the 3 classes that create PostgreSQL roles serially, or give their roles unique names.
  - Check Postgres connections: forks × cache size × 5 must stay under `max_connections`.
  - Confirm `verify-maven-reports.py` still accounts for every class.
- [ ] **6.3** Build a migrated template database once per run in `LocalPostgresTestDatabase` and create each class's database from it (`CREATE DATABASE … TEMPLATE`). Migration, upgrade and bootstrap tests keep using an empty database. This saves about 4–5 min of test time.
- [ ] **6.4** Lower the job timeout from 35 min to about 20 once five runs in a row finish under 15 min.
- [ ] **6.5** Only if the job still exceeds about 12 min: move the performance and lifecycle tests into a parallel job, then consider shards with a check that every class ran exactly once.

**Done when:** median `backend-postgres` time over five runs is under 15 min with 145 classes and 669 tests, no failures and no skips.

## PR order

| PR | Phases | Depends on |
|---|---|---|
| A | 1 | — |
| B | 2 | — |
| C | 3 | A merged and live ruleset updated |
| D | 4, 5 | A, B, C |
| E | 6.1–6.2 | — (can go first) |
| F | 6.3–6.5 | E measured |

## Not doing

- Parallel test methods (tests change JVM-wide state and cluster-wide roles)
- A bigger context cache, or a bigger timeout presented as a speed fix
- Skipping or weakening tests
- Bigger runners before measuring CPU and I/O
- Merge queue (needs an organisation-owned repo)
- A single serial job in place of parallel jobs
