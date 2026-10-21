# Application prerequisite review handoff

Prepared October 21, 2026 on `codex/application-prerequisite-fixes`, HEAD `3541bb0f574c66ea0860fe60a112e5a7160f02cd`. The implementation and review-preparation changes are **uncommitted**. No files have been staged, no PR created and no deployment performed. This document describes a candidate for review, not a release approval.

The [P01–P36 closure audit](AWS_APPLICATION_PREREQUISITES_IMPLEMENTATION_CLOSURE.md) records requirement-level source, tests and containment. The [release qualification checklist](PHASE_3_RELEASE_QUALIFICATION.md) records environment work. The formal register stays Open/Pending until its required revision, environment, result, date and reviewer evidence exists.

## Reconciliation and P30 repair outcome

**P30 repair — October 21, 2026:** [Reconciliation and repair evidence](DOCUMENTATION_RECONCILIATION.md#p30-frontend-repair) records removal of the Patch Management cards, connector IDs, mounting branches and four unsupported mock modules, including their credential/input logging handlers. Query bookmarks and direct paths cannot mount these forms. New catalog/navigation regressions and refreshed frontend gates pass on the changed bytes. Fix Intelligence API/routes, tenant OSV and runtime containment remain intact. Independent review, exact committed CI and environment qualification remain pending.

The earlier guidance-only reconciliation completed with: 16 touched guidance/evidence files, final 73-file dirty review inventory, 2,181-file candidate secret scan with zero findings, passing local links/diff checks, and unchanged verified application bytes. The nine core guides plus backend `.env.example` now describe source-backed current contracts. LocalStorage/raw-token query keys remain documented because they remain in source; static tokens do not override stored tokens. Explicit runtime intent, deployed migration separation, ENFORCE/cohort semantics and the reset-history limitation are preserved. [Reconciliation evidence](DOCUMENTATION_RECONCILIATION.md) maps claims to source and records final checks.

## Earlier review preparation results

- Reviewed the combined production diff and regression coverage for queue ownership, transaction/tenant boundaries, invitation publication, recurring-work serialization, shutdown, rollout recovery and startup dependencies. No additional runtime repair was identified in this preparation pass. All existing Phase 3 changes remain present.
- Resolved ten archived curl-header detections and one architecture-review prose false positive. Local API-key examples now reference an explicitly configured environment variable; the intentionally invalid-key example also uses a variable reference. Added archive notices so obsolete endpoint/role/migration instructions are not mistaken for the current contract. No scanner configuration, ignores or coverage floors changed.
- Gitleaks 8.30.1 reports zero findings in the repository-relative tracked/untracked candidate snapshot (2,179 files before this handoff was added) and in the existing `origin/main..HEAD` commit range (five scanned commits). These earlier snapshot counts precede final reconciliation; current inventory and scan results are in the reconciliation record. These are separate checks: existing history does not contain the dirty candidate. The temporary `.mcp.json` scan copy was removed after scanning; the original was not modified or printed.
- Backend source/resources/tests/POM/scripts still match all 1,495 files in the completed full/default verification snapshots: SHA-256 `a20779e43193240986be02757605546874fd9f4901bc009e7756136af60a142d`. The frontend manifest differs only in `CLAUDE.md`; application/build/test files match. No application code was changed during this preparation pass, so the passing full suites were not rerun for documentation edits.
- Migration validation/integrity, tenant DDL boundaries, migration environment/URL tests, ShellCheck, and Spring advisory applicability checks pass again. Existing migration files are unchanged; new platform V6 is additive, tenant head/floor remains V5. The Git-based integrity command checks committed history; the candidate catalog and unchanged previous migration bytes were checked separately.
- Workflow, container build inputs and new test portability were inspected. No task-local filesystem paths or database ports are embedded in new tests. The SIGTERM test uses a child JVM and the provisioned test database. Docker, CodeQL and Trivy executables are unavailable locally; their hosted jobs remain pending. The performance certification workflow also remains pending for the exact committed candidate.

The local remote-tracking refs were used without a network refresh. `origin/main` is `71b55d4740d42c69cdb45be620f5bf5463a47a1a` and is an ancestor of HEAD. Recheck the actual remote base before merge; this is not a claim that the current remote has no newer commits.

Evidence is under `/private/tmp/sg-ci-preparation/`: candidate manifests, tracked/untracked review inventory, complete review patch, redacted repository/history scan reports, and verification results. Full-suite evidence remains under `/private/tmp/sg-implementation-closure/`. Temporary local evidence must be preserved in the eventual review record if needed; these paths are not durable CI artifacts.

## Draft pull request description

Suggested title: **Repair prerequisite recovery and reconcile operational guidance**

### Scope

Repair retained prerequisite workflows and add Phase 3 recovery regressions; reconcile operational guidance with current source. Retire unsupported patch cards/forms and credential/input logging; query/direct navigation cannot mount them, while supported connectors and contained status pages remain available. Accepted work retains ownership through retries and shutdown; recurring operations serialize their effects; expired or superseded invitations retain uncertain provider outcomes for reconciliation. Rollouts preserve the exact accepted assessment request, bound failed retries and cancel revoked work. Startup/readiness reject missing shared work structures, and bootstrap JDBC timeouts remain bounded while retaining TLS options.

### Why

Linked bug/design record: [application prerequisite register](AWS_APPLICATION_PREREQUISITES.md), with concrete defects, containment and source/test evidence in the [closure audit](AWS_APPLICATION_PREREQUISITES_IMPLEMENTATION_CLOSURE.md). The rollout waiting state was rejected by the prior constraint, revocation missed waiting/claimed tasks, failed exact requests could retry indefinitely, and explicit zero/ambiguous JDBC timeouts bypassed bounds. Phase 3 regressions also exposed stale-owner publication, duplicate recurring effects, shutdown loss and expired invitation publication.

### Repro / Manual Test

1. In a disposable PostgreSQL fixture, apply reset-history platform V5 and run `AiGridPolicyRolloutRecoveryPostgresIntegrationTest`: the original schema produces four assertion failures. V6 with original services still fails revocation and retry-budget assertions. The candidate passes all six cases.
2. Run `ProductionBootstrapTransportTest` against the original timeout method: eight assertion failures across nine cases; the candidate passes. Shell URL capture checks explicit TLS-option preservation.
3. Run `mvn -Ppostgres-it verify` with a disposable PostgreSQL 16 test service and the standard frontend gates. Never bootstrap or reset a shared/deployed database as a reproduction.

### Test added or changed

- [x] Frontend: 17 catalog/query/direct-route/in-page-navigation regressions; all 671 tests pass.
- [x] Regression tests added/changed: rollout upgrade/recovery, JDBC transport, admission contention, restricted runtime journeys, parser limits, generative containment and measured telemetry; prior Phase 3 tests cover recurring transactions, queue recovery, feed replay, bootstrap failure, invitation/campaign delivery and real child-JVM SIGTERM.
- Not adding a test: archive/prose scanner cleanup changes no application behavior; the unchanged scanner is its verification.

Local results on the matching source snapshot: default backend 1,309 reported / 1,304 executed tests with five existing OSV skips; full PostgreSQL 1,309 Surefire plus 491 Failsafe cases across 106 integration classes, zero failures/errors/skips. Default line coverage 31.89% against the unchanged 25% floor; zero SpotBugs findings. The subsequent frontend lint/typecheck/build/bundle guard/coverage pass on a new manifest: 74 files / 671 tests, 43.08% lines / 32.72% branches, three existing warnings in untouched components; all four coverage floors raised. Production static-key/JWT sentinel builds reject the inputs without echoing values.

### Risk and Rollback

- Blast radius: retained backend workers, shared work coordination/readiness, tenant recurring workflows and invitation delivery; additive platform V6. Runtime evidence, generic Azure, SCCM JDBC, local archives, Fix Intelligence/tenant OSV, pilot generative assistance and destructive tenant purge stay contained; unsupported patch catalog/forms and their logging are retired, covered by new catalog/query/app-route/navigation regressions.
- Rollback plan: capture candidate and fallback artifact digests and inspect actual platform/tenant histories first. The last observed deployed binary predates the reset baselines; fresh local V5→V6 tests do not establish deployed upgrade or rollback compatibility. Use an authorized representative clone to qualify a data-preserving forward transition and supported rollback or roll-forward, retaining outboxes, leases, keys and schedule/retention progress. Do not remove V6, edit applied history, reset a shared database or use `flyway:repair` to hide mismatches. Production transition remains blocked on that qualification.

### Documentation

- [x] `docs/backend.md` — shared dependency startup/readiness contract.
- [x] `docs/database.md` — additive platform V6, tenant V5 and migration boundary.
- [x] Prerequisite closure, Phase 3 status/schedule/cleanup/qualification documents and applicable `CLAUDE.md` guidance.
- [x] Architecture/frontend/business guide, README and backend configuration-example reconciliation; source map and subsequent P30 repair in [documentation reconciliation](DOCUMENTATION_RECONCILIATION.md). The P30 follow-up changes frontend bytes and has a new verification manifest.

### Pre-merge checklist

- [x] Backend default and full PostgreSQL verification pass on matching source snapshots.
- [x] Frontend build and full coverage suite pass on matching application sources.
- [x] Previously applied migrations remain unchanged.
- [x] Local repository candidate and existing branch-history secret checks pass with unchanged rules.
- [x] Applicable `CLAUDE.md` watermarks/scope guidance updated.
- [x] Repair local P30 mock-form containment; add 17 regressions, rerun frontend gates and fixture-browser checks, and refresh frontend/candidate manifests. Independent review remains pending.
- [ ] Independent review and authorized selective staging/commit; include all new regression classes, the startup validator, V6 and closure/qualification documents. Review the inventory; do not blindly stage the whole workspace.
- [ ] Refresh/check the remote base and run hosted Quality, CodeQL, Trivy and Performance Governance on the exact committed/merge-queue revision. Quality includes PostgreSQL, frontend, migrations/scripts, policies, secrets and both image builds. Record outcomes/artifact digests and investigate any failure without weakening gates.
- [ ] Complete Q1–Q4 environment/operator evidence before release. Commit/CI success alone does not qualify deployment.

Commit, push, PR creation and deployment remain outside the current authorization. This review package is ready for the repository owner's next decision; it does not mark the branch merge-ready or production-ready.

## Exact next repository and environment steps

1. Review the final combined dirty patch and inventory, including pre-existing Phase 3 work, the 90 archive deletions already present at entry, and the scoped P30 frontend repair. Review new regressions/gates/browser evidence and the new frontend manifest under `/private/tmp/sg-p30-containment/`. The refreshed package under `/private/tmp/sg-ci-preparation/` preserves its prior package under `pre-p30/`; do not treat the earlier frontend snapshot as certification of new bytes.
2. Obtain authorization to selectively stage/commit/push (and separately create a PR if requested). Inspect `git diff --cached` and staged secret/migration checks; do not use blind `git add .`. No such authorization is granted by this handoff. Refresh the remote base and resolve any changes without resetting user work.
3. On the exact committed/merge-queue revision run Quality default backend, full PostgreSQL, frontend, migration integrity/catalog/tenant-boundary/scripts, policy checks, unchanged Gitleaks and both image builds; also run required CodeQL, Trivy and Performance Governance. Record revision, artifact digests, results, UTC time and independent reviewer. The prior hosted PostgreSQL shared-memory follow-up still needs that hosted result.
4. Before release, complete closure Q1–Q4: approved stored authority/old credentials review; actual API/worker/migrator revision/flags/replicas/pools/UTC/ingress/TLS/restricted-role evidence; actual migration histories and backup/restore boundary; authorized representative-clone forward and rollback/roll-forward rehearsal; host SIGTERM/drain/recovery; operator browser password setup and controlled provider UNKNOWN reconciliation; named cohort/ENFORCE and hold/release policy evidence. The last observed deployed backend predates the reset; do not infer actual history or compatibility from fresh bootstrap.
5. Keep all contained capabilities disabled and retain the P30 UI repair evidence separately. Only update formal register statuses when revision, environment, result, date and independent reviewer evidence meets each original criterion. Deployment, live database/service changes, credential rotation and real email require specific authorization and an identified target.

The P30 local evidence is `/private/tmp/sg-p30-containment/`: before snapshots and failing regressions, passing frontend logs/coverage, browser results/screenshots, backend/migration preservation comparison, refreshed manifests/review patch and unchanged-rules repository-relative secret scan. Only backend CLAUDE prose changed; all 1,495 backend verification inputs still match the earlier full/default runs. Those backend suites were not rerun solely for the frontend repair. Exact committed hosted results, image builds, independent review and Q1–Q4 environment/operator evidence remain pending.
