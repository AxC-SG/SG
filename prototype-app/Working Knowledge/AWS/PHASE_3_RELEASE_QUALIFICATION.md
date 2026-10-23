# Phase 3 release qualification

As of October 21, 2026, local repairs and the current verification checkpoint are recorded in [implementation status](PHASE_3_IMPLEMENTATION_STATUS.md). Phase 3 remains **in progress and not release-qualified**. This checklist is a reviewable handoff, not authorization to deploy, modify a live database, rotate credentials, send real email or change service configuration.

## Local P30 containment checkpoint

**P30 repair — October 21, 2026:** [Reconciliation and repair evidence](DOCUMENTATION_RECONCILIATION.md#p30-frontend-repair) records removal of the Patch Management cards, connector IDs, mounting branches and four unsupported mock modules, including their credential/input logging handlers. Query bookmarks and direct paths cannot mount these forms. New catalog/navigation regressions and refreshed frontend gates pass on the changed bytes. Fix Intelligence API/routes, tenant OSV and runtime containment remain intact. Independent review, exact committed CI and environment qualification remain pending.

The scoped local frontend repair is complete. Review its new frontend manifest/regression/browser evidence and qualify the exact committed candidate through CI and independent review. Local checks do not certify a deployed environment.

## Environment evidence still required

| Boundary / owner | Required evidence | Current limit |
|---|---|---|
| P13/P18 — platform | Actual service names, revision/artifact digest, effective runtime role, scheduling and individual path flags, replica counts, UTC cron configuration and aggregate connection-pool budget. Include every active backend, worker and migrator. | The last authorized read-only [Render observation](runtime-topology-check.md) listed an older backend and a still-present migrator. Available metadata did not expose effective environment values. Repository defaults cannot fill this gap. |
| P14 — platform | Termination grace exceeds the configured executor wait; accepted work drains or recovers when the actual process is terminated. Verify claims, execution, commit and restart on the intended candidate artifact. | Local real-JVM SIGTERM tests and all four executor queue-drain tests pass. The default executor wait is 20 seconds; a host's hard-kill deadline is independent. |
| P19 — platform/security | Restricted runtime identity, no ownership/superuser/BYPASSRLS/DDL, retained GHSA and tenant access, forced RLS, actual JDBC option preservation, current endpoint certificate chain and hostname with verified trust. Capture counts/booleans only, never passwords, full connection URLs or bearer values. | Bootstrap-provisioned restricted-role local journeys pass. Local PostgreSQL JDBC `verify-full` accepts the trusted matching certificate and rejects wrong hostname, untrusted certificate and absent trust file. This does not verify Render's endpoint or trust anchors. |
| P20/P21/P23 — platform/backend | Rehearse supported bootstrap/upgrade, per-tenant failure/retry and readiness against an authorized representative clone, using the intended migration role separately from the runtime. Report-only must remain non-mutating. | Disposable fresh/repeat bootstrap, injected runtime-grant failure, inaccessible failure state, explicit retry/activation after grants and report-only under a rejecting DDL trigger pass. Existing deployed schema history is not known. |
| P27/P28/P32 — backend/UI/operator | Supported LOCAL/EXTERNAL mode and current support/service-account authority on the candidate; invitation/setup/password login and campaign reconciliation with controlled delivery. An operator enters any new browser password. | Restricted-role HTTP tests cover LOCAL login, revoked support, signed EXTERNAL human/machine claims, registry denial and invitation/setup-cookie/CSRF/password/login. Local production-build browser login reaches the tenant with Bearer auth and no API-key/tenant-header fallback; fragment invite validation/acceptance reaches password setup and strips the token from the URL. Browser password submission and a deployed issuer/provider are not certified by these checks. |
| P26/P29/P31 — backend/product/platform | Effective internal pilot cohort `slug:scoutgrid-internal-pilot`, ENFORCE mode, capability matrix and server containment flags; agreed existing hold/release policy and operator recovery. | Local entitlement/containment/retention tests pass. No live pilot tenant or effective mode is claimed. Generic Azure, SCCM JDBC, runtime evidence, Fix Intelligence/tenant OSV and retired patch-form containment, local archives, generative assistance and destructive tenant purge retain their existing containment. |

## Upgrade and rollback boundary

The last observed backend revision is `acb4bfc0a0259ce98c01cc820bbbc50e76ff8b1f`. Its source packages **platform V1–V7 and tenant V1–V13**, with different V1 contents from the current baseline. Commit `e2af3fedef28308350e7d6dc79899fa5762f9e01` consolidated development migrations. The current platform V1 and tenant V1 match that consolidation; subsequent prerequisite migrations reach independent platform **V6** and tenant **V5**. Platform V6 adds the rollout assessment waiting state and legacy claim grace period; only the reset-history V5-to-V6 transition is locally qualified. This binary requires tenant V5 and the platform work coordination structures checked by startup/readiness. The next platform version is V7 and the next tenant version is V6.

Consequently, neither an additive upgrade from the last observed deployed revision nor a rollback to that binary is established. An older source revision does not prove which migrations actually ran in the deployed database. **Do not reset the existing database, edit applied migrations or use `flyway:repair` to disguise the differing histories.** No such operation was performed here.

Before authorizing a rollout:

1. Inspect the actual migration histories and catalog read-only, with secret-safe output. Identify the database backup/restore boundary and the exact candidate and rollback artifact digests.
2. Rehearse the supported transition on an explicitly authorized, isolated database clone. If it has the older history, agree on a separate forward migration/data-preservation plan before applying this candidate. Fresh bootstrap passing is insufficient.
3. Exercise the chosen previous binary against the resulting additive schema and retained state: pending/leased work, encryption key versions, hashed links, outboxes, schedule identities, retention progress and authentication authority. A binary that cannot preserve these contracts is not a supported rollback target.
4. Record the tested rollback or roll-forward procedure and restore evidence, then perform candidate environment journeys and termination/recovery checks. Keep destructive purge disabled.

The source migration comparison is retained under `/private/tmp/sg-phase3-completion/migration-history-comparison.json`. It is static source evidence, not a live schema inspection or a successful rollback rehearsal.

## Authorization required to finish

The pasted handoff explicitly permits autonomous implementation and read-only inspection of Scout workspace `tea-d9adqh3eo5us739qcfag`, and explicitly excludes deployment, live database mutation, credential rotation, real email and service changes. Remaining work requires an identified staging/clone target, approved candidate/rollback artifacts, and explicit authorization for the specific deployment, bootstrap or controlled delivery operation. Read-only environment evidence may instead be supplied by the responsible operator. No commit or push has been performed.
