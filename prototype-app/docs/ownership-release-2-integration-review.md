# Ownership Release 2 integration review

Review date: November 17, 2026 (Asia/Kolkata).

**Disposition: lab-only integration; release blocked.** The user explicitly accepted the lab-only scope and retained
the release block. This is not authorization to migrate a shared database, deploy to AWS/Vercel, enable ownership for
a tenant, discard deployed campaign data, or remove CI/CD gates.

## Integration baseline

- Target baseline: `main` at `8c76d3db` (PR #135 CI/CD hardening).
- Ownership source: `origin/feat/ownership-release-2` at `1282d2a9`.
- Common ancestor: `80c28d0a76610fb6d369356b828ad8c0991dd5d9`.
- Prepared branch: `codex/ownership-release-2-integration`, merging the complete ownership history onto current main.
- The source changes 240 files. Six files overlap the independent main work; the merge has no text conflicts.
  Clean merging alone does not establish runtime compatibility.
- Existing workflow files, release tooling, infrastructure, image qualification, provenance, signed-in smoke,
  worker-progress gates and paired frontend/backend publication are retained from main.

## Findings and disposition

| Priority | Finding | Disposition |
|---|---|---|
| P1 | Both cloud discovery services lost `@Autowired` on `setBackgroundTaskExecutionPolicy`; it was accidentally moved onto the new producer field. Their default `allowAll()` would permit discovery scheduling on API and schema-migrator nodes. | Fixed: restore policy injection, retain one optional producer setter, add six Spring-wiring regression cases for AWS/GCP × api/schema-migrator/worker. |
| P1 | Binary schema compatibility is V27 but base YAML still defaults both bounds to V23 and production pins the minimum to V23. The effective range becomes empty, rejecting upgraded tenants under enforcement. | Fixed: align YAML bounds to V27; the existing `MigrationCatalogTest` guards agreement with the packaged catalog. External environment overrides still need inspection before deployment. |
| P2 | Two existing CBOM integration tests derive fixture/assertion dates from the database session's `current_date`, while the application uses UTC. During India's post-midnight/UTC-previous-day window, one expiry fixture is not expired and the snapshot query checks the wrong day. | Test-only fix: derive both SQL dates explicitly in UTC, retaining the application's existing behavior. Rerun results are recorded below. |
| P2 | The first remote browser run uses pre-Release-2 fixtures: CLOUD_BOM qualification and campaign ledger endpoints fall through to incompatible generic payloads, while ticket-attempt reads are unhandled. Ownership/campaign pages fail to render in those fixtures. | Add explicit qualification, members, owner-buckets, reconciliation and ticket-attempt fixtures, and update campaign outcome/ownership fields. Preserve unexpected-request enforcement and all journey assertions; no production behavior is changed by this follow-up. |
| P1 | V26 drops `campaign_notify_groups.group_email` without migrating existing addresses into `group_email_enc`. The upgrade test explicitly seeds an address and then asserts the old column is removed. | Accepted for this lab-only integration; remains a release blocker for any database whose recipient data must survive. No applied migrations were edited and no shared database was migrated. |
| P1 | Existing custom-recipient workflows now encrypt email unconditionally. `CampaignService.prepareRecipient` returns 503 when the tenant key is unavailable. Only the local/test key wrapper exists; ownership read switches do not restore the old write path. | Release blocked until a deployed wrapper and key provisioning are qualified, or a separately reviewed compatibility implementation preserves the old workflow. Never enable the local wrapper in deployed environments. |
| P2 | Campaign writes, membership materialization, the 15-minute reconciler and the campaign-member finding delete restriction apply independently of ownership read switches. Existing CVE campaigns can acquire members after launch. | Accepted lab behavior. Read-wave rollback restores ownership display/routing only; it is not a full application or database rollback. Reconciler cron `-` stops scheduled reconciliation but does not restore old campaign writes. |
| P2 | Once ticket routing is canonical, CVE ticket creation requires a routing hash that the CVE workbench does not send. | Keep the tickets read wave empty for workbench users until the Release 3 client flow exists. The existing routing/rollback tests cover the server boundary. |

## Release and recovery constraints

Platform head stays V16; tenant head moves V23 → V27. This is a **forward schema release**, not a schema-neutral
runtime reconciliation. The main release tool classifies unequal heads as forward; runtime-only Lab reconcile refuses
schema-changing candidates. Do not weaken that boundary or manually promote a frontend independently of its backend.

If deployment is later authorized, rehearse the exact artifact against a disposable clone, establish recipient-data
disposition, snapshot before the migrator, stop API and worker during migration, migrate to V27, and verify both runtime
roles plus paired frontend smoke. A previous V23 binary cannot simply be rolled back over V27: V24 removes campaign
insert defaults and V26 removes a mapped column. Use the existing snapshot recovery procedure or a qualified forward fix.
Emptying ownership read waves does not reverse these schema changes.

Directory and cloud producers remain disabled by default. CORE/CLOUD_BOM authority and consumer read waves remain
separate tenant decisions. No Organizations role, external ID, IAM grant, connector setting or tenant key was provisioned
by this integration. Optional Organizations access must be qualified separately from the AWS hosting migration.

## Verification

Verification is performed on the combined branch, not copied from the ownership source scorecard.

- Frontend: typecheck, production build/bundle credential scan, lint (0 errors; 2 existing warnings), 124 unit-test files
  and 1,265 tests pass. Coverage passes: statements 59.27%, branches 52.11%, functions 51.77%, lines 61.93%.
- Migration integrity against main and tenant-DDL boundary checks pass.
- CI/CD contract tests: 17 pass; hardening tests: 10 pass; lab release/reconcile/recovery tests: 87 pass.
- Backend: the complete run executes 1,723 unit tests and 949 PostgreSQL integration tests with no skips. It initially
  finds the two UTC date assumptions above; after the test-only fixes, both affected classes pass all seven tests on
  rerun. Retained class reports total 1,723 unit and 949 integration tests with zero failures/errors/skips. This is a
  full-suite run followed by targeted correction checks, not a claim of a second complete suite run.
- Final Spring-wiring/catalog rerun: all ten tests pass. SpotBugs reports zero bugs/errors and passes.
  The full-run configured coverage gate and the final report/check against retained coverage data both pass.
- Redacted Gitleaks scan of all 41 ownership commits passes with no leaks.
- PostgreSQL tests use a new disposable cluster on port 55432, not a shared/deployed database.
- Local Node is v26.12.1; CI's pinned Node 24 qualification remains required. Java is 17.
- Browser/accessibility/visual checks, exact-container qualification and live ServiceNow/AWS/GCP/KMS qualification have
  not been performed in the initial local review. Remote CI results are recorded separately below; existing CI checks
  remain required before merging to remote main.

### Remote CI follow-up

The [successful remote Quality run](https://github.com/AxC-SG/SG/actions/runs/43940270940) qualifies code/fixture revision
`252808d81cca3ca82f1be5d8d4b811eda8a758ef`. The final Quality gate, Node 24 frontend, backend unit/coverage/SpotBugs,
full PostgreSQL suite with its no-skips report check, static/migration checks, Gitleaks, Semgrep, filesystem scanning,
and exact ECS image migration inspection, migrator/API/worker startup and image scan all pass. CodeQL and the Vercel
branch preview also pass. All six pinned-browser journeys pass: findings 67, CVE 94, governance 168, inventory 108,
connectors 126 and campaign/experience 264 (827 checks total). Terraform and scheduled performance jobs are skipped by
the existing component/event selection; PR publication is skipped by design. No AWS deployment is performed.

The fixture follow-up also passes 457 local affected-journey checks, lint with the same two existing warnings and all
five browser-runner tests. Production source and CI gates are unchanged by that follow-up. Later documentation-only
commits record this immutable evidence; consult [PR #136](https://github.com/AxC-SG/SG/pull/136) for checks on its current
head. Final merge review and all release blockers remain separate from CI success.
CI fixture journeys and isolated image startup do not establish live-provider, full new-screen accessibility/visual or
production release qualification.

The [qualification scorecard](ownership-release-2-qualification.md) retains its additional external-input and Release 3
gaps. Passing local checks does not lift the release block.

## Delivery state

Local merge commit: `569a54a0` (parents `8c76d3db`, `1282d2a9`). All four `CLAUDE.md` files and the affected product,
API, architecture, ownership and AWS qualification documents are updated. The temporary PostgreSQL cluster has been
stopped after verification. Remote main, AWS runtime and production deployments are unchanged; the existing Vercel
integration creates a successful branch preview as part of PR validation.

The user approved publishing the integration branch and opening a draft PR on November 17, 2026, after the initial
push was rejected for missing explicit publication authorization. Publication approval does not lift the release block.
The branch is published in [draft PR #136](https://github.com/AxC-SG/SG/pull/136), targeting main. Revision `252808d8` passes
all required remote checks and is conflict-free against main `8c76d3db`. Current-head CI and final merge review remain
required; deployment and tenant enablement remain blocked.
