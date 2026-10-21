# Phase 3 implementation status

Phase 3 (M2) is **in progress and is not release-qualified**. Changes remain on `codex/application-prerequisite-fixes`. This checkpoint does not mark all plan items complete or authorize deployment.

## What this changes for users

- Selected connector requests save their work before reporting acceptance. Restart recovery preserves healthy work and can retry expired work.
- A duplicate request reuses accepted work. Reaching an attempt limit releases the linked connector/source so another request can be made.
- Invitation and campaign messages save encrypted delivery intent with the business change. Retry uses the same message and delivery identity. Provider acceptance is distinct from delivery to an inbox.
- Generic Azure discovery and local vulnerability archives are disabled for the pilot. Existing inventory, canonical content and historical archive references are retained.
- Generative assistance remains disabled in deployed pilot profiles; deterministic investigation and recommendation paths remain available.
- The selected internal entitlement pilot is `scoutgrid-internal-pilot` (`slug:scoutgrid-internal-pilot`). This is a release configuration choice, not a claim that a live tenant was created.

## Implementation boundaries

| Plan item | Current implementation / remaining work |
|---|---|
| P10–P12, P14, P18 | Role guards and shutdown admission; transactional tenant delta publication; ingestion attempt tokens, heartbeat, domain-commit fence and bounded periodic expired recovery; atomic GitHub/AWS/ServiceNow admission; exact assessment identity in rollouts; audit committed with ingestion success. Independent review found four gaps; corresponding fixes and regressions are included. Remaining logical-occurrence and whole-family qualification stays open. |
| P13 | All scheduled entrypoints are classified in [the schedule matrix](PHASE_3_SCHEDULE_MATRIX.md). Deprecation tasks now use an expiring token claim and atomic finding/event/completion transaction; expired recovery, healthy ownership and rollback regressions passed. EOL/OSV/EPSS now dispatch through owned sync runs with durable occurrence identity; Copilot cursor and job admission commit together. Demo data and completion commit under one tenant row lock. Cron annotations explicitly select UTC. Azure credential overlap/rotation and ingestion pre-dispatch shutdown checks are covered by the October 21 continuation. Remaining maintenance overlap, process shutdown, provider/fanout replay and deployed time-zone/revision evidence remain open. |
| P16 | NVD completed-interval continuity per filter scope; bounded windows and honest incomplete pages; EPSS UUID keyset scan. Global feed publication selects each tenant before its publication transaction and reports incomplete fanout if any tenant fails. EPSS publication/freshness recovery and missing-score/page-failure replay are covered by the October 21 continuation. NVD gap/filter/multi-window and other feed-fanout replay qualification remain. |
| P17, P24 | Generic Azure hard containment across configuration, target, admission and execution boundaries; independent AI Azure retained. Archive filesystem operations blocked; newly fetched canonical description/raw payload stay in PostgreSQL; historical-only archive content reports unavailable. |
| P19–P21, P23 | Explicit public GHSA grants; schema grants verified before activation; report-only privilege inspection avoids DDL probes; migration wrapper preserves transport options and offers run-once behavior; tenant eligibility/readiness use the same declared floor. This binary requires tenant V5, including retention progress. Previous binaries still require separate additive-schema rollback qualification. Current-environment TLS/hostname proof and full failure/retry lifecycle checks remain. |
| P26 | Retention sweep uses bounded independent transactions and a durable cursor; legal holds and reference checks remain effective; the October 21 continuation adds restricted-role hold/reference/replay/concurrency coverage and truthful failed/reference reporting. [The cleanup matrix](PHASE_3_CLEANUP_MATRIX.md) records existing policies and remaining dependency/replay/overlap checks without inventing retention periods. |
| P27–P29 | Explicit LOCAL/EXTERNAL JWT contracts, issuer/audience/access-purpose validation, ambient setup-cookie CSRF, same-tenant active service-account registry and assignment restrictions; named entitlement cohort without wildcards. Complete supported-mode/registry/support and browser journeys remain qualification work. |
| P31 | Server-side generative gate precedes credential resolution in shared and direct call paths; deterministic fallbacks remain. |
| P32 | Separate platform invitation and tenant campaign outboxes; encrypted immutable payloads, per-delivery idempotency keys, bounded retry, visible UNKNOWN state and controlled operator reconciliation. Provider retry stops at 23 hours, within Resend's documented 24-hour idempotency retention. Campaign-specific and restricted-role pre-auth qualification remains. |
| P34–P35 | Spreadsheet-safe audit CSV, bounded opaque request IDs; role/scope, refresh validity/error/age and per-tenant failure isolation; dashboard request samples identify their local bounded window. |

Database TLS/grants is **P19**. **P27** is authentication-mode coherence; earlier shorthand that called TLS “P27” should not be used as the plan mapping.

## Schedule and demo continuation — October 20, 2026

- EOL manual requests persist intent without invoking a local executor, including on API nodes. EOL stages serialize execution without discarding a different requested stage. Catalog/release batches and tenant effects use fenced transactions, and tenant publication failures remain failed rather than successful zero-row work.
- OSV and EPSS execute through the existing leased sync-run worker. Daily vulnerability schedules retain per-type UTC-date identities after terminal completion. New occurrences can queue behind a conflicting active run while unrelated feed families progress. Polling selects the oldest candidate per supported type, so a blocked family cannot fill the 100-row selection and hide other feeds.
- Copilot scheduling stores a per-tenant/connector cursor in the same transaction as tenant job admission. Failed admission cannot consume an occurrence. Existing active-job deduplication remains.
- Demo seeding selects the tenant before its transaction, holds a NOWAIT tenant lock, and commits data with the completion marker. Rollback releases the healthy-owner lock; existing SEEDING markers can be resumed. The seeder performs database work, with no provider delivery in this transaction.
- Forward platform migration **V5** adds the schedule-occurrence index and Copilot progress table. Tenant head and required floor remain **V5**. Earlier migrations were not edited. Rollback to a binary that lacks schedule coordination still needs release qualification.

No repository files were moved or deleted by this continuation. Existing user changes and archived-document moves/deletions remain untouched. Verification results follow.

## Verification and release evidence

Verification runs in disposable source copies and an isolated PostgreSQL 16 instance. Test SMTP/provider calls use stubs; no real email is sent. Current-source tests cover producer rollback, concurrent duplicate admission, expired-owner commits, healthy leases, periodic recovery, attempt-limit/source recovery, feed-to-tenant publication, bounded retention/holds, JWT mode claims, explicit cohort parsing, metric validity and delivery retry/reconciliation. The pre-change atomicity reproduction uses a separate disposable database.

The October 20 schedule checkpoint backend `mvn -q -o verify` passed: **1,284 reported, 1,279 executed and five existing OSV skips**. Line coverage was **31.5%**, above the unchanged 25% floor; SpotBugs passed. The full PostgreSQL Failsafe suite passed **410 tests across 91 classes**, with zero failures/errors/skips. The five OSV controller checks skipped by the default unit profile also passed explicitly: **415 database checks total**. The 14 schedule/restart cases include completed-occurrence dedupe, atomic rollback, executor rejection, independent tenants, a blocked backlog exceeding the poll bound, stale EOL ownership, and demo seed recovery/overlap. Real demo dataset provisioning also passed.

The earlier demo seeder reproduced the stranded SEEDING error; the earlier queue query reproduced an independent OSV run remaining queued behind 101 blocked EOL rows. Both regressions passed against the fixes. The prior producer-rollback and deprecation reproductions remain earlier checkpoint evidence. Migration integrity/validation/tenant-boundary checks, unchanged baseline checks and `git diff --check` passed again. A final backend-source secret scan found no leaks, without changing scanner rules.

At that schedule checkpoint, all **1,473** backend source/resource/test/POM files matched the passing unit and database copies. Snapshot SHA-256: `1650549992812a4984d59aa06a9a25d619f41ccd852c94edd78a10964fe71b1a`. Test commands, reports, reproductions and the source manifest are retained in the task-owned disposable evidence directory. The isolated PostgreSQL instance was stopped after verification. No live database, tenant, provider delivery, deployment or service configuration was changed.

Frontend source was unchanged in this continuation. The earlier frontend lint/type/build/coverage result remains **74 files and 654 tests**; those frontend gates were not rerun for these backend changes.

The Phase 3 changed-file secret scan passed. A repository-wide scan still flags 11 existing documentation examples/text: 10 curl placeholders in unchanged archive files and one phrase in the unchanged production architecture review. No scan rules or allowlists were loosened. These findings are retained separately from the candidate scan.

The Azure disabled-state screenshot was checked in an isolated browser with stubbed API responses; it is visual evidence, not a deployed backend journey.

Read-only Render findings are in [runtime-topology-check.md](runtime-topology-check.md). The deployed backend is an older revision, and effective runtime roles/scheduler flags were not exposed by the available metadata. No services, credentials or database contents in the deployed environment were changed.

Provider reference: [Resend idempotency keys](https://resend.com/docs/dashboard/emails/idempotency-keys). The application uses a conservative 23-hour automatic replay cutoff and requires an operator decision after unknown acceptance; it never treats provider acceptance as confirmed inbox delivery.

## Maintenance, retention and EPSS continuation — October 21, 2026

- Azure credential expiry/warning effects use conditional updates against the scanned expiry and warning threshold. Concurrent sweeps record one transition/audit, and rotation after the candidate read cannot expire or warn a replacement secret with a different expiry. Audit failure rolls back the transition.
- Ingestion polling rechecks shutdown between tenants and claim groups and returns accepted, undispatched claims to QUEUED with `WORKER_STOPPING`. A replacement worker can claim them. Work already dispatched keeps the existing owned execution/fencing path; actual process termination and complete executor draining remain unqualified.
- EPSS commits scores while retaining stale eligibility, publishes tenant recomputation intent, then acknowledges freshness in a separate fenced transaction. A failed tenant or interruption before the acknowledgment can replay identical scores. Replay refetches provider scores; this is not a durable snapshot of historical provider responses. Each successfully scored batch republishes intent, including unchanged scores; the existing tenant queue deduplicates pending intent.
- Retention now persists FAILED even when the first batch rolls back. Existing manifest references are reported as `PURGE_BLOCKED` / `SNAPSHOT_REFERENCE`, matching the existing final deletion check. No retention period or deletion policy changed. Restricted-role fixtures cover protected/referenced/unexpired evidence, concurrent hold creation and policy extension, overlapping sweeps, bounded resume after failure, and purge audit identity.
- Packaged migration heads and required tenant floor remain platform **V5** / tenant **V5**. No migration, frontend, deployment, service configuration, live database or provider delivery changed. Existing user edits and archive moves/deletions are preserved.

The continuation backend `mvn -q -o verify` passed: **1,286 reported, 1,281 executed, five existing OSV skips**. Line coverage is **31.5%**, above the unchanged 25% floor; SpotBugs reported zero findings. Focused PostgreSQL qualification passed **38 tests across five classes**, with no failures/errors/skips: 15 new maintenance/retention/EPSS cases plus 23 retained durable-work and schedule cases. The final six-case retention run replaces its earlier five-case result. Full PostgreSQL and frontend suites were not repeated; their October 20 results remain earlier checkpoint evidence rather than new results for these changes.

The saved pre-change implementations reproduced duplicate credential audit, rotation-after-scan, continued shutdown dispatch and EPSS publication/freshness failures. The fixed cases passed. The earlier retention implementation also reproduced absent first-batch failure progress and incorrect manifest-reference eligibility; both passed against the fixes. The source scan passed with the existing repository rules and relative paths; no scanner allowlists changed. `git diff --check` passed. No migration resources changed, so the previously passed migration-integrity/validation results were not rerun.

All **1,476** backend source/resource/test/POM files match the final verification copies. Manifest SHA-256: `100e4b86ea63d1c6a7bee7f68a60673e4d9538533f53805b27f09deb23dd020e`. The only test-source adjustment after the passing default verify was the retention integration fixture/diagnostic, followed by test compilation and the passing six-case PostgreSQL run; production and unit-test source stayed unchanged. Commands, XML reports, source manifest, saved earlier implementations and reproductions are under `/private/tmp/noscan-phase3-maintenance/`. The disposable PostgreSQL instance was stopped after verification and reproductions. The October 20 evidence remains a separate checkpoint. Phase 3 remains **in progress and not release-qualified**.

## Full PostgreSQL CI follow-up — October 21, 2026

The full PostgreSQL run on `8eea4151` reported 425 tests, with two failures and four errors. The observation test still expected snapshot-referenced evidence to become purge eligible after legal-hold release; it now verifies that the hold clears while the snapshot reference continues blocking purge. The disabled-deletion test now compares the password timestamp loaded from PostgreSQL before and after the request, avoiding Java nanosecond versus PostgreSQL microsecond rounding. The remaining four errors followed PostgreSQL shared-memory exhaustion in the CI service container; the Quality workflow now reserves 1 GiB of shared memory for that service. These changes affect tests and CI only. Fresh full-suite verification is pending on the updated PR revision.

## Next implementation work

1. Qualify remaining maintenance overlap (finding workflow, asset lifecycle, suppression, incident/projection/exposure paths) and full process shutdown boundaries.
2. Complete cleanup dependency and overlap checks, including queued/unknown deliveries during demo expiry.
3. Complete NVD gap/filter/multi-window and remaining feed-fanout replay qualification; qualify supported authentication/email journeys with the restricted runtime role.
4. Verify deployed roles, scheduler flags and TLS, then assemble release and rollback evidence.
