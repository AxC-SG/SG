# CBOM V11–V14 Deployment Runbook

## Preconditions

1. Resolve or explicitly quarantine every `DRIFTED` tenant.
2. Confirm backend and frontend artifacts come from the same release.
3. Verify full backend tests, frontend build, scoped stylesheet tests, and migration catalog tests.
4. Capture counts of CRYPTO findings, null-expiry suppressions, pending suppression requests, queued ingestion jobs, and failed delta entries.

## Deployment order

1. Set `app.cbom.assessment.enabled=false` for the first backend rollout.
2. Deploy tenant migrations in order: V11 suppression governance, V12 assessment foundation, V13 canonical verification, and V14 relationships. Skip and quarantine drifted tenants; do not force baselines.
3. Deploy the backend containing hardened routes, mirror behavior, suppression guard, assessment/diff/report APIs, verification, governance, PQC, internal gates, and the bounded graph API.
4. Deploy the frontend containing suppression workflow, tenant policy, assessment provenance, semantic diff, report downloads, and verification state/actions.
5. Confirm no new null-expiry CRYPTO suppression can be created.
6. Run `LegacyCryptoSuppressionCutoverService` in bounded passes until the remaining count is zero.
7. Enable `app.cbom.assessment.enabled=true` on a canary instance, then expand gradually while observing queue age, failures, duration, rejection count, and per-tenant fairness.
8. Backfill active CBOM artifacts by enqueueing one assessment per current artifact. Re-running is safe because assessment identity is artifact checksum + rule digest + evaluator version.
9. Smoke-test one tenant: ingest the valid fixture, confirm assessment provenance, compare successor fixtures, download JSON/HTML reports, request verification, query a depth-1 graph, preview a rule change, and evaluate an internal CI gate.

## Release gates

- Remaining legacy null-expiry CRYPTO suppressions: `0`.
- V11–V14 migration failures among eligible tenants: `0`.
- Assessment queue oldest-visible age under five minutes.
- No cross-tenant/RLS failures and no unexpected suppression-policy denials.
- Legacy accept calls return `410 Gone` and emit removal telemetry.
- Secret-bearing fixture is rejected before an asset, source, or BOM record is written.
- Unsupported pinned packages fail closed; unknown evidence remains `UNKNOWN`, never a failed control.
- Graph requests reject depth greater than 3 or limit greater than 500.
- Verification cannot resolve a CRYPTO finding without an accepted assessment-run ID.

## Recovery

Flyway migrations are forward-only. Disable assessment polling if workers regress, keep read APIs backward-compatible, and ship a forward-fix migration. Suppression hardening must not be rolled back to the legacy accept behavior. V13/V14 are additive and old application instances ignore their columns/tables. Assessment jobs are idempotent by artifact, package digest, and evaluator version and can be replayed safely.

External CI credentials and runtime assurance collectors remain launch-disabled. The internal gate evaluator is deployable for authenticated tenant users, but exposing gate results to pipelines requires the separately reviewed one-job correlation-token credential described in the implementation plan. Runtime collectors require Connector Security approval and are not a deployment prerequisite.
