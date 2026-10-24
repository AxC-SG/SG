# Harm assessment implementation verification

Verified on 12 October 2026 on branch `codex/harm-assessment-metadata`.

## Results

- Latest focused backend verification: 25 unit tests and 3 PostgreSQL baseline integration tests passed, including Maven verification gates. The integration tests exercise approvals, history, role and tenant enforcement, source references, drift reconciliation, key rotation, stale/duplicate/out-of-order evidence, guardrail comparisons, and upgrade compatibility.
- Existing observation ingestion integration suite: 14 PostgreSQL tests passed. Additional focused provider discovery tests passed during implementation.
- Frontend: production build and bundle verification passed; coverage run passed all 644 tests in 70 files. Baseline component and asset-detail interaction tests cover approval actions and safe request bodies. Focused lint and type checks passed.
- Policy compilation, Phase 2 catalog validation (83 entries), legacy parity validation (21 installed policies), and standalone package validation (2 packages) passed.
- `git diff --check` passed. The provider comparison matrix retains 22 objectives and 66 classified provider rows.

## Reproduction

From `prototype-app/backend`:

```sh
mvn -q -Ppostgres-it verify -Dit.test=AiHarmBaselinePostgresIntegrationTest -Dtest=AiHarmMetadataTest,AiGridFactProducerTest,AiSecurityDigestBaselineServiceTest,AiGridSnapshotServiceTest,AiGridFindingServiceTest,MigrationCatalogTest
```

From `prototype-app/frontend`:

```sh
npm run build
npm run test:coverage
```

From the repository root:

```sh
node prototype-app/scripts/compile-ai-grid-phase1.mjs
node prototype-app/scripts/validate-ai-grid-phase2-catalog.mjs
node prototype-app/scripts/validate-ai-grid-legacy-parity.mjs
git diff --check
```

The archived standalone package validator was run with its package root adjusted to this checkout, since the original root-level script was already removed in the working tree.

## Scope and rollout

Platform migration V9 and tenant migration V15 were verified against disposable PostgreSQL databases, including an upgrade from existing V14 baseline records. No production migration was run. Tests and the [baseline UI screenshot](../../output/playwright/harm-baseline-section.png) use local fixtures; the screenshot shows the actual component with sanitized fixture evidence.

H14 remains DRAFT/PAUSED with default DISABLED selection. Owner-facing findings require existing certification, approved distribution, release, canary visibility and tenant selection gates. Production tenant evidence and rollout readiness remain unverified. No tenant policies were bulk-enabled, and no provider API calls or raw-content collection were added.

See the [metadata matrix](ai-grid-harm-policy-metadata-matrix.md) and [policy readiness manifest](harm-policy-readiness.json) for supported claims and deferred evidence requirements. Existing unrelated working-tree changes were preserved.
