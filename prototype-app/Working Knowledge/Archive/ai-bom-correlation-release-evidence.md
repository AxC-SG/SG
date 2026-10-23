# AI-BOM correlation implementation and release evidence

Implemented on `codex/ai-bom-correlation-repair`, based on the attached implementation plan. The implementation is separated into storage/matching, reconciliation/readers, and classification/display review groups. The review stack starts from the existing AI-findings work at `30a70b83`, whose prerequisite commits are not yet on `main`. Existing unrelated working-tree changes were preserved.

## Review stack

1. [PR #59 — storage and strict bounded matching](https://github.com/ggkarthik/Scout/pull/59), based on `codex/ai-findings-repair`.
2. [PR #60 — atomic reconciliation and lifecycle-aware readers](https://github.com/ggkarthik/Scout/pull/60), based on PR #59's branch.
3. [PR #61 — uncertainty display, classification coverage, and release evidence](https://github.com/ggkarthik/Scout/pull/61), based on PR #60's branch.

All are draft PRs. No deployment, merge, or retirement enablement has been performed. Local verification below is complete; hosted CI is separate and runs on each PR.

## Delivered behavior

- Tenant V2 adds association lifecycle, ordered dependency paths, independent correlation gaps, and lifecycle history. Tenant and platform V1 migrations are unchanged. Fresh provisioning and V1-to-V2 upgrades are tested, including RLS and existing link uniqueness.
- Exact SemVer prerelease identity preserves qualifier case and rejects malformed versions; Maven qualifier aliases cannot manufacture a SemVer match. Invalid evidence in an unrelated ecosystem cannot block a valid identity match.
- A pure resolver follows only `DEPENDS_ON`/`COMPOSED_OF` edges from the source's current document. It retains diamond paths, guards cycles locally, and reports every configured traversal limit. Package identities include ecosystem, namespace, trustworthy version, and canonical package URL qualifiers. Duplicate inventory identities and duplicate document references produce gaps. Explicit ecosystem/name/version fallback is supported when a package URL is absent.
- Reconciliation owns a transaction per resource after tenant context is established. It captures source revision, locks source then resource, rejects mismatched revisions, and holds the source lock through commit. Upload replacement and document deletion use the same source lock. Scheduling updates only the state column so detached snapshots cannot overwrite document revisions.
- Links, paths, gaps, and affected-resource subjects change atomically. Existing links missing subjects are repaired. Definite path withdrawal proceeds independently of unrelated gaps; unavailable documents and failed units retain prior support. Supported document deletion, PARTIAL replacement, omitted declarations, dependency version changes, last-path retirement, and reactivation are covered.
- Canonical findings retain status, owner, due date, suppression fields, and identity. Closed findings can carry valid associations. Neither reconciliation nor retirement creates or resolves a finding.
- Current detail, affected-resource summaries, JPA filters, and SQL projection filters exclude retired links. The projection's stored subject data concerns artifact subjects, not these AI-resource associations; affected-resource predicates read live links, so no projection refresh is needed.
- Resource detail and a paginated correlation endpoint expose paths, unresolved gaps with remediation, retired support, retained uncertainty, and legacy links awaiting path confirmation. Retired/reactivated paths preserve lifecycle events and the retired BOM/component/relationship evidence.
- Serving-software, model-weights, dataset, and mis-typed serving fixtures document the existing classification boundary. Upload success describes completed ingestion and asynchronous assessment/linking; empty results do not claim successful assessment.

## Validation recorded on 2026-10-13

| Check | Result |
| --- | --- |
| Clean committed snapshot: full backend unit suite | 1,159 passed; no skipped tests, failures, or errors |
| Focused PostgreSQL suites | 39 passed; no skipped tests, failures, or errors |
| Clean committed snapshot: complete PostgreSQL CI suite | 249 tests passed across 77 classes; no skipped tests, failures, or errors |
| Backend coverage gate and SpotBugs | Passed in `verify` |
| Frontend lint | Passed; three existing warnings in unrelated files |
| Frontend typecheck and production build | Passed |
| Full frontend coverage suite | 650 tests passed across 71 files |
| Migration validation, integrity, and tenant DDL guards | Passed |
| Schema migrator environment tests and diff whitespace check | Passed |

Backend verification used an isolated PostgreSQL 16 cluster in `/tmp`, bound to loopback port 55439. No application database was used. The complete CI command ran from a clean Git archive excluding unrelated local changes: `APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED=false mvn -q -Ppostgres-it -Dpostgres.test.admin-url=jdbc:postgresql://127.0.0.1:55439/postgres -Dpostgres.test.username=ai_bom_test verify`. The focused acceptance command was `mvn -q -Ppostgres-it -Dit.test=AiBomResourceVulnerabilityCorrelationPostgresIntegrationTest,AiBomLifecycleBaselinePostgresIntegrationTest,AiBomDeclaredInventoryPostgresIntegrationTest,AiBomAffectedResourceFindingsFilterPostgresIntegrationTest,AiBomDeclaredResourceControllerPostgresIntegrationTest,AiBomProjectionQueueCapPostgresIntegrationTest,BomInventoryReadServicePostgresIntegrationTest -Dpostgres.test.admin-url=jdbc:postgresql://127.0.0.1:55439/postgres -Dpostgres.test.username=ai_bom_test verify`.

Frontend verification ran lint, typecheck, build, and `npm run test:coverage -- --maxWorkers=4`. The worker limit avoids unrelated App-test timeouts seen during an unrestricted run.

The shared-pipeline fixture (`src/test/resources/fixtures/ai-bom/model-framework-vulnerable-library.json`) ingests model → vLLM → runtime wrapper → vulnerable library. Shared software recomputation creates exactly one canonical finding; reconciliation records three ordered dependency edges. Removing its terminal support retires the association without changing the finding; restoring support reuses the association and path identity.

Observed fixture transitions include:

| Scenario | Verified result |
| --- | --- |
| Diamond graph | Two paths, one association; removing one path retains the association |
| Last-path withdrawal | Association retired; its affected-resource subject removed |
| Restoration | Association identity reused; subject restored; retirement history retained |
| Missing version / traversal truncation | Prior support retained and visibly qualified by a gap |
| Missing or failed current document | Prior support retained; `SOURCE_DOCUMENT_UNAVAILABLE` recorded |
| Injected subject-write failure | Link/path/subject writes rolled back; subsequent sweep repairs the unit |
| Replacement races | A captured older revision cannot overwrite newer support; a writer paused after reconciliation computes evidence waits for the source lock to commit |
| Cross-tenant concurrency | Four simultaneous reconcilers across two provisioned schemas produce one link/path/subject per resource; foreign identifiers cannot read or mutate another tenant; thread context is restored |
| Ambiguous identity / conflicting versions | Prior association and path identities survive with visible gaps; disambiguation or a valid replacement resolves the gap without creating a second association |
| Tenant/resource failures | A failed resource transaction rolls back while another resource commits; a tenant read failure leaves other tenants running and the next sweep repairs it |
| Unrelated PARTIAL asset upload | Existing AI dependency support, inventory component presence, and finding status remain unchanged |
| Observation mode | Legacy subject repaired; unsupported association remains ACTIVE |
| Writes disabled | Association/subject writes remain disabled |
| Repeated delivery | Link/path/subject identities and canonical finding count remain stable |

## Browser review evidence

The user story is a declared model resource whose software dependency already has a canonical finding: a reviewer can inspect ordered support, see incomplete version evidence and retained uncertainty, then request retired history separately. The browser previews render the actual before/after detail page in clean archives using deterministic demo HTTP fixtures; these screenshots do not claim a deployed environment or live database connection.

| Boundary | Evidence |
| --- | --- |
| Browser → API | Detail and findings GETs returned 200; selecting Retired history issued `/api/bom/declared-resources/resource-1/correlation?history=true&page=0&size=50` and returned 200 in the fixture preview |
| API → database | Real PostgreSQL controller/reconciliation suites cover tenant authorization, path/gap persistence, active-only filtering, pagination, rollback, and lifecycle transitions; all 249 integration tests passed |
| Response → UI | Browser DOM and images show the three ordered edges, VERSION_MISSING remediation, retained uncertainty, and explicit RETIRED reason/time only in history; the preview console had zero errors/warnings |

[Before](../../output/playwright/ai-bom-before.png) · [Current support and uncertainty](../../output/playwright/ai-bom-after.png) · [Retired history](../../output/playwright/ai-bom-history.png)

## Rollout and rollback

Default: `AI_BOM_CORRELATION_WRITES_ENABLED=true`, `AI_BOM_CORRELATION_RETIREMENT_ENABLED=false`. The existing production sweep backfills supported paths and repairs subjects repeatedly while logging desired versus active link counts, desired/withdrawn/uncertain path counts, subject repairs, retirements, reactivations, gaps, and limits using identifiers rather than BOM payloads.

Apply tenant V2 with the existing schema migrator before deploying schema-aware application code. Deploy active-reader changes together with reconciliation. Let the existing worker perform observation passes for representative tenants, inspect paths/gaps and proposed withdrawals, and retain the release evidence before setting `AI_BOM_CORRELATION_RETIREMENT_ENABLED=true`. Incomplete units retain uncertain support even after retirement is enabled.

For rollback, set both `AI_BOM_CORRELATION_RETIREMENT_ENABLED=false` and `AI_BOM_CORRELATION_WRITES_ENABLED=false`. Keep the forward migration and history-aware readers. Shared software correlation continues independently.

## Remaining release work and explicit boundaries

| Owner | Item | Reason and follow-up |
| --- | --- | --- |
| Release maintainer | Production observation and retirement enablement | Representative multi-tenant fixture observations and repeatable backfill checks are complete; representative live-tenant observations require the deployment environment. Retirement stays disabled until those observations are recorded. |
| BOM lifecycle maintainer | Future source disable/hard-delete transitions | The repository has a supported BOM soft-delete operation, which is covered. It has no source-disable/hard-delete API to exercise. Any future such API must coordinate the source lock and preserve association history rather than relying on raw FK cascades. |

Exact upload-completion receipts, shared queue schema changes, a full stage UI, automatic classification correction, direct model/dataset advisory ingestion, deployment-based priority changes, and deleted-artifact posture closure remain outside this change, as specified in the plan. Mis-typed serving software remains excluded according to its declared type; the classification tests demonstrate this consequence rather than claiming to fix it.
