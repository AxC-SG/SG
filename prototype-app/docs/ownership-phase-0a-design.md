# Ownership MVP — Phase 0A Architecture Gate Design

Status: draft for approval  
Source plan: `docs/ownership-capability-mvp-plan.md` §16.2  
Baseline: `main` @ `98155ae6` — tenant migrations V1–V19, platform migrations V1–V10.

This document records the repository-grounded decisions for the nine Release-1 prerequisites. Items that need
deployed infrastructure, production-scale data or people are marked **OPEN** and must be closed by their owners
before the Release-1 authority switch (§15.3). Code in Release 1 is written against the interfaces defined here so
that the open items change configuration, not structure.

## 1. Storage map and migrations (prerequisite 1)

Next free versions: **tenant V20**, **platform V11** (re-verify before each merge; `PackagedMigrationCatalog`
derives targets from the highest packaged version and rejects gaps/duplicates).

Conventions copied from tenant V19: `-- migration-guard: tenant-only` header, `${tenantSchema}` /
`${tenantId}`, `tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id)`,
`ENABLE` + `FORCE ROW LEVEL SECURITY`, and a `tenant_isolation` policy on `app.current_tenant_id`.

| Migration | Contents |
|---|---|
| platform V11 `tenant_data_keys_and_ownership_authority` | `tenant_data_keys` (tenant, key version, KMS key ref, wrapped DEK, state, created/rotated); `ownership_domain_authority` (tenant, domain, state `LEGACY/DARK/CANONICAL`, accepted_by/at); `ownership_kill_switches` (source kind, tenant nullable, state) |
| tenant V20 `identity_and_teams` | `team`, `team_alias`, `directory_user`, `directory_group`, `external_identity`, `external_group`, `directory_group_member`, `external_group_team_mapping`, `team_member`, `identity_source`, `identity_import_run` |
| tenant V21 `ownership_core` | `ownership_subject`, `ownership_subject_edge`, `ownership_claim`, `ownership_assignment`, `ownership_review_item`, `ownership_event`, `ownership_effective_assignment` (view), optional `ownership_effective_cache` |
| tenant V22 `ownership_projection_columns` | additive `ownership_subject_id`, `assignee_principal_id` on asset/finding projections; exception owner-snapshot columns (§7.3) |
| later releases | campaign/investigation columns (R2/R3), cleanup drops (post-GA) |

Rules: DDL is forward-only; every cross-row reference is tenant-inclusive (`(tenant_id, id)` candidate keys);
no cross-tenant cascade; new tables are added to tenant purge coverage and `TenantSchemaFingerprint`; grants follow
the existing tenant-role grant block used by V19.

V20 as built: also adds `directory_search_token` (HMAC prefix tokens for users/groups). External IDs are stored as
`external_id_enc` + `external_id_index` (blind index) so uniqueness never needs plaintext; PII columns carry a
`LIKE 'enc:t1:%'` check. `TenantSchemaCompatibility` now requires tenant V20.

V21 as built: claim `priority` is a generated column from `priority_class`, and source kind/class pairs are
checked in SQL. `ownership_assignment.status` adds `NONE` (claims exist, none eligible) so the row and its ID
survive for exception snapshots while readers fall through to the parent. The effective view is
`security_invoker` (requires PostgreSQL 15+; Render default is 16). Single writers: `OwnershipSubjectService`
(subjects/edges; rejects cycles and > 6 hops at write time), `OwnershipClaimService` (claims, idempotent per
observation, supersedes per source reference), `OwnershipResolutionService` (assignments), `OwnershipReviewService`
(review items), `OwnershipEvents` (append-only, trigger-enforced). `ownership_effective_cache` has no writer.
V21 also adds `ownership_resolution_queue`: team archive/restore enqueues affected subjects in one set-based insert,
and `OwnershipMaintenanceJob` (every minute, per tenant, bounded batches in separate transactions) expires claims and
drains the queue.

V22 as built: adds `(tenant_id, id)` candidate keys on `assets`/`findings`; `assets.ownership_subject_id`,
`findings.ownership_subject_id`, `findings.assignee_principal_id` (FK to `platform.app_users`; tenant membership is
checked by the writer, because a tenant-inclusive FK to memberships would block membership removal); the four §7.3
snapshot columns on `finding_suppression_requests`; and `owner_team_id`/`ownership_assignment_id` on `finding_events`
for direct suppression, false-positive and accepted-risk decisions. Nothing populates or reads these yet.

Namespace uniqueness for `team.name_key` + `team_alias.alias_key` is enforced by one transactional
`TeamNamespaceService` taking a tenant-scoped `pg_advisory_xact_lock`; table unique indexes are a backstop only.

## 2. Tenant encryption and KMS (prerequisite 2)

Current state: `CredentialEncryptionService` is single-key AES-256-GCM with `enc:v1:` prefix, key id and previous
keys from config; `ProviderCredentialMigrator` re-encrypts stored provider credentials. There is no tenant key
hierarchy and no KMS client.

Design:

```text
TenantDataCipher (new interface)
  encrypt(tenantId, purpose, plaintext) -> "enc:t1:<tenantKeyVer>:<base64(iv||ct)>"
  decrypt(tenantId, purpose, ciphertext)
  blindIndex(tenantId, purpose, normalizedValue) -> byte[] (HMAC-SHA256)
KeyWrapper (interface)       : wrap/unwrap(dek, encryptionContext{tenantId,purpose,keyVersion})
  AwsKmsKeyWrapper           : production; encryption context bound to tenant+purpose
  LocalKeyWrapper            : local/test only; refuses to start with APP_ENVIRONMENT != local/test
TenantKeyRegistry            : platform.tenant_data_keys, caffeine cache (bounded TTL), versioned rotation
```

- Per-tenant DEKs wrapped by KMS; AAD = `tenantId|purpose|keyVersion`; plaintext DEK cached in memory only, bounded TTL.
- Prefix is `enc:t1:` because `CredentialEncryptionService` already writes `enc:v2:<keyId>:` with platform keys.
  Wrap context is `{tenantId, purpose=tenant-data-key, keyVersion}`; field AAD is `tenantId|purpose|keyVersion`.
- Blind-index key is derived from tenant key **version 1** so indexes survive DEK rotation; destroying v1 or
  rotating the index key needs a reindex job (not in Release 1).
- `enc:v1:` ciphertext stays readable through `CredentialEncryptionService`; `ProviderCredentialMigrator` gains a
  re-envelope pass (v1 → v2) driven by `ProviderCredentialMigrationTool`, resumable, never logging plaintext.
- Gate: identity-source enablement and any PII write call `TenantDataCipher.readiness(tenantId)`; failure blocks with a
  typed error (§6.1 step 2). Outage behaviour: reads of already-cached keys continue until TTL, writes fail closed.
- Blind indexes (HMAC, tenant-derived index key) replace plaintext indexes for exact email/employee-id lookup;
  prefix search uses bounded n-gram tokens of the normalized display name under the same HMAC key (limit set by the
  100k/300k plan check below).

**OPEN (blocking):** deployed Render→KMS spike (auth, wrap/unwrap latency, rotation, outage, redacted logging).
Until it passes, no production PII write and no new connector-secret write; Release-1 code ships behind the
readiness gate with `LocalKeyWrapper` in local/test only.

## 3. Identity canonical key and search (prerequisite 3)

- Canonical identity key: `(tenant_id, source_id, external_id)`; email is a *link hint*, never a merge key.
- Ambiguity (same email across sources, mutable-identifier collision) → `ownership_review_item(AMBIGUOUS_IDENTITY)`;
  no automatic merge.
- Search: exact via blind index; prefix via token index. **OPEN:** 100k/300k-user query-plan evidence.
- As built (`DirectoryService`, `DirectoryImportService`): display names are tokenised per word (accents folded,
  prefixes of 2–12 characters, HMAC under purpose `directory.search`); a query matches when every word prefixes a
  name word. Group names are not PII and use a plain `name_key` prefix match. Every directory write checks tenant-key
  readiness and returns 503 when it fails. CSV preview records a `VALIDATED` run; commit needs the same SHA-256, tenant
  and importer within 30 minutes and applies rows one transaction each. Email collisions become `AMBIGUOUS_IDENTITY`
  review items keyed by a blind index, never merged. Not yet built: REST endpoints, persisted row-error downloads,
  background (durable) commit, compensating deactivation, and a product path that provisions tenant keys.

## 4. Authorization matrix (prerequisite 4)

Existing tenant roles (`TenantRolePolicy`): `TENANT_ADMIN`, `INVENTORY_ADMIN`, `SECURITY_ANALYST`,
`READ_ONLY_AUDITOR`; plus `SERVICE_ACCOUNT` (registry-bound). The plan's "read-only tenant role" maps to
`READ_ONLY_AUDITOR`. The matrix in plan §5 is adopted verbatim and implemented as a single
`OwnershipAuthorization` component; every controller method is annotated and covered by a parameterized
authorization integration test (role × endpoint). Wrong-tenant IDs return 404.

Analyst manual assignment: server-derived scope check (finding assigned to caller, or CVE the caller leads — CVE
leg arrives in Release 3), reason mandatory, expiry ≤ 30 days, impact preview ≤ 100 descendants / 1,000 findings,
alert event `OWNERSHIP_ANALYST_ASSIGNMENT` written in the same transaction as the claim.

## 5. Resolver, inheritance, TTL (prerequisite 5)

Implements plan §6.9 exactly. Contract points fixed here:

- Priorities (lower wins): 1 manual, 2 ServiceNow, 3 cloud account/project, 4 AI Grid, 5 cloud tag/label, 6 Entra/Okta.
- Direct specificity beats any inherited result; ≤ 6 parent hops; cycle/missing/overflow → `CONFLICT` + review item.
- Resolver is a pure function `OwnershipResolver.resolve(directClaims, now) -> DirectResult` with a `RESOLVER_VERSION`
  constant; inheritance is applied only by the `ownership_effective_assignment` view, never in Java;
  `OwnershipResolutionService` is the only writer of `ownership_assignment`; unchanged inputs ⇒ zero writes.
- Default source TTL/staleness: claims carry `observed_at`; a source claim becomes stale after **2× sync interval**
  and ineligible after **7 days** without re-observation (tenant-lowerable). Anomaly pause: a producer batch that would
  change > **20 %** of its claims (min 50) pauses and raises a review item. **OPEN:** product confirmation of thresholds.

## 6. ServiceNow CMDB contract (prerequisite 6)

Initial fields per plan §6.4 (`support_group`, approved owner-team/department field, approved person field);
watermark `sys_updated_on` + `sys_id` tie-breaker; minimum table permissions read-only on `cmdb_ci*`, `sys_user*`.
Existing `ServiceNowCmdbConfigService` is the configuration home; the claim producer is new and must not reuse the
platform feed credentials (CLAUDE.md boundary). **OPEN:** representative CMDB sample and permission list from the
ServiceNow admin.

## 7. Effective-owner join benchmark (prerequisite 7)

Harness (to be built in Release 1 week 1, under `backend/scripts/perf/ownership/`): seeds 1M/3M findings and
5M/15M occurrence topology into a disposable Postgres, then records `EXPLAIN (ANALYZE, BUFFERS)` and p95 for:
owner-team filter, status filter, ownership coverage count, single-subject explanation. Decision rule: if p95
misses plan §13 budgets, enable `ownership_effective_cache` (schema ships in V21 but is unused until then).
**OPEN:** results.

Local smoke run (2026-11-08, PostgreSQL 16.15 on a developer Mac, 100k findings / 500k occurrences = one tenth of
expected size, 10 samples, findings occurrence-scoped 3 hops below the owning application):

| Query | p50 | p95 | Budget | Result |
|---|---:|---:|---:|---|
| Q1 owner-team filter, first page | 382 ms | 1,774 ms | 750 ms | MISS |
| Q2 status filter, first page | 305 ms | 325 ms | 750 ms | pass |
| Q3 coverage count, all open findings | 2,726 ms | 6,990 ms | 1,000 ms | MISS |
| Q4 single-subject explanation | 0.9 ms | 1.3 ms | 250 ms | pass |

Re-run with the cache (2026-11-08, same machine and size, 10 samples; `results/20261108T233444-100000f-500000o.txt`):

| Query | p50 | p95 | Budget | Result |
|---|---:|---:|---:|---|
| Q1 owner-team filter, live walk | 326 ms | 1,469 ms | 750 ms | MISS |
| Q1c owner-team filter, cache | 17 ms | 20 ms | 750 ms | pass |
| Q3 coverage count, live walk | 1,335 ms | 1,390 ms | 1,000 ms | MISS |
| Q3c coverage count, cache | 53 ms | 63 ms | 1,000 ms | pass |
| Q5 one invalidation page (`path @> app`) | 0.4 ms | 0.9 ms | — | — |
| Q4 single-subject explanation, live | 0.7 ms | 1.2 ms | 250 ms | pass |

Q5 covers only a few hundred rows per application in this topology; a subtree of 10⁵–10⁶ rows still needs measuring at
expected size.

Decision under the rule above: the live LATERAL walk is adequate for single-subject reads, explanations and
correctness-sensitive writes, but owner-team filtering and coverage aggregation need `ownership_effective_cache`
(or an equivalent projection) before the inventory/findings read waves are enabled at expected size.

Cache as built (V21 amended before first merge; no shared database had V20–V22 applied):

- `ownership_effective_cache` stores per subject only stable IDs (status, team, origin subject, assignment and its
  version), depth and `inheritance_path` — the subjects the walk visited, the subject first. A GIN index on the path
  replaces the planned per-subtree version counters: a change at subject R affects exactly the rows whose path
  contains R (R's assignment changed, a node between a row and its origin gained a claim, or R was re-parented).
- `ownership_cache_invalidation` is the change queue. `OwnershipResolutionService` (material assignment change) and
  `OwnershipSubjectService` (registration, `setParent`, `clearParent`) only enqueue; `OwnershipEffectiveCacheService`
  is the single writer of both tables. Changes are recorded even while the cache is off, so enabling it starts from a
  complete backlog; an hourly reconciliation queues active subjects with no row.
- The maintenance job (when `app.ownership.effective-cache.enabled`) expands queued subjects into invalidations
  (`path @> ARRAY[R]`, only rows refreshed before R was queued, ≤ 10,000 rows per transaction; a re-queue during
  expansion is kept) and refreshes invalidated rows from `ownership_effective_for`. A parent change never rewrites
  descendants in one transaction and never writes `ownership_assignment` rows for descendants.
- Readers: `OwnershipReadAdapter.filter` and `coverage` use the cache when enabled; coverage adds `refreshing`
  (linked rows whose row is missing or invalidated). Detail reads, explanations, impact previews, ticket routing and
  owner snapshots stay on the live walk. Team names are joined at read time, so a rename touches no cache row.
- Cutover: with the cache enabled, qualification adds the gate `effectiveCacheBacklog` = queued + invalidated +
  missing rows, which must be 0 before DARK→CANONICAL.
- Default off (`APP_OWNERSHIP_EFFECTIVE_CACHE_ENABLED`). It must be on before the inventory/findings read waves are
  enabled at expected size; the benchmark harness now measures Q1c/Q3c (cache variants) and Q5 (one invalidation page). Expected and
qualification-size runs (1M/5M and 3M/15M) on representative hardware remain OPEN. The first smoke attempts also
exposed missing predicate-shaped indexes on the walk (`ownership_subject_edge (child_subject_id)`,
`ownership_assignment (subject_id)`); without them each step sequentially scanned the edge table.

## 8. Authority switch, read flags, compatibility adapter (prerequisite 8)

- `platform.ownership_domain_authority(tenant_id, domain, state)`; domains `CORE`, `CLOUD_BOM`, `AI_GRID`.
- `OwnershipAuthorityService.stateFor(tenant, subjectFamily)` is the only authority lookup; legacy and canonical
  writers both call it and fail closed on mismatch (service guard + DB check on writer-identity column).
- Per-consumer read flags (`inventory`, `findings`, `campaigns`, `tickets`, `ai`) as server-side config per tenant.
- `OwnershipReadAdapter` returns the §7.5 envelope (`authorityState`, `legacyOwnerLabel`); legacy rows are
  `LEGACY_PENDING_MIGRATION`, never `UNOWNED`.
- Recovery test plan: switch rehearsal on an internal canary tenant, 24 h gates, rollback only before step-5 go.

### 8.1 As built (Release 1 slices 6c–10)

- Endpoints: `/api/directory/**` (people, groups, members, CSV templates/preview/commit), `/api/ownership/teams/**`,
  `/review-items`, `/encryption` (+ `/provision`), `/subjects/{type}/{id}` (explanation, manual assignment preview,
  assign, revoke), `/assets`, `/findings`, `/assets/filter`, `/findings/filter`, `/coverage`,
  `/authority/{domain}` (+ `/qualification`). Every method is `@PreAuthorize("@ownershipAuthorization.can(...)")`.
- Directory reads return masked email/employee ID; unmasking is not offered yet.
- Manual assignment and revocation require the subject's domain to be CANONICAL (LEGACY and DARK return 409).
  Producers publish only in DARK or CANONICAL. Analyst scope = an open finding with `assignee_principal_id` = caller.
- ServiceNow producer runs after a successful CMDB sync when `app.ownership.servicenow.producer-enabled=true`, reads
  the synced `cis` rows (no second credential), re-observes unchanged claims (timestamps only, zero assignment
  writes), pauses with a `PRODUCER_ANOMALY` review item when > 20 % (min 50) of active claims would change or end,
  and ends absent CIs' claims only after a complete scan.
- Resolver watermark excludes timestamps; staleness is computed at read time from the winning-priority claims.
- Effective view is `ownership_subject ⋈ LATERAL ownership_effective_for(id)` so subject filters and joins walk only
  the needed chains (the earlier all-subjects recursive CTE could not be filtered by the planner).
- Read waves: `app.ownership.read-waves.inventory|findings` = `*` or tenant IDs. A row is CANONICAL only when the
  wave is on and the domain is CANONICAL; otherwise `LEGACY_PENDING_MIGRATION` with the legacy label.
- Cutover: LEGACY→DARK starts populate (maintenance job links assets/findings to subjects); qualification gates on
  zero unlinked assets/findings, empty queue, swept expiries, current resolver version, no inheritance errors and no
  open producer anomaly, and reports a legacy-vs-canonical comparison. DARK→CANONICAL requires the passing report's
  hash and records `accepted_by`; CANONICAL cannot be reverted by the API.
- Finding domains follow the finding kind, not the asset: `VULNERABILITY` is CORE (adapter v1, affected asset);
  `CRYPTO` is CLOUD_BOM (occurrence adapter, Release 2); `AI_POSTURE`/`AI_EXPOSURE` are AI_GRID (Release 3). The
  populate step and `subjectForFinding` link VULNERABILITY findings only, canonical finding filters/coverage count
  them only, and an AI or CRYPTO finding on a canonical asset still reads `LEGACY_PENDING_MIGRATION`.
- Findings compatibility adapter: `FindingQueryService` batch-reads the envelope for each already-paginated page (and
  the detail/history reads). For a canonical row, `FindingResponse.ownerGroup` is the live team name and the existing
  `ownership` map keys the UI reads (`displayName`, `ownerTeam`, `sourceSystem`, `supportGroup`) are filled from the
  effective assignment, plus `ownerTeamId`, `ownershipStatus`, `authorityState`, `assignmentId`, `stale` and
  `inheritanceDepth`. Nothing is written back. Legacy rows keep today's display plus
  `authorityState=LEGACY_PENDING_MIGRATION`. With the findings wave off, no ownership query runs.
- Asset domains follow the asset type: APPLICATION/HOST are CORE; CONTAINER_IMAGE/CLOUD_RESOURCE are CLOUD_BOM
  (Release 2). Inventory filters and coverage count CORE types only.
- Inventory compatibility read: `AssetResponse.ownership` and `HostAssetDetailResponse.ownership` carry the envelope
  beside the raw `ownerTeam`/`ownerEmail`/`supportGroup` evidence, which is never relabelled (plan §9.4). The
  unpaginated asset list uses one set-based `forAllAssets()` read (the cache when enabled); nothing is queried while
  inventory is not canonical. Host-detail findings report the live canonical team in `ownerGroup`. The inventory host
  list and host detail page show the resolved owner (Resolved ownership / Observed ownership evidence panels) when
  canonical and today's display otherwise; shared helpers live in `frontend/src/features/ownership/`.
- Ownership & Directory hub (`frontend/src/features/ownership/`, Configurations → Ownership, `?view=`): Overview
  (inventory and finding coverage; tenant-key readiness and provisioning; CORE cutover report with start-dark, no-go
  and report-hash-bound go), Teams (search, active/archived, create, rename, ticket group, archive/restore with
  confirmation, aliases), People (name-prefix search from 2 letters, masked contact fields, add, deactivate/reactivate),
  Groups (create, deactivate/reactivate, members with add/remove; names resolved for the first 25), Imports (template,
  dry run, commit bound to the preview token) and Review (open/resolved/dismissed, type filter, resolve/dismiss with
  note). Views and actions follow the §5 matrix for visibility only. Sources and group-to-team mappings are not shown
  until their endpoints exist (Releases 2–3).
- Legacy rule editor: kept as the hub's "Legacy rules — pending migration" view while inventory coverage reports
  `LEGACY_PENDING_MIGRATION` (user decision, 2026-11-09: keep until cutover, delete in the §15.5 cleanup; the shared
  suppression matcher is untouched).
- Not built: canary rehearsal and 24 h gates (operational), campaign and ticket consumers (Release 2), owner-team/status
  filter controls and the Findings page columns, unmask action, Playwright journey/visual/axe runs for the hub.

## 9. Staffing and acceptance owners (prerequisite 9)

**OPEN — human decision.** Needs named leads for ownership/platform, connectors, consumer UI, QA/SRE/security and
the release authority, plus provider-tenant access dates (ServiceNow, Entra, Okta, AWS, GCP).

## 10. Gate status

| # | Prerequisite | Status |
|---|---|---|
| 1 | Storage map, versions, RLS/grants/purge | Platform V11 + tenant V20–V22 implemented and IT-verified |
| 2 | KMS spike + cipher interface | Implemented (`security.tenantkey`, platform V11, local wrapper only); **spike OPEN** |
| 3 | Identity key + search | Manual + CSV directory implemented and IT-verified; **100k/300k plan OPEN** |
| 4 | Authorization matrix | `OwnershipAuthorization` implemented; every ownership endpoint guarded and role × endpoint IT-verified |
| 5 | Precedence/inheritance/TTL | Resolver, view, scheduled expiry sweep and re-resolution queue implemented (V21); thresholds **need product confirmation** |
| 6 | ServiceNow CMDB contract | `ServiceNowOwnershipProducer` implemented against the initial contract (support_group; department behind a flag) and IT-verified; **samples OPEN** |
| 7 | Effective-owner benchmark | Harness at `backend/scripts/perf/ownership/`; smoke run: filter/coverage miss → `ownership_effective_cache` implemented (§7) and IT-verified; **expected/qualification-size results OPEN** |
| 8 | Authority/read-flag/adapter plan | `OwnershipAuthorityService`, `OwnershipReadAdapter`, `OwnershipCutoverService` implemented and IT-verified (CORE only) |
| 9 | Leads, staffing, ROM | **OPEN** |

Implementation proceeds against these interfaces. Anything marked OPEN is enforced in code as a disabled-by-default
switch (publication, identity-source enablement, domain authority) so unfinished evidence cannot be bypassed at runtime.

## 11. Release 1 progress and handoff (updated 2026-11-09)

Start here in a new session. The plan is `docs/ownership-capability-mvp-plan.md`; this document records what is built.

### 11.1 Where the work is

- Git worktree `../SG-ownership-mvp` (relative to the main checkout `SG/`), branch `feat/ownership-mvp`.
- Committed: `764fe136` plan, `543e7620` Phase 0A design, `f9ea681e` Release 1 slice 1 (tenant data keys, platform
  V11), `7bd38452` slice 2 (identity and team tables, tenant V20, `TeamNamespaceService`).
- **Everything below is uncommitted** in that worktree: tenant V21 (ownership core, amended in place for the effective
  cache — no shared database has V20–V22 applied) and V22, all `service/ownership/*` beyond slice 2, the four
  ownership/directory controllers, the cache, the finding/asset compatibility reads, the inventory UI changes, the
  Ownership & Directory hub, the benchmark harness under `backend/scripts/perf/`, the e2e fixture/journey updates and
  this document's later sections.
- Frontend `node_modules` in the worktree were installed with `npm ci` (its lockfile differs from the main checkout).

### 11.2 Done in Release 1

| Area | Built | Verified by |
|---|---|---|
| Tenant encryption | `security.tenantkey` (cipher, blind index, local wrapper, registry), readiness gate on PII writes | `TenantDataCipherTest`, `TenantKeyRegistryPostgresIntegrationTest` |
| Identity and teams | V20 tables; one shared team/alias namespace under an advisory lock | `TeamNamespacePostgresIntegrationTest`, writer-control test |
| Directory | Manual people/groups/memberships, encrypted prefix search, CSV preview/commit (5 kinds) | `DirectoryPostgresIntegrationTest` |
| Ownership core | Subjects, ≤ 6-hop edges, claims, direct assignments, effective view, review items, events, expiry sweep, re-resolution queue | `OwnershipCorePostgresIntegrationTest`, `OwnershipResolverTest` |
| Manual assignment | Reason, expiry, analyst scope and limits, impact preview, revoke | `ManualAssignmentPostgresIntegrationTest` |
| ServiceNow producer | Claims from synced CMDB `support_group` after a successful sync, anomaly pause, complete-scan ending | `ServiceNowOwnershipProducerPostgresIntegrationTest` |
| Authorization | §5 matrix in `OwnershipAuthorization`; every endpoint guarded | `OwnershipAuthorizationPostgresIntegrationTest` (37 cases) |
| Cutover | Per-domain authority, populate, qualification report and hash-bound go (CORE only) | `OwnershipCutoverPostgresIntegrationTest` |
| Effective cache | §7 design: path-indexed invalidation queue, bounded refresh, hourly reconciliation, backlog gate on cutover; default off (`APP_OWNERSHIP_EFFECTIVE_CACHE_ENABLED`) | `OwnershipEffectiveCachePostgresIntegrationTest`; benchmark at 1/10 size (§7) |
| Domain rules | Findings by kind (VULNERABILITY → CORE, CRYPTO → CLOUD_BOM, AI_* → AI_GRID); assets by type (APPLICATION/HOST → CORE, others → CLOUD_BOM) | cutover and compatibility ITs |
| Finding reads | `FindingQueryService` fills `ownerGroup` and the `ownership` map from canonical rows; no query while the findings wave is off | `FindingOwnershipCompatibilityPostgresIntegrationTest`, `FindingQueryServiceTest` |
| Inventory reads | `AssetResponse.ownership` and `HostAssetDetailResponse.ownership` beside raw evidence; one set-based list read; host-detail findings use live team names | `AssetOwnershipCompatibilityPostgresIntegrationTest` |
| Inventory UI | Host list owner column/search/missing-owner count and host-detail Resolved ownership / Observed evidence panels | `InventoryPage.test`, `HostAssetDetailPage.test`, `resolvedOwnership.test` |
| Ownership & Directory hub | Overview, Teams, People, Groups, Imports, Review, Legacy rules (§8.1) | `OwnershipDirectoryHub.test` (9), `ConfigurationsPage.test` |

Last full runs (2026-11-08/09): backend `mvn -q verify` — 1,664 unit tests, 0 failures, JaCoCo and SpotBugs pass;
ownership Postgres ITs all pass; frontend lint (0 errors), typecheck, build and `test:coverage` (113 files, 1,167
tests) pass; e2e runner unit tests pass.

### 11.3 Not verified yet

- Playwright journeys, visual baselines and axe checks for the hub and inventory changes (Docker was unavailable).
  The connect fixtures and journey were updated but not run.
- No run against a live backend session and no screenshots (required by `CLAUDE.md` for UI changes).
- The full Postgres IT suite outside the ownership classes has not been run after the `FindingQueryService`,
  `AssetQueryService` and `HostInventoryReadService` changes (`CustomerDemoDatasetPostgresIntegrationTest` was run).

### 11.4 Next steps, in order

1. **Commit the worktree in reviewable pieces** after one full `mvn -Ppostgres-it verify`: schema and core (V21/V22,
   subject/claim/resolution/review services), directory and CSV, ServiceNow producer, authorization and controllers,
   cutover, effective cache, finding/asset compatibility reads, inventory UI, Ownership & Directory hub, benchmark
   harness and docs. Follow `CLAUDE.md` commit conventions; branch is already `feat/ownership-mvp`.
2. **Browser and live verification**: `npm run e2e:build`, then the connect, experience and inventory journeys plus
   visual/affected-route/axe checks in the pinned Playwright image; a live session with a disposable tenant to check
   persistence after reload; screenshots at 390 px and 1280 px in both themes.
3. **Findings page** (last Release 1 code item): Owner Team and Ownership Status columns and an owner-team/status filter
   using `/api/ownership/findings/filter` and `features/ownership/resolvedOwnership.ts`; legacy rows keep today's
   display and a Pending Migration marker (plan §9.7).
4. **Resolve the TTL/anomaly divergence**: §5 of this document and the code use stale after 2 × interval, ineligible
   after 7 days, and an anomaly pause at > 20 % (min 50) of claims; plan §12.1/§12.3 specify stale after
   max(2 × interval, 24 h), expiry after max(3 × interval, 72 h) capped at 30 days, and a pause at ≥ 100 changes and
   ≥ 10 %, or ≥ 10,000 changes. Align one to the other with product sign-off.
5. **Open Phase 0A evidence** (§10): deployed Render→KMS spike (infrastructure); benchmark at 1M/5M and 3M/15M on
   representative hardware, including a 10⁵–10⁶-row invalidation subtree; 100k/300k-user search query plans; a real
   ServiceNow CMDB sample and permission list; named leads and release authority (§9).
6. **Canary rehearsal** on an internal tenant: LEGACY → DARK → qualify → CANONICAL with the 24 h gates and consumer
   rollback, after steps 1, 2 and the KMS spike.
7. **Release 2** (plan §16.5) starts after Release 1 exit: ServiceNow directory sync, AWS/GCP producers, BOM/CBOM
   occurrence adapters (vulnerability adapter v2), campaign materialization and ticket routing — and with them the
   hub's Sources and group-to-team Mappings views.

### 11.5 Working notes

- Backend: `export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home` and
  `APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED=false` for Postgres ITs; local Postgres is at `/tmp:5432`; IT databases are
  dropped and recreated per class.
- Ownership ITs: `mvn -Ppostgres-it verify -Dtest=NoSuchTest -Dsurefire.failIfNoSpecifiedTests=false
  -Dit.test='Ownership*PostgresIntegrationTest,*OwnershipCompatibility*PostgresIntegrationTest,TeamNamespacePostgresIntegrationTest,Directory*PostgresIntegrationTest,ManualAssignment*PostgresIntegrationTest,ServiceNowOwnership*PostgresIntegrationTest,TenantKeyRegistryPostgresIntegrationTest'`.
- Benchmark: `PGHOST=/tmp BENCH_DB=ownership_bench_<name> backend/scripts/perf/ownership/run_benchmark.sh <findings> <occurrences> <runs>`
  (creates and drops a disposable database; results under `results/`).
- Read waves are off by default (`app.ownership.read-waves.inventory|findings`); with them off, no ownership query runs
  on finding or asset reads.
