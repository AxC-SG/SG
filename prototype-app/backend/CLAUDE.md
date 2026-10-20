# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> The root `../CLAUDE.md` contains full project conventions, architecture, scheduling, and the never-touch list. This file adds backend-specific runtime detail.

## Commands

```bash
# Run the API server (port 8080, default profile)
mvn spring-boot:run

# Run with local profile (enables header-based tenant selection, JWT auth, no prod-secret check)
mvn spring-boot:run -Dspring-boot.run.profiles=local

# Unit tests only (Surefire; excludes *PostgresIntegrationTest.java)
mvn test

# Unit + Postgres integration tests (Failsafe; requires local Postgres)
mvn -Ppostgres-it verify

# Run a single test class
mvn test -Dtest=MyServiceTest

# Run a single Postgres IT class
mvn -Ppostgres-it verify -Dit.test=MyServicePostgresIntegrationTest

# Remove old packaged migration resources before bootstrapping a fresh development DB
mvn clean
```

## Authentication and request auth model

Every `/api/**` request goes through `ApiKeyAuthenticationFilter` (runs before `UsernamePasswordAuthenticationFilter`) before reaching a controller. Two auth paths:

**API key auth** (`X-API-Key` header, enabled when `app.security.allow-api-key-auth=true`):
- Grants `ROLE_OPERATOR`, `ROLE_SECURITY_ANALYST` to all callers.
- `X-Creator-Key` (or an unconfigured creator key) additionally grants `ROLE_CREATOR`, `ROLE_PLATFORM_OWNER`, `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN`.
- `X-User-ID` header sets the user identity; defaults to `APP_DEFAULT_USER_ID` (`local-analyst`).
- Defaults: `APP_API_KEY` is empty, so API-key requests are rejected ("API key is not configured") until it is set; with no creator key configured, every valid API-key caller gets creator-level access. `change-me-in-prod` is only the frontend dev-mode fallback.

**JWT Bearer auth** (`Authorization: Bearer <token>`):
- `APP_JWT_AUTH_MODE` selects `LOCAL` or `EXTERNAL`. `LOCAL` requires a 32-byte HMAC secret and local issuer, without external issuer/JWK settings. `EXTERNAL` requires an issuer URI and no local HMAC secret; a JWK URI is optional. Ambiguous combinations fail startup. See `JwtDecoderConfig` and `RuntimeConfigurationValidator`.
- Both modes validate issuer, audience and `token_use=access`. Local login/token issuance is available only in `LOCAL` mode.
- Decoded JWT is passed to `JwtTenantAuthenticationService.authenticate()`, which: resolves or creates the `platform.app_users` record, extracts roles from `APP_JWT_ROLES_CLAIM` (default `roles`), also handles namespaced claims ending in `/roles`, sets `TenantContext` from JWT tenant claims.
- The resulting `AuthenticatedTenantActor` is stored as a `TenantAuthenticationDetails` on the `SecurityContext`.

**Authorization rules** (from `SecurityConfig`):
- `/api/platform/**` and `/api/operations/**` → `ROLE_PLATFORM_OWNER` required
- `/api/operations/quality/**` and `GET /api/operations/software-identities/search` → also permit `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN`, `ROLE_SECURITY_ANALYST`, `ROLE_READ_ONLY_AUDITOR`
- All other `/api/**` → authenticated
- `/api/fix-intelligence/**` → `permitAll()` unconditionally — a carve-out added with the Fix Intelligence MVP (`FixIntelligenceController`), not gated by profile/env. This is a real hole against the pattern above, not a documented exception; see root `CLAUDE.md` Known Limitations before adding real data behind it.
- `/actuator/**` beyond health/info → authenticated (not public)
- Public: OPTIONS, `/actuator/health` (+ `/health/readiness`, `/health/liveness`), `/actuator/info`, `POST /api/auth/login`, `POST /api/auth/setup-password`, `POST /api/auth/setup-session`, `POST /api/demo-requests`, `/api/demo-invites/**`, `/api/tenant-invites/**`
- `GET /api/auth/context` and `GET /api/me` → authenticated (no longer `permitAll()`), but still CSRF-ignored as read-only endpoints
- `POST /api/internal/ai-grid/evidence/{producerId}` requires `ROLE_SERVICE_ACCOUNT` and that the authenticated principal equals `producerId` — used by trusted external evidence producers (CIEM/DSPM/ASM/runtime tools) feeding the AI Grid pipeline

## Multi-tenancy

`TenantAwareDataSource` wraps every connection from the HikariCP pool and runs:
```sql
SELECT set_config('app.current_tenant_id', '<uuid>', FALSE);
SELECT set_config('search_path', '<tenant_schema>,platform', FALSE);
```
On connection close it resets both. This means all JPA queries automatically hit the correct schema without any application-layer schema prefix on queries.

`TenantContext` (thread-local) carries the current tenant UUID and schema name. `ApiKeyAuthenticationFilter` calls `TenantContext.clear()` in a `finally` block. JWT auth sets `TenantContext.setCurrentTenantId(actor.tenantId())` inside the filter.

`APP_ALLOW_HEADER_TENANT_SELECTION=true` (local profile default) lets clients override the tenant via `X-Tenant-ID` header. Must be disabled in production.

### Tenant context must be set BEFORE the transaction begins (critical invariant)

`TenantAwareDataSource` pins a connection's `search_path` (and `app.current_tenant_id`) **at the moment the connection is acquired**, from whatever `TenantContext` holds then — it does not re-read on later queries. A Spring transaction binds its connection at the start of the transaction. Therefore the tenant must be selected *before* the transaction opens.

This is fine for HTTP-invoked code: the auth filter sets `TenantContext` before any `@Transactional` controller/service method runs, so the bound connection already points at the right schema.

It is a trap for **background code** (scheduled jobs, async workers, `@PostConstruct`). A method shaped like this:

```java
@Transactional                                   // transaction (and connection) bound FIRST...
public X doWork(Tenant tenant) {
    return tenantSchemaExecutionService.run(tenant, () -> { ... });  // ...context switched too LATE
}
```

silently runs against `tenant_default` for **every** tenant when called from a thread with no pre-set context — the `search_path` was pinned (to the default schema) before `run()` switched `TenantContext`. No error; it just queries the wrong schema. This caused the async ingestion worker and the finding-delta drain to process only the default tenant.

Correct pattern — context first, transaction inside:

```java
public X doWork(Tenant tenant) {                 // no method-level @Transactional
    return tenantSchemaExecutionService.run(tenant, () ->
        transactionTemplate.execute(status -> { ... }));   // tx opens with context already set
}
```

Equivalently, wrap the call at the background call site in `tenantSchemaExecutionService.run(tenant, () -> service.theTransactionalMethod(...))`. Audit any `@Transactional` method that calls `tenantSchemaExecutionService.run(...)` internally and is reachable from a scheduled/async path.

A scheduled poller/drain over a **per-tenant** table (`ingestion_jobs`, `finding_delta_queue`, etc.) must iterate `tenantService.listTenants()` and run each tenant's claim+process inside `run(tenant, …)` — the scheduler thread carries no context, so a bare drain only ever touches `tenant_default`.

### AI Grid reporting boundaries

`GET /api/ai-frameworks` reads global platform reference data and deliberately does not resolve a tenant, so a platform owner can use framework labels and filters before entering a workspace. `GET /api/ai-framework-coverage` and `/api/ai-assessment-states/latest` are tenant-bound and must route through `AiGridController.tenant()`.

The customer-facing assessment vocabulary is derived centrally by `AiGridFindingService.AssessmentResult.deriveAssessmentState`: `PASS`/`FAIL` remain direct; `OUT_OF_SCOPE`, `CAPABILITY_UNAVAILABLE`, and `NOT_APPLICABLE` become `NOT_ASSESSED`; evidence collection errors and incomplete/stale evidence become `UNKNOWN`. `AiGridApiService.latestAssessmentStates()` applies that same derivation to each policy version's latest run and returns per-state totals—do not duplicate the mapping in SQL or another controller.

`AiGridManifestApprovalService` remains the tenant control plane for approved manifests and component allowlists. Manifest approval requires an agent/version relationship and active listed components.

### Runtime telemetry deferred

Runtime event/log collection, execution evaluation, curated activity summaries, readiness reporting, and findings are outside the current release. `AiRuntimeScope` hard-blocks runtime admission/read paths even when a flag is enabled. The scheduled adapter worker never claims work, static scans skip the runtime evaluator, and Copilot permission checks never query transcripts. Startup rejects an enabled runtime flag in every environment. Fresh tenant V1 starts without runtime history and the retention scheduler is disabled; the standalone runtime-exclusion doc was archived outside the repo under `Other Docs/Archive/`; see `../docs/business-logic-guide.md#ai-security--ai-grid-pipeline`.


## Database migrations

There are **two independent Flyway migration lines**, each restarted at a fresh `V1` baseline by a one-time migration-history reset — do not mix them up:

- **Platform/public:** `src/main/resources/db/migration/postgres_reset/V1__platform_schema.sql` owns public/platform DDL, migration-owned reference seeds, and the empty `tenant_default` schema. Every file starts with `-- migration-guard: platform-only`. No AGCF-RT distributions are seeded; any catalog distributions with runtime evaluation modes are unavailable, DISABLED, PAUSED, and unpinned.
- **Tenant:** `src/main/resources/db/migration/tenant/V1__tenant_schema.sql` owns the complete tenant DDL, RLS, constraints, and budget seed. Each tenant has its own `tenant_schema_history`, applied by the tenant control plane or `ProductionBootstrapCli`; application startup Flyway does not apply this line. The baseline uses `${tenantSchema}` and `${tenantId}` and starts without customer/runtime data.
- Current packaged targets are platform **V5** and tenant **V5**, independently resolved by `PackagedMigrationCatalog`. The next platform migration is V6 and the next tenant migration is V6; each must update `MigrationCatalogTest`. This binary requires tenant V5, including bounded retention progress; a configured lower minimum cannot bypass that floor. Additive-schema rollback compatibility still requires qualification before release.
- This explicitly authorized development reset includes all changes from the former platform V1–V10 and tenant V1–V17 histories. Use a fresh database and `mvn clean` to remove stale packaged migration resources. Baselines are not idempotent repair scripts: do not replay them against existing tables or use `flyway:repair` to adopt the reset. `baseline-on-migrate` stays false.
- Outside this one-time reset, never edit an already-applied migration; add the next version instead.

## Key env vars for local dev

Set in `application-local.yml` or as env vars:

| Env var | Purpose | Local default |
|---|---|---|
| `DB_URL` | JDBC URL | `jdbc:postgresql://localhost:5432/vulnwatch` |
| `APP_JWT_AUTH_MODE` | Explicit `LOCAL` or `EXTERNAL` contract | `LOCAL` |
| `APP_JWT_LOCAL_ISSUER` | Issuer for locally issued access tokens | `urn:scoutgrid:local` |
| `APP_JWT_HMAC_SECRET` | Local signing/verification secret, at least 32 bytes | (empty; must be configured for local tokens) |
| `APP_JWT_ISSUER_URI` | Required issuer for `EXTERNAL` mode | (empty) |
| `APP_SECURITY_JWT_AUDIENCE` | Required expected access-token audience | `scoutgrid-api` |
| `APP_JWT_ROLES_CLAIM` | Claim name for roles in JWT | `roles` |
| `APP_ALLOW_HEADER_TENANT_SELECTION` | Trust `X-Tenant-ID` header | `false` (local: `true`) |
| `APP_REQUIRE_TENANT_CONTEXT` | Enforce tenant context on every request | `true` (local: `false`) |
| `APP_ALLOW_API_KEY_AUTH` | Enable X-API-Key auth path | `true` |
| `OPENAI_API_KEY` | OpenAI key for AI-assist features | (empty = AI features off) |
| `NVD_API_KEY` | NVD rate-limited API key | (empty = unauthenticated) |
| `GITHUB_API_TOKEN` | GitHub token for SBOM/GHSA | resolved from `backend/secrets/github-api-token` |

`OPENAI_API_KEY`/`OPENAI_ENABLED` gate VulnWatch's own AI-assist features (EOL slug suggestion, CVE investigation summaries) — unrelated to the AI Security / AI Grid module, which discovers *other systems'* AI resources and is gated per-tenant by the `ai.security` entitlement, not an env var.

AWS AI discovery uses one bounded provider-call ceiling (`APP_AI_SECURITY_PROVIDER_CALL_CEILING`) plus connector enablement, provider kill switch, retries, semaphores, and scan budgets. The former per-layer AWS maturity flags were removed; Macie remains separately opt-in because it is cost-sensitive. A real `APP_AI_SECURITY_IDENTITY_HMAC_KEY` remains required in production because prompt evidence is stored only as tenant-keyed digests.

## Postgres integration test scaffolding

Tests whose file name ends with `PostgresIntegrationTest.java` are excluded by Surefire and picked up by Failsafe under `-Ppostgres-it`. They require a local Postgres instance.

Use the composed annotations and helpers from `src/test/java/com/prototype/vulnwatch/support/`:

| Class | Purpose |
|---|---|
| `@PostgresIntegrationTest` | Service/repo-layer IT (no MockMvc) |
| `@PostgresControllerIntegrationTest` | Controller IT with MockMvc auto-configured |
| `LocalPostgresTestDatabase.provision("unique_key")` | Creates `vulnwatch_it_<key>` DB; idempotent |
| `PostgresITSupport.registerDatabaseProperties(registry, db)` | Wires dynamic Postgres props |
| `AuthRequest.authedGet/Post/Put/Delete` | Adds `X-API-Key` header automatically |
| `AuthRequest.asPlatformOwner(request)` | Adds creator key (grants PLATFORM_OWNER) |

Minimal controller IT skeleton — see `src/test/java/com/prototype/vulnwatch/support/README.md` for the full template.

Do not add `@Transactional` to controller ITs. Mock outbound HTTP with `MockRestServiceServer`.

## Package layout

```
com.prototype.vulnwatch/
  config/      # Spring beans: SecurityConfig, ApiKeyAuthenticationFilter,
               # JwtDecoderConfig, TenantAwareDataSource, ProductionSafetyValidator,
               # TenantResolutionFilter, WebConfig, TenantSchemaReadinessHealthIndicator,
               # TenantSchemaMigratorRunner (21 files)
  controller/  # 48 REST controllers under /api/**, incl. FixIntelligenceController
  service/     # 280 business-logic services, incl. subpackages cbom/, cmdbingestion/,
               # sbomingestion/, vulningestion/ (feed sync + the @Scheduled entry points)
  domain/      # 153 JPA entities
  dto/         # 283 API request/response objects, incl. dto/patch/ (unwired scaffolding)
  repo/        # 97 Spring Data JPA repositories
  client/      # 25 external API client files, incl. client/http/ (NVD, EUVD, JVN, GHSA, CSAF, EPSS, GitHub, ServiceNow, AWS, Azure…)
  security/    # SensitiveTenantAction annotation + interceptor, PasswordSetupCookieService,
               # PublicEndpointRateLimiter (5 files)
  util/        # CPE handling, version comparison, SBOM parsing (6 files)
  migration/   # Standalone (non-Spring) production bootstrap: ProductionBootstrapCli,
               # PlatformOwnerSetupLinkIssuer, TenantSchemaMigrationCli, TenantSchemaFingerprint,
               # PackagedMigrationCatalog, TenantSearchPathFlywayCallback (6 files)
  web/         # PlatformAdminRequestPaths — request-path classifier; no call site found
               # outside its own unit test as of this writing, verify before relying on it
  tools/       # LegacyGithubSyncRunBackfillTool — standalone main() CLI

com.prototype.vulnwatch.aisecurity/   # separate top-level package, NOT under the tree above
  controller/  # 19 REST controllers — AI Security / AI Grid (posture management for AI/ML
               # resources discovered in AWS Bedrock / Azure AI Foundry)
  service/     # 71 services — snapshot/facts/ownership/systems/policy-assessment/exposure-
               # correlation pipeline + platform governance (answer-key, release certification,
               # policy rollout/deprecation)
  model/, policy/, aws/, azure/, copilot/  # contracts, predicate engine, AWS/Azure/Copilot Studio discovery clients
```

`aisecurity/**` tables have **no JPA entity or Spring Data repository** — every read/write goes through `JdbcTemplate`/`NamedParameterJdbcTemplate` directly in the service classes. Full module map: `docs/business-logic-guide.md#ai-security--ai-grid-pipeline`, schema: `docs/database.md#ai-security--ai-grid-tables`.

`FixIntelligenceController` (`/api/fix-intelligence/**`, `permitAll()`) is entirely demo-data-backed — it calls `FixDemoDataSeeder.generateDemoFixes()` on every request and touches no repository. The domain entities added alongside it for a real implementation (`Fix`, `FixApplicabilityDecision`, `AssetFixStatus`, `CveFixMap`, plus the unrelated `PatchConnectorCredential`/`JiraIssueBacklog` patch-management entities) have JPA mappings and repositories but **no backing Flyway migration** for `asset_fix_status`, `cve_fix_map`, `patch_connector_credentials`, or `jira_issue_backlog` in either migration line — do not wire a service to these repos without adding the migration first. `FixApplicabilityService` and `dto/patch/*` are similarly unwired (no caller). See root `CLAUDE.md` Known Limitations for the full list, including the `.disabled` patch-management config/scheduling classes excluded from the build.

Newer, less-obvious controllers worth knowing about: `CampaignController` (`/api/campaigns` — remediation campaigns), `CbomController` (`/api/bom/cbom` — cloud BOM posture), `BomController` (`/api/bom`), `AzureDiscoveryController` (`/api/connectors/azure-discovery`), `IngestionJobController` (`/api/ingestion-jobs`), `TenantSchemaStatusController` (`/api/platform/tenant-schema-status` — per-tenant schema migration status), `DemoDatasetController` (`POST /api/platform/tenants/{tenantId}/demo-data`, `PLATFORM_OWNER` — manual demo dataset provisioning), `TenantSupportAccessController` (`/api/tenants/{tenantId}/support-grants` + `/api/auth/support-grants/**` — tenant-initiated break-glass support access, distinct from the platform-owner-initiated `tenant_support_grants` flow).

## Docker build

```bash
docker build -t vulnwatch-backend .
docker run -e DB_URL=... -e APP_JWT_ISSUER_URI=... -p 8080:8080 vulnwatch-backend
```

JVM flags in the image: `-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError`.

## Production bootstrap (Render)

The permanent `scout-backend` web service (`render.yaml`, repo root) never runs schema migrations itself (`APP_SCHEMA_MIGRATION_ENABLED=false`) and is only ever given the restricted `scout_runtime` Postgres role — never the owner/migration role. Schema bootstrap (platform + tenant migrations, runtime-role provisioning, control-plane verification, optional platform-owner setup-link email) runs from a **separate, temporary** Render web service via `backend/scripts/run-render-migration.sh`, which execs `com.prototype.vulnwatch.migration.ProductionBootstrapCli` (a standalone `main()`, no Spring context) and then holds the container open in a completion-only maintenance state so Render's process supervisor doesn't restart it and re-run the privileged bootstrap. The SQL-level role provisioning is `backend/scripts/provision-runtime-role.sql` (automated, self-verifying). There is no committed operational runbook or manual-DBA reference doc right now — prior references to `docs/p0-production-runbook.md` and `docs/production-database-roles.sql` pointed at files that don't exist in this repository; read `run-render-migration.sh` and `provision-runtime-role.sql` directly, or author replacement docs if this needs to be written down.


## AI-BOM correlation boundary

Post-reset tenant V2 adds link lifecycle, dependency paths, and independent gaps; platform V1 and tenant V1 remain immutable (V2 is the first post-reset tenant migration). `AiBomResourceVulnerabilityCorrelationService` establishes tenant context before calling the Spring-proxied, per-resource `AiBomCorrelationReconciler`. Lock order is source then resource; upload promotion and document soft deletion take the same source lock, held until commit. Captured revision mismatch aborts without retirement. Never create or mutate canonical findings from this reconciler. Current readers use ACTIVE associations independently of finding status. Observation/backfill and missing-subject repair run with retirement disabled by default; the release owner records representative tenant evidence before enabling retirement. `AI_BOM_CORRELATION_WRITES_ENABLED=false` disables association writes for rollback while canonical software processing continues.
