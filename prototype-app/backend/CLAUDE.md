# CLAUDE.md

> **Current prerequisite contract (October 21, 2026):** [implementation closure](<../Working Knowledge/AWS/AWS_APPLICATION_PREREQUISITES_IMPLEMENTATION_CLOSURE.md>) and [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>). Generic Azure, local archive operations, tenant OSV, runtime evidence and destructive tenant purge remain contained; Fix Intelligence and the patch connectors are re-enabled (tenant V9) but not yet release-qualified; deployed pilot generative assistance remains off. The unsupported Patch Management mock forms and credential-logging handlers have been retired; see [review handoff](<../Working Knowledge/AWS/AWS_APPLICATION_PREREQUISITES_REVIEW_HANDOFF.md>). Documentation completion is not release qualification.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> The root `../CLAUDE.md` contains full project conventions, architecture, scheduling, and the never-touch list. This file adds backend-specific runtime detail.

## UI 2.0 integration contract (October 28, 2026)

The frontend migration is complete: app/auth routes share UI 2.0 and `/demo` content retains its public boundary. Backend APIs, DTOs, authorization, tenant scoping and schema were not redesigned by that migration. Preserve those contracts when adding screens; do not enable contained capabilities or add mock success responses to match a design.

Use [the UI development standard](../docs/ui-development-standard.md) for new frontend work and API-driven states. Keep feature behavior server-authorized and report unavailable/permission/validation/error states explicitly. Shared UI architecture or interaction changes require the user's approval during development with alternatives, pros/cons and an app-wide consistency plan. See [current migration state](<../Working Knowledge/New UI 2.0/CURRENT_STATE.md>) for the limits of historical qualification evidence.

## Commands

See [local setup](../README.md#backend). The base configuration does not supply APP_ENVIRONMENT or APP_RUNTIME_ROLE; both must be explicit. Copy the ignored local profile from its committed example before using it, and configure private signing/encryption material for browser flows.

```bash
# Run the API server (port 8080, default profile)
mvn spring-boot:run

# Run with configured local example profile and local secrets
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

### JWT modes and current authority

`APP_JWT_AUTH_MODE` selects `LOCAL` or `EXTERNAL` in `JwtDecoderConfig`. LOCAL uses a configured local issuer and at least 32 bytes of HMAC secret, without external issuer/JWK settings. EXTERNAL requires an issuer URI and no local HMAC secret; its JWK URI is optional. Both validate issuer, audience and `token_use=access`. Local login, setup and context-token issuance require LOCAL mode; EXTERNAL does not issue local tokens.

`JwtTenantAuthenticationService` checks the current ACTIVE user, stored global grants (including supported owner aliases/compatibility state), and current membership or support grant on each authentication. Human role claims do not create global grants or tenant membership. A stale PLATFORM_OWNER claim without current stored ownership is rejected. `TenantRolePolicy` allows only `TENANT_ADMIN`, `INVENTORY_ADMIN`, `SECURITY_ANALYST` and `READ_ONLY_AUDITOR` for membership assignment and consumption; platform, compatibility and machine roles cannot be assigned as tenant roles.

Tenant claims select a registered workspace; they do not authorize it. A platform owner entering a tenant must carry an explicit current membership or support mode/reference. Revoked/expired support or membership and inactive users fail on revalidation. SERVICE_ACCOUNT tokens must claim only that role and select an explicit tenant; `ServiceAccountJwtAuthorizationService` requires an ACTIVE, same-tenant registry entry keyed by the verified JWT subject. The registry key ID alone is not a credential.

### Local API-key compatibility

`ApiKeyAuthenticationFilter` still supports `X-API-Key` only when `APP_ALLOW_API_KEY_AUTH=true` and an actual `APP_API_KEY` is configured (empty by default). It grants OPERATOR/SECURITY_ANALYST; a matching `X-Creator-Key`, or an unconfigured creator key, additionally grants CREATOR/PLATFORM_OWNER/TENANT_ADMIN/INVENTORY_ADMIN. `X-User-ID` selects the local identity, default `local-analyst`. These are local compatibility authorities, not the deployed JWT authority model. Deployed validation rejects API-key auth and creator-key configuration. A Bearer failure never falls back to API-key authentication.

### Public and protected endpoints

`SecurityConfig` permits OPTIONS, health/readiness/liveness/info, POST login/setup-password/setup-session and demo-requests, GET `/api/auth/csrf`, and GET/POST demo-invite and tenant-invite exchange routes. Public exchange does not bypass token/lifecycle checks. Setup-password uses its setup cookie plus CSRF; verified header authentication bypasses CSRF only after successful authentication, with setup-password explicitly excluded.

Other actuator routes and `/api/**` require authentication, with additional route/controller/service checks. `/api/platform/**` and `/api/operations/**` require PLATFORM_OWNER; GET operations quality and software-identity search also admit the listed tenant reader/admin roles in `SecurityConfig`. `/api/auth/context` and `/api/me` require authentication. `/api/fix-intelligence/**` requires authentication (the former denyAll rule was removed when Fix Intelligence shipped); writes are role-checked in `FixIntelligenceController` (create/edit `TENANT_ADMIN`/`SECURITY_ANALYST`, approve/retire `TENANT_ADMIN`, and the approver must differ from the proposer). Static host-context evidence requires SERVICE_ACCOUNT plus producer/principal binding; runtime ingestion/read paths remain HTTP 410 / `RUNTIME_OUT_OF_SCOPE`.

## Multi-tenancy

`TenantAwareDataSource` wraps every connection from the HikariCP pool and runs:
```sql
SELECT set_config('app.current_tenant_id', '<uuid>', FALSE);
SELECT set_config('search_path', '<tenant_schema>,platform', FALSE);
```
On connection close it resets both; a failed reset or unfinished transaction causes physical connection eviction/abort. Platform work uses `platform,public`; required but absent tenant context gets a sentinel UUID that cannot match tenant rows. Search path chooses the schema; forced RLS and the restricted role enforce row isolation. `TenantSchemaExecutionService` rejects tenant/schema switches through its scoped runner inside an active transaction (FAIL is the only accepted mode). Establish platform scope before starting its transaction as well.

`TenantContext` (thread-local) carries the current tenant UUID and schema name. `ApiKeyAuthenticationFilter` calls `TenantContext.clear()` in a `finally` block. JWT auth sets `TenantContext.setCurrentTenantId(actor.tenantId())` inside the filter.

`TenantResolutionFilter` is a servlet filter before the security chain; JWT authentication then installs the revalidated tenant ID **and schema** before downstream transactions. Header selection requires explicit `APP_ALLOW_HEADER_TENANT_SELECTION=true`; it is disabled in the base and deployed profiles and is not enabled by the committed local example. It cannot override JWT details installed by the auth filter. Deployed requests never fall back to a default workspace.

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

historically ran with a connection pinned before context selection. The current `TenantSchemaExecutionService` rejects the tenant/schema switch in an active transaction, so this pattern now fails explicitly. Missing context also fails closed under required-tenant RLS. Always establish context first rather than relying on a mid-transaction switch.

Correct pattern — context first, transaction inside:

```java
public X doWork(Tenant tenant) {                 // no method-level @Transactional
    return tenantSchemaExecutionService.run(tenant, () ->
        transactionTemplate.execute(status -> { ... }));   // tx opens with context already set
}
```

Equivalently, wrap the call at the background call site in `tenantSchemaExecutionService.run(tenant, () -> service.theTransactionalMethod(...))`. Audit any `@Transactional` method that calls `tenantSchemaExecutionService.run(...)` internally and is reachable from a scheduled/async path.

A scheduled poller/drain over a **per-tenant** table (`ingestion_jobs`, `finding_delta_queue`, etc.) must iterate `tenantService.listActiveTenants()` and run each tenant's claim+process inside `run(tenant, …)` — the scheduler thread carries no tenant context. A bare drain cannot safely select customer work.

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
- Current packaged targets are platform **V8** and tenant **V9**, independently resolved by `PackagedMigrationCatalog`. The next platform migration is V9 and the next tenant migration is V10; each must update `MigrationCatalogTest`. This binary requires tenant V9, including Fix Intelligence and patch management tables, GCP discovery tables, the ticketing framework (Jira connector, per-finding ticket provider and sync watermark), bounded retention progress and intelligence revision eligibility; a configured lower minimum cannot bypass that floor. The last observed deployed backend predates the development history reset; actual deployed histories remain unverified. Fresh reset-history V5→V6 tests do not prove deployed upgrade or rollback compatibility. See [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).
- This explicitly authorized development reset includes all changes from the former platform V1–V10 and tenant V1–V17 histories. Use a fresh database and `mvn clean` to remove stale packaged migration resources. Baselines are not idempotent repair scripts: do not replay them against existing tables or use `flyway:repair` to adopt the reset. `baseline-on-migrate` stays false.
- Outside this one-time reset, never edit an already-applied migration; add the next version instead.

## Key env vars for local dev

Copy `src/main/resources/application-local.example.yml` to the ignored `application-local.yml` when using the local profile. `application.yml` imports `backend/.env.local`; generate secrets locally from `.env.example`. Set APP_ENVIRONMENT=local explicitly if not using the example. The example does not enable header selection or disable required tenant context. Configure LOCAL signing before using browser login.

| Env var | Purpose | Local default |
|---|---|---|
| `DB_URL` | JDBC URL | `jdbc:postgresql://localhost:5432/vulnwatch` |
| `APP_JWT_AUTH_MODE` | Explicit `LOCAL` or `EXTERNAL` contract | `LOCAL` |
| `APP_JWT_LOCAL_ISSUER` | Issuer for locally issued access tokens | `urn:scoutgrid:local` |
| `APP_JWT_HMAC_SECRET` | Local signing/verification secret, at least 32 bytes | (empty; must be configured for local tokens) |
| `APP_JWT_ISSUER_URI` | Required issuer for `EXTERNAL` mode | (empty) |
| `APP_SECURITY_JWT_AUDIENCE` | Required expected access-token audience | `scoutgrid-api` |
| `APP_JWT_ROLES_CLAIM` | Role claim name (not human grant authority) | `roles` |
| `APP_ALLOW_HEADER_TENANT_SELECTION` | Trust `X-Tenant-ID` header | `false` (explicit opt-in only) |
| `APP_REQUIRE_TENANT_CONTEXT` | Enforce tenant context on every request | `true` |
| `APP_ALLOW_API_KEY_AUTH` | Enable X-API-Key auth path | `true` |
| `OPENAI_API_KEY` | Optional credential for explicitly enabled local assistance | empty; key alone never enables it |
| `NVD_API_KEY` | NVD rate-limited API key | (empty = unauthenticated) |
| `GITHUB_API_TOKEN` | GitHub token for SBOM/GHSA | resolved from `backend/secrets/github-api-token` |

`GenerativeAssistancePolicy` defaults assistance off (`OPENAI_ENABLED=false`) and refuses deployed production/preproduction assistance before resolving any key alias. Startup rejects pilot enablement. Deterministic recommendations/fallbacks remain available with truthful source/time metadata. EOL slug resolution is deterministic. Static AI Security / AI Grid discovery uses its separate capability/entitlement and provider controls; it does not require an OpenAI key.

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
  dto/         # API request/response objects
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

`aisecurity/**` tables have **no JPA entity or Spring Data repository** — every read/write goes through `JdbcTemplate`/`NamedParameterJdbcTemplate` directly in the service classes. Full module map: [business-logic-guide.md](../docs/business-logic-guide.md#ai-security--ai-grid-pipeline), schema: [database.md](../docs/database.md#ai-security--ai-grid-tables).

`FixIntelligenceController` (`/api/fix-intelligence/**`) serves Fix Intelligence reads to all tenant roles and role-checked writes; queries live in `service/fix/FixIntelligenceQueryService` (tenant-filtered SQL) and writes in `FixManagementService`. Patch connectors live in `service/patch/` (`sccm/`, `intune/`, `bigfix/`, `tanium/`) behind the `PatchProvider` contract; providers never write to the database — `PatchIngestionService` does. `FixApplicabilityDecision` and `JiraIssueBacklog` still have no migration; do not wire them. See root `CLAUDE.md` → Fix Intelligence.

Newer, less-obvious controllers worth knowing about: `CampaignController` (`/api/campaigns` — remediation campaigns), `CbomController` (`/api/bom/cbom` — cloud BOM posture), `BomController` (`/api/bom`), `AzureDiscoveryController` (`/api/connectors/azure-discovery`), `IngestionJobController` (`/api/ingestion-jobs`), `TenantSchemaStatusController` (`/api/platform/tenant-schema-status` — per-tenant schema migration status), `DemoDatasetController` (`POST /api/platform/tenants/{tenantId}/demo-data`, `PLATFORM_OWNER` — manual demo dataset provisioning), `TenantSupportAccessController` (`/api/tenants/{tenantId}/support-grants` + `/api/auth/support-grants/**` — tenant-initiated break-glass support access, distinct from the platform-owner-initiated `tenant_support_grants` flow).

## Docker build

```bash
docker build -t vulnwatch-backend .
docker run --env-file /path/to/private/local-runtime.env -p 8080:8080 vulnwatch-backend
```

JVM flags in the image: `-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError`.

## Production bootstrap (Render)

The permanent `scout-backend` web service (`render.yaml`, repo root) never runs schema migrations itself (`APP_SCHEMA_MIGRATION_ENABLED=false`) and is only ever given the restricted `scout_runtime` Postgres role — never the owner/migration role. Schema bootstrap (platform + tenant migrations, runtime-role provisioning, control-plane verification, optional platform-owner setup-link email) runs from a **separate, temporary** Render web service via `backend/scripts/run-render-migration.sh`, which execs `com.prototype.vulnwatch.migration.ProductionBootstrapCli` (a standalone `main()`, no Spring context) and then holds the container open in a completion-only maintenance state so Render's process supervisor doesn't restart it and re-run the privileged bootstrap. The SQL-level role provisioning is `backend/scripts/provision-runtime-role.sql` (automated, self-verifying). Operational entrypoints are [bootstrap wrapper](scripts/run-render-migration.sh) and [runtime grants](scripts/provision-runtime-role.sql). Follow [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>) before any separately authorized environment operation.


## AI-BOM correlation boundary

Post-reset tenant V2 adds link lifecycle, dependency paths, and independent gaps; platform V1 and tenant V1 remain immutable (V2 is the first post-reset tenant migration). `AiBomResourceVulnerabilityCorrelationService` establishes tenant context before calling the Spring-proxied, per-resource `AiBomCorrelationReconciler`. Lock order is source then resource; upload promotion and document soft deletion take the same source lock, held until commit. Captured revision mismatch aborts without retirement. Never create or mutate canonical findings from this reconciler. Current readers use ACTIVE associations independently of finding status. Observation/backfill and missing-subject repair run with retirement disabled by default; the release owner records representative tenant evidence before enabling retirement. `AI_BOM_CORRELATION_WRITES_ENABLED=false` disables association writes for rollback while canonical software processing continues.
