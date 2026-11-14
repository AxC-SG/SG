# VulnWatch Architecture

Last updated: 2026-10-28 (UI 2.0 documentation alignment)

---

## System Shape

VulnWatch is a security operations prototype: SBOM ingestion → vulnerability intelligence ingestion → deterministic CPE-based correlation → finding projection and workflow.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser — React 18 + TypeScript + Vite (port 5173 local)           │
│  Vercel static SPA (prod); nginx:8080 image is CI-scan only         │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ REST API (http://localhost:8080/api)
┌─────────────────────────────▼───────────────────────────────────────┐
│  Spring Boot 3.5.16 — Java 17 (port 8080)                            │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────────────┐ │
│  │ Controllers  │  │   Services     │  │  Scheduled Jobs          │ │
│  │ (67 REST)    │  │   (351)        │  │  (daily + hourly + 2s)   │ │
│  └──────┬───────┘  └───────┬────────┘  └──────────────────────────┘ │
│         │                  │                                         │
│  ┌──────▼──────────────────▼──────┐   ┌────────────────────────────┐│
│  │  Spring Data JPA / HikariCP    │   │  OutboundHttpClient        ││
│  │  TenantAwareDataSource         │   │  (retry + backoff)         ││
│  └──────────────┬─────────────────┘   └──────────┬─────────────────┘│
└─────────────────┼──────────────────────────────────┼────────────────┘
                  │ JDBC                             │ HTTPS
┌─────────────────▼──────────────────┐  ┌───────────▼────────────────┐
│  PostgreSQL — schema-per-tenant    │  │  External APIs             │
│  platform schema (shared)          │  │  NVD, KEV, GHSA, CSAF      │
│  tenant_<id> schema (per tenant)   │  │  EPSS, EUVD, JVN, EOL      │
│  Flyway migrations (postgres_reset)│  │  GitHub, ServiceNow, SCCM  │
└────────────────────────────────────┘  │  AWS, Azure, OpenAI, Resend│
                                        └────────────────────────────┘
```

Of the 67 controllers / 351 services, 19 controllers / 71 services live under `com.prototype.vulnwatch.aisecurity` — a separate top-level package implementing AI Security / AI Grid posture management (see [Core Data Flow](#7-ai-security--ai-grid) below and [business-logic-guide.md](business-logic-guide.md#ai-security--ai-grid-pipeline)). Its tables are read/written via `JdbcTemplate` directly, bypassing the Spring Data JPA path shown above.

---

## Core Data Flow

### 1. Inventory In

Three ingestion paths populate the inventory:

**SBOM ingestion** (CycloneDX / SPDX):
- File upload or configured endpoint fetch → `SbomIngestionService` → parse → normalize CPEs → write `inventory_components` + `inventory_component_cpe_map`
- GitHub repos or GHCR images → `GithubSbomIngestionCoordinator` → same normalization pipeline
- Runs every 5 minutes for configured sources; on-demand via upload

**CMDB sync:**
- ServiceNow CMDB → `ServiceNowCmdbSyncService` → CI records → `Asset`, `Ci`, `CiAlias`
- SCCM/MECM runs live JDBC against operator-approved SQL Server hosts (`SccmJdbcPolicy`, `SCCM_ALLOWED_HOSTS`), through durable `SCCM_CMDB` ingestion jobs; there is no fixture substitution.
- Runs every 5 minutes for scheduled syncs

**AWS Discovery:**
- `AwsDiscoveryClient` → SSM `DescribeInstanceInformation` → EC2 instances → `Asset`, `DiscoveryModel`
- Runs every 5 minutes for configured targets

**Generic Azure Discovery** is contained by `GenericAzureDiscoveryPolicy`; saved settings and inventory are retained, but configuration changes, connection tests and discovery execution are unavailable. This is independent of the retained static Azure AI/Foundry capability and its provider/entitlement controls.

**BOM / CBOM:**
- `BomController` (`/api/bom`) handles general Bill-of-Materials ingestion; `CbomController` (`/api/bom/cbom`) tracks cloud-posture BOM data
- Connect page's `bom-management` connector supports SBOM, AI-BOM, CBOM, and Vendor-BOM ingestion via URL or upload

All paths normalize software identities into `software_identities` and `software_instances`, and resolve CPEs into `cpe_dim` + `inventory_component_cpe_map`.

### 2. Vulnerability Intelligence In

Daily scheduled jobs pull from external feeds:

| Feed | Time | Tables written |
|------|------|----------------|
| NVD + CISA KEV | 01:00 | `vulnerabilities`, `vulnerability_targets`, `vulnerability_intel_observations` |
| GHSA | 01:15 | `vulnerabilities`, `vulnerability_targets` |
| Microsoft + Red Hat CSAF/VEX | 01:45 | `vex_assertions`, `vulnerability_intel_relations` |
| EPSS | 03:15 | `vulnerability_intel_observations` |

`EuvdApiClient` (EU Vulnerability Database) and `JvnApiClient` (Japan Vulnerability Notes) provide additional on-demand CVE sources, not on the daily schedule above.

The `vulnerability_intel_summary` table is a read-model projection aggregating all intel signals per CVE.

### 3. Correlation

CPE-based matching runs after each inventory or intel update:

1. Join `inventory_component_cpe_map` × `vulnerability_targets` on CPE vendor + product
2. `ApplicabilityDecisionService` evaluates version range constraints using `VersionScheme`-aware comparison
3. Result written to `component_vulnerability_states` (one row per component × vulnerability, with `applicabilityState`)
4. States roll up to `org_cve_records` (one row per CVE per tenant): `matchedAssetCount`, `matchedSoftwareCount`, `maxSeverity`, `hasKev`, `epssScore`

### 4. Finding Projection

`FindingService` watches `component_vulnerability_states` via the delta queue:

1. When a state flips to APPLICABLE: create `Finding` (if in AUTO generation mode)
2. When a state flips to NOT_APPLICABLE: auto-resolve linked findings
3. Suppression rules evaluated at creation; matching rules suppress immediately
4. Delta queue (`finding_delta_queue`) batches changes; drain job processes 100 per 2 seconds

### 5. EOL Pipeline

Runs weekly (Sunday), 4 stages:

1. Catalog refresh (02:00) → `eol_product_catalog`
2. Release data (03:00) → `eol_release`
3. Slug resolution (03:30) → `software_eol_mapping` (deterministic tiered matching; no OpenAI)
4. Denormalization (04:00) → `inventory_components.eol_slug`, `eol_cycle`, `eol_date`, `is_eol` (`eolDaysRemaining` is computed in response DTOs, not stored)

Daily sweep (00:15) catches components that crossed their EOL date between weekly runs.

### 6. Remediation Campaigns

`CampaignController` (`/api/campaigns`) groups findings/CVEs into a tracked remediation effort with a lifecycle (`DRAFT` → `ACTIVE` → `PAUSED`/`BLOCKED`/`IN_REVIEW` → `CLOSED`/`CANCELLED`), per-item exceptions, notify groups, and a watchlist. Frontend at `/vuln-repo/campaigns` (`CampaignsPage`, `CampaignDetailPage`) includes AI-assisted insights gated the same way as CVE investigation summaries.

### 7. AI Security / AI Grid

A separate discovery-and-governance pipeline, entitlement-gated (`ai.security`), that finds and assesses *other systems'* AI/ML resources rather than correlating CVEs:

1. **Discovery** — AWS Bedrock and Azure AI connectors (`aisecurity.aws`/`aisecurity.azure`) emit sanitized `ObservationEnvelopeV1` chunks describing agents, models, guardrails, knowledge bases, and MCP servers.
2. **AI Grid pipeline** — per completed scan scope: immutable snapshot → derived facts → ownership resolution → agent-rooted system grouping → policy assessment (JSON predicate engine) → R2 exposure correlation (cross-system risk chains, promoted to "validated" only on exact, fresh evidence) → coverage/setup-action reconciliation → bridge into the canonical `findings` table (`finding_kind = AI_POSTURE`/`AI_EXPOSURE`).
3. **Platform governance** — a separate platform-owner track (answer-key precision review, release certification, GA/canary policy distribution) gates what policy/correlation content ever reaches tenants.
4. **Tenant reporting** — `/policies` combines tenant-visible policies with registered framework coverage, latest assessment-state totals, and static assessment coverage (runtime Program 2 telemetry is deferred). The customer state projection is `PASS`/`FAIL`/`UNKNOWN`/`NOT_ASSESSED`: out-of-scope, capability-unavailable, and not-applicable subjects have no security state (`NOT_ASSESSED`); incomplete, stale, or failed evidence is `UNKNOWN`.

The framework registry (`GET /api/ai-frameworks`) is platform reference data and is readable without selecting a tenant. Framework coverage is tenant-scoped; runtime readiness is retired/out of scope and must not be called by current customer pages. Consequently, `/platform/ai-policies` is limited to global catalog/distribution governance and does not render tenant coverage or telemetry.

Full mechanics: [business-logic-guide.md](business-logic-guide.md#ai-security--ai-grid-pipeline). Schema: [database.md](database.md#ai-security--ai-grid-tables).

---

### 8. Canonical Ownership (Release 1)

Built but off by default (PR #71). Sources publish **claims** about who owns a **subject** (an asset, and in later releases occurrences and AI resources). `OwnershipResolver` picks one direct result per subject by fixed precedence (manual, ServiceNow, cloud account/project, AI Grid, cloud tag, Entra/Okta); the `ownership_effective_assignment` view applies inheritance up to 6 parent hops. Owners are always **teams**; people and groups come from a manual or CSV directory whose PII is encrypted with per-tenant data keys (`security/tenantkey/`, `enc:t1:`, HMAC blind indexes).

Each tenant moves each domain (`CORE`, `CLOUD_BOM`, `AI_GRID`) from LEGACY to DARK (link and compare) to CANONICAL (reads switch, irreversible through the API). Until then, read paths return `LEGACY_PENDING_MIGRATION` with the legacy owner label and the old `ownership_rules` stay in force. Release 1 cuts over CORE only. Per-consumer read waves, the effective-owner cache and the ServiceNow producer are separate switches, all off by default. The plan is [ownership-capability-mvp-plan.md](ownership-capability-mvp-plan.md) and the as-built record is [ownership-phase-0a-design.md](ownership-phase-0a-design.md).

## Multi-Tenant Architecture

### Schema-Per-Tenant

Each tenant gets a dedicated PostgreSQL schema. Connection-level `search_path` isolation means:
- Tenant A queries can never reach Tenant B's tables
- All JPA entities are schema-agnostic — they just use table names, and the schema is set at the connection level

**TenantAwareDataSource** wraps HikariCP:
- On checkout: `set_config('search_path', '<tenant schema>,platform', false)` (`platform,public` in platform context) and `set_config('app.current_tenant_id', '<id>', false)` (session-level)
- On return: `RESET search_path` / `RESET app.current_tenant_id` to prevent leakage

**Platform schema** holds: `tenants`, `app_users`, `tenant_memberships`, `tenant_support_grants`, `tenant_schema_versions`, and the global vulnerability intel, CPE, and EOL tables.

**Per-tenant schemas** hold: all operational data — `findings`, `assets`, `inventory_components`, `org_cve_records`, `risk_policies`, `suppression_rules`, `audit_events`, `demo_invites`, etc.

### Tenant Context Flow

```
HTTP Request
  → TenantResolutionFilter (servlet filter, HIGHEST_PRECEDENCE + 10; explicit local header/default compatibility only; no unverified JWT authority)
  → ApiKeyAuthenticationFilter (JWT validates current authority and installs tenant ID/schema; local API-key compatibility)
  → RequestCorrelationFilter (X-Request-ID into MDC)
  → TenantStatusFilter (block deleted or non-ACTIVE tenants)
  → Controller → Service → Repository (correct schema via HikariCP connection)
```

### New Tenant Bootstrap

`TenantSchemaService` creates new tenant schemas by cloning `tenant_default` (tables, sequences, defaults, foreign keys, and row-level security policies). Tenant creation is asynchronous: `TenantService.createTenant()` (called from `POST /api/platform/tenants`, which now returns 202) saves the tenant with status `PROVISIONING` and returns immediately — the schema clone and per-tenant migration happen the next time the tenant schema control plane runs (`TenantSchemaMigrationService.provisionNewTenant()` or `ProductionBootstrapCli`). `TenantLifecycleGuardService.isTenantAccessible()` only allows `ACTIVE` tenants into the workspace, so `PROVISIONING`/`PROVISIONING_FAILED` tenants are blocked until that run completes; `POST /api/platform/tenants/{tenantId}/provisioning-retry` re-queues a failed one.

### Tenant Schema Control Plane

Per-tenant DDL is no longer applied by the application's own startup Flyway run. A second, independent Flyway migration line lives under `backend/src/main/resources/db/migration/tenant/` (its own `<schema>.tenant_schema_history` table per tenant), separate from the platform-only `postgres_reset/` line (each file there must start with a `-- migration-guard: platform-only` comment, enforced by `PostgresResetMigrationGuardTest`). Both lines are append-only after their independent reset V1 baselines. Current packaged targets are platform V8 and tenant V6 (`MigrationCatalogTest`); the next versions are platform V9 and tenant V7. Every applied migration remains immutable.

`TenantSchemaMigrationService` drives the rollout: hold a Postgres advisory lock → migrate the `tenant_default` template and compute a SHA-256 **structural fingerprint** (normalized dump of every column/constraint/index/sequence/RLS policy) → migrate one canary tenant → migrate the rest in batches of 10, comparing each tenant's post-migration fingerprint against the template and failing (`DRIFTED`) rather than silently diverging. Every step is recorded in `platform.tenant_schema_versions`, surfaced by `TenantSchemaStatusService`/`TenantSchemaStatusController` (`GET /api/platform/tenant-schema-status`, shown in the Platform Console) and by `TenantSchemaReadinessHealthIndicator` (an actuator health contributor gated behind `app.tenancy.enforce-schema-version=true`).

The required/supported tenant range is V23–V23 (platform head V16); a lower configured floor cannot bypass it. With schema enforcement enabled, startup/readiness fail on missing required platform work structures/SELECT grants, V6 waiting-state constraint, schedule-occurrence index or reviewed-intelligence structures. Individual incompatible tenants are blocked at entry while compatible tenants remain usable; readiness reports their count. These are read-only checks, not startup migration ownership. The last observed deployed backend predates the development history reset; actual histories and upgrade/rollback compatibility remain unverified. See [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).

For production, the same rollout runs from `ProductionBootstrapCli` — a standalone `main()` that skips Spring/JPA entirely — invoked in a standalone ECS task with `/app/scripts/run-schema-migration.sh --run-once`. See [Deployment](#deployment) below; see [bootstrap wrapper](../backend/scripts/run-schema-migration.sh), [runtime grants](../backend/scripts/provision-runtime-role.sql) and [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).

**RLS rollout status:** row-level security policies are created on every provisioned tenant schema at provisioning time, and the mechanism that retroactively backfills a `tenant_id` column (if missing) and turns on `FORCE ROW LEVEL SECURITY` per table is now baked directly into `tenant/V1__tenant_schema.sql` rather than a later numbered migration, applied per tenant schema as each tenant is carried through the control-plane rollout above. `ProductionSafetyValidator.validateRuntimeRoleCannotBypassRls()` (platform line) remains the pre-flight gate confirming the production/preprod runtime role is non-superuser and lacks `BYPASSRLS` before this enforcement is allowed to proceed.

---

## Security Model

### Authentication Paths

`APP_JWT_AUTH_MODE=LOCAL` uses the local issuer and a configured ≥32-byte HMAC secret; EXTERNAL requires an issuer URI without a local HMAC secret, with optional JWK URI. Both validate issuer, audience and access-token use. LOCAL login uses current ACTIVE DB users and bcrypt password hashes; shared localhost login is explicitly configured and disabled by default. EXTERNAL disables local issuance.

`JwtTenantAuthenticationService` revalidates current stored global grants and tenant membership/support. Human claims cannot create grants or memberships; stale owner claims are rejected after revocation. Machine JWTs require SERVICE_ACCOUNT-only roles, explicit tenant and an active same-tenant registry entry matching the verified subject. A key ID alone is not a credential. API-key/creator-key role escalation remains local compatibility only and is rejected by deployed validation. See [backend authentication](backend.md#authentication).

`SecurityConfig` exposes only the listed public health/info, login/setup/CSRF and invitation/demo exchanges. Other API/actuator routes require authentication plus their route/service authorization. `/api/fix-intelligence/**` requires authentication; its writes are role-checked in `FixIntelligenceController`. Setup-cookie password submission requires CSRF; header CSRF bypass is granted only after verified authentication. See [public/protected endpoints](backend.md#public-and-protected-endpoints).

### Role Hierarchy

| Role | Access |
|------|--------|
| `PLATFORM_OWNER` | Platform APIs; tenant entry requires current authorized membership or support mode/reference |
| `TENANT_ADMIN` | Full tenant admin — users, connectors, all settings |
| `INVENTORY_ADMIN` | Connector configuration, CMDB/SBOM management |
| `SECURITY_ANALYST` | Finding triage, investigation workflow, CVE workbench |
| `READ_ONLY_AUDITOR` | Read-only across all tenant data |
| `OPERATOR` | API key default — read/write operations, no admin |
| `CREATOR` | Creator key default — includes all platform-level operations |
| `SERVICE_ACCOUNT` | Trusted external evidence producers only — required by `AiGridEvidenceIngestionController` (`POST /api/internal/ai-grid/evidence/{producerId}`); the authenticated principal must equal `producerId` |

This is a route-level summary, not an inheritance hierarchy. `TenantRolePolicy` restricts membership to the four customer roles; stored global grants and service-account authority are separate. Controller/service checks and sensitive support-action restrictions further constrain access. [Entitlements](backend.md#authorization-rules) share one resolver with the browser snapshot and never override independent containment.

### Security Filters (in order)

1. `TenantResolutionFilter` — populate `TenantContext` (registered as a servlet filter ahead of the Spring Security chain via `TenantIsolationConfig`)
2. `ApiKeyAuthenticationFilter` — API key / JWT resolution
3. `RequestCorrelationFilter` — inject `X-Request-ID` (plus method/path) into MDC
4. `TenantStatusFilter` — block deleted or non-ACTIVE tenants (HTTP 410 for a missing tenant, 423 otherwise)

### Production Safety Checks

`ProductionSafetyValidator` runs at startup and fails if (when `require-production-secrets=true`):
- `APP_ALLOW_API_KEY_AUTH=true`
- `APP_CREATOR_KEY` is set
- Invalid LOCAL/EXTERNAL JWT settings; deployed LOCAL also requires explicit HMAC permission and strong signing material
- `APP_ALLOW_HEADER_TENANT_SELECTION=true`
- `APP_REQUIRE_TENANT_CONTEXT=false`
- `APP_CREDENTIAL_ENCRYPTION_KEY` is weak/default
- `APP_CORS_ALLOWED_ORIGINS` is `*`
- `APP_TEST_PERSONAS_ENABLED=true`
- Runtime bootstrap/platform-owner seeding, Spring Flyway, schema migration, mock/persona/header fallback or demo synchronous provisioning enabled in a deployed runtime
- Missing/invalid APP_ENVIRONMENT or APP_RUNTIME_ROLE, non-FAIL transaction tenant guard, missing explicit entitlement cohort/ENFORCE, or pilot generative enablement

---

The deployed application uses the restricted non-owner/non-superuser/non-BYPASSRLS role with no DDL. Privileged migrations/grants run separately. Source/defaults do not certify the effective deployed identity or configuration. Durable work/attempt fencing, shutdown and encrypted delivery are described in [backend operations](backend.md#durable-work-scheduling-and-delivery).

## Projection Tables

Six read-model projections are central to performance:

| Table | Purpose |
|-------|---------|
| `component_vulnerability_states` | Component-level CPE applicability truth — drives all downstream work |
| `org_cve_records` | Per-tenant CVE rollup — backs the CVE Assessment Workbench UI |
| `vulnerability_intel_summary` | Global CVE read model — backs the Intelligence view |
| `software_inventory_items` | Flattened software inventory — backs reporting |
| `software_identity_summary` | Per-identity aggregation (asset count, version count, EOL status) |
| `quality_issue_projection` | Data quality issues by domain/severity — backs Operations Quality view |

These tables are never the authoritative source; they are rebuilt from the underlying entities when the source changes.

---

## Outbound HTTP Infrastructure

All external HTTP calls use `OutboundHttpClient` (wraps Spring `RestTemplate`):

- `OutboundPolicy` — per-service config (min request interval, max retries, backoff, retryable statuses, Retry-After handling)
- `OutboundPolicyFactory` — creates policies with `OutboundPolicyDefaults`
- `OutboundFailureClassifier` — distinguishes transient vs. permanent failures
- `OutboundFailureDecision` — controls retry vs. fail behavior
- `OutboundResponseHandler` — parses and validates responses

`AdvisoryFetchService` (in `client/http/`) handles bulk advisory fetching (CSAF/VEX sources with large document sets).

---

## Frontend Architecture

### Tech Stack

React 18 + TypeScript + Vite + React Router v7 + TanStack Query (React Query).

### Routing

All routes defined in `src/App.tsx` with typed helpers in `src/app/routes.ts`. Legacy query-param URLs redirected via `buildLegacyCompatiblePath()` on first render.

### One application presentation

UI 2.0 is the only tenant/platform/auth presentation. `main.tsx` imports one eager CSS entry (`styles/index.css`) and composes QueryClientProvider, BrowserRouter and `PresentationBoundary`. `AppShell` inside `App.tsx` owns shared navigation, workspace context and mounted theme. Route pages compose existing feature behavior and shared components; they do not own a second shell or theme store.

`presentationBoundary.ts` applies `data-ui="2"` outside `/demo` on direct loads; `PresentationBoundary` reapplies it before paint on route navigation and browser history. Public/demo content intentionally retains separately scoped styles. UI 1 rebuild switching and the legacy bridge are removed. Rollback uses the retained frozen build, not a build-time flag.

New screens follow [the UI development standard](<../Working Knowledge/New UI 2.0/ui-development-standard.md>), with exact CSS ownership in [UI 2 styles and rollback](<../Working Knowledge/New UI 2.0/ui2-styles-and-rollback.md>). Changes to shared presentation/interaction conventions need user approval during development, with alternatives, pros/cons and an affected-screen consistency plan.

### Key Architectural Decisions

**Feature-colocated types:** TypeScript types live in the feature directory that owns them (`src/features/findings/types.ts`, etc.). `src/types/index.ts` re-exports them for convenience but is not the source of truth.

**Two distinct CVE views:**
- `/vuln-repo/org-cves` → **Unified Vulnerability Records** — CVEs correlated to the org's inventory (query: `org_cve_records`)
- `/vuln-repo/vulnerabilities` → **Vulnerability Intelligence** — all ingested CVEs regardless of inventory match (query: `vulnerability_intel_summary`)

**S.AI Scoring (browser-side only):** `src/lib/riskScoring.ts` computes CVE Risk Score and Finding Priority Score from data already returned by the API. Not stored in the database. Recalculates on every render. Accepts optional `PolicyWeights` from the tenant's risk policy.

**ExposureDashboard vs. OperationalDashboard:** `/exposure` is risk-focused (CVE counts, SLA status, risk score). `/operations` is pipeline-focused (ingestion, source freshness, SLOs and run queues). Correlation efficiency and CSAF/VEX quality analytics live under Inventory; `/operations/quality` redirects there with quality-tab search parameters. Do not add operational/pipeline panels to the Exposure Dashboard.

### API Layer

API calls use `src/api/client.ts` and the established `src/features/cve-workbench/api.ts` adapter for specialized CVE workflows. Base URL: `VITE_API_BASE`, otherwise same-origin `/api` (the Vite proxy in development). Vercel production builds must set it — currently `https://api-lab.scoutgrid.io/api` — and the build rejects a value whose origin is not in the CSP `connect-src`. Auth headers injected on every request. TanStack Query provides caching, deduplication, and background refresh.

---

## Deployment

- **Backend container:** `eclipse-temurin:17-jre`, non-root user, port 8080, JVM flags: `-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError`
- **Frontend (production):** Vercel deploys `prototype-app/frontend` using `frontend/vercel.json`; `https://scoutgrid.io` is the sole public frontend origin. The Vercel configuration provides SPA rewrites and browser security headers. `frontend/Dockerfile.ci` builds the same static bundle only for CI image-security checks; it is not a deployment artifact.
- **AWS Standard target:** ECS Fargate runs the API and worker in private subnets behind an ALB and uses private RDS PostgreSQL. Vercel remains the frontend host for the lab and production (owner decision, November 13, 2026); the Amplify lab frontend is retired. Terraform defines the [Standard stack](../infrastructure/terraform/standard).
- **Current environment (November 13, 2026):** the Sydney AWS lab is the only backend (`https://api-lab.scoutgrid.io/api`) behind the Vercel site `https://scoutgrid.io`. Render is retired. See the [plan](<../Working Knowledge/AWS/LAB_SOLE_ENVIRONMENT_PLAN.md>) and [lab README](<../Working Knowledge/AWS/aws-lab/README.md>).
- **Database bootstrap:** An ECS task runs `ProductionBootstrapCli` with the migration role and exits. The API and worker use the restricted runtime role. See [bootstrap wrapper](../backend/scripts/run-schema-migration.sh), [runtime grants](../backend/scripts/provision-runtime-role.sql) and [qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).

For deployment-facing environment variables and operational endpoints, see [Backend](backend.md).

---

## Key Constraints and Design Decisions

1. **CPE-based correlation only** — matching uses normalized CPE strings. No fuzzy name matching. This makes false positives rare but requires good CPE coverage in the vulnerability feeds.

2. **Deterministic correlation** — `ApplicabilityDecisionService` applies version constraints mechanically. Correlation and EOL slug resolution are deterministic. Retained generative-assistance paths default off and remain hard off for the deployed pilot.

3. **Schema-per-tenant as the primary isolation boundary** — row-level security alone (a `tenant_id` column with no schema separation) was rejected as the *sole* mechanism because it requires every query to include a filter, which is easy to miss. Schema-level isolation via `search_path` enforces isolation at the database connection level; RLS is additionally enforced per tenant schema as defense-in-depth (see "Tenant Schema Control Plane" above), not as a replacement for it.

4. **Projection tables over on-the-fly joins** — the `org_cve_records` rollup and `vulnerability_intel_summary` exist because joining `component_vulnerability_states × vulnerabilities × inventory_components` at query time is too slow at scale. The projections trade storage for query speed.

5. **Delta queue over synchronous writes** — `finding_delta_queue` decouples correlation (high-write bursts) from finding creation (requires policy evaluation, suppression checks). The 2-second drain window batches work and avoids thundering-herd under large SBOM ingestion events.

6. **`ddl-auto=none`** — Flyway migrations own all DDL; Hibernate never creates or alters tables. New tenant schemas are provisioned by `TenantSchemaService`, which clones `tenant_default` (tables, sequences, defaults, foreign keys, RLS policies) rather than relying on Hibernate schema generation.


## AI-BOM correlation authority and lifecycle

The shared software pipeline owns canonical vulnerability findings. `AiBomCorrelationResolver` computes bounded source-document dependency support without writes; `AiBomCorrelationReconciler` applies association/path/gap/subject changes in one resource transaction after tenant context is established. Source locking serializes this boundary with replacement/deletion writers, and captured revision mismatch aborts the unit. Current readers filter ACTIVE links; history remains explicit, and finding workflow status is independent. Tenant V2 adds evidence/lifecycle storage without changing either V1 baseline. Observation/backfill precedes optional retirement enablement; disabling reconciliation writes preserves canonical software processing. The implementation plan and release evidence are archived outside the repo under `Other Docs/Archive/`.
