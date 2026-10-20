# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Backend

```bash
cd backend
mvn spring-boot:run                                    # start the API server (port 8080, default profile)
mvn spring-boot:run -Dspring-boot.run.profiles=local   # local profile: enables JWT auth + header tenant selection
mvn test                                               # unit tests (Surefire) + JaCoCo report at target/site/jacoco/index.html
mvn -Ppostgres-it verify                               # unit + Postgres integration tests (Failsafe, requires Postgres)
mvn test -Dtest=MyServiceTest                          # run a single unit test class
mvn -Ppostgres-it verify -Dit.test=MyServicePostgresIntegrationTest  # run a single IT class
```

Surefire excludes `**/*PostgresIntegrationTest.java`; Failsafe picks them up at the `integration-test` / `verify` phase. `mvn -Ppostgres-it test` runs unit tests only — use `verify` to also run the Postgres ITs.

The development migration histories were reset to two complete V1 baselines. Use a fresh PostgreSQL database and run the normal platform and tenant bootstrap. Existing development data may be discarded; `flyway:repair` does not convert an old schema/history into these new baselines. Clear Maven's old packaged migrations with `mvn clean` before building.

If the error is `Found more than one migration with version N` (after a migration file is renamed/replaced), run `mvn clean` first to purge stale copies from `target/classes/` before restarting.

### Frontend

```bash
cd frontend
npm install
npm run dev           # dev server on port 5173 (strictly)
npm run lint          # eslint .
npm run typecheck     # tsc -b --noEmit
npm run build         # tsc -b --force && vite build && node scripts/verify-production-bundle.mjs
npm run test:unit     # vitest run (non-watch)
npm run test:coverage # vitest run --coverage (enforces line/branch thresholds)
npx vitest run src/pages/FindingsPage.test.tsx  # run a single test file
```

Frontend CI gates: `npm run lint` → `npm run typecheck` → `npm run build` → `npm run test:coverage` (vitest with coverage thresholds enforced).

Backend CI gates: `mvn -q verify` runs Surefire + Failsafe + JaCoCo `check` (line-coverage floor) + SpotBugs. Repo-wide, `gitleaks` (config: `.gitleaks.toml`, also wired as a `pre-commit` hook via `.pre-commit-config.yaml`) scans for committed secrets — there is no committed credential-incident-gate runbook right now (a prior reference to `docs/p0-production-runbook.md` was removed when that file was deleted; someone should author a replacement if this procedure needs to be written down again).

## Architecture

### System Shape

VulnWatch is a security operations prototype: SBOM ingestion → vulnerability intelligence ingestion → deterministic CPE-based correlation → finding projection and workflow.

- `frontend/` — React 18 + TypeScript + Vite SPA
- `backend/` — Java 17 + Spring Boot 3.5.16, Spring Data JPA, Spring Security
- Database — PostgreSQL at `jdbc:postgresql://localhost:5432/vulnwatch`
- Schema — Flyway-owned migrations in `backend/src/main/resources/db/migration/postgres_reset/` (`ddl-auto=none`)

See `backend/CLAUDE.md` and `frontend/CLAUDE.md` for directory-specific runtime detail.

### Backend Package Layout (`com.prototype.vulnwatch`)

| Package | Contents |
|---|---|
| `controller/` | 48 REST controllers under `/api/**`, including `FixIntelligenceController` (`/api/fix-intelligence/**` — see Fix Intelligence note below) |
| `service/` | 280 business-logic services (including subpackages `cbom/`, `cmdbingestion/`, `sbomingestion/`, `vulningestion/` — the latter holds the NVD/KEV/GHSA/CSAF/EUVD/JVN sync logic and `@Scheduled` entry points) |
| `domain/` | 153 JPA entities (assets, inventory, vulns, findings, policies, CMDB, EOL, SCCM, AWS/Azure discovery, campaigns, BOM/CBOM, Fix Intelligence/patch-management scaffolding) |
| `dto/` | 283 API request/response objects (incl. `dto/patch/` — patch-management DTOs with no current caller, see Known Limitations) |
| `repo/` | 97 Spring Data JPA repositories |
| `client/` | 25 external API client files (incl. `client/http/`) (NVD, EUVD, JVN, GHSA, CSAF, EPSS, GitHub, ServiceNow, SCCM, endoflife.date, AWS, Azure, OpenAI, Resend) |
| `config/` | Spring beans and security configuration (`SecurityConfig`, `ApiKeyAuthenticationFilter`, `TenantAwareDataSource`, `ProductionSafetyValidator`) |
| `security/` | `SensitiveTenantAction` annotation + interceptor, `PasswordSetupCookieService`, `PublicEndpointRateLimiter` (5 files) |
| `util/` | CPE handling, version comparison, SBOM parsing |
| `migration/` | Standalone (non-Spring) production bootstrap: `ProductionBootstrapCli` (platform + tenant schema migration, runtime-role provisioning, control-plane verification, optional platform-owner setup-link email), `PlatformOwnerSetupLinkIssuer`, `TenantSchemaMigrationCli` (compatibility shim delegating to `ProductionBootstrapCli`), plus `TenantSchemaFingerprint`, `PackagedMigrationCatalog`, and `TenantSearchPathFlywayCallback` (6 files total) |
| `web/`, `tools/` | `PlatformAdminRequestPaths` (request-path classifier — no call site found outside its own test as of this writing); `LegacyGithubSyncRunBackfillTool` (standalone CLI) |

A separate top-level package, `com.prototype.vulnwatch.aisecurity` (own `controller/`, `service/`, `model/`, `policy/`, `aws/`, `azure/` subpackages — 19 controllers, 71 services), implements **AI Security / AI Grid**: discovery and governance of AI/ML resources (Bedrock agents, Azure AI Foundry projects, MCP servers, etc.) found in the org's cloud accounts, entitlement-gated per tenant (`ai.security`). Its tables have no JPA entity or repository — they're accessed via `JdbcTemplate` directly. See "AI Security / AI Grid" in `docs/backend.md` and `docs/business-logic-guide.md#ai-security--ai-grid-pipeline`.

Newer, less-obvious controllers (outside `aisecurity`) worth knowing about: `CampaignController` (`/api/campaigns` — remediation campaign lifecycle, see below), `CbomController` (`/api/bom/cbom` — cloud bill-of-materials posture), `BomController` (`/api/bom`) for general BOM ingestion, `AiBomDeclaredResourceController` (`/api/bom/declared-resources` — declared AI-BOM models/datasets, coverage setup actions, and the reviewed deployment-mapping propose/approve/remove workflow; see "AI-BOM → AI Grid Integration" in `docs/business-logic-guide.md`), `AzureDiscoveryController` (`/api/connectors/azure-discovery`), `TenantSchemaStatusController` (`/api/platform/tenant-schema-status` — per-tenant schema migration status; see "Tenant Schema Control Plane" in `docs/backend.md`), `DemoDatasetController` (`POST /api/platform/tenants/{tenantId}/demo-data`, `PLATFORM_OWNER` — manual demo dataset provisioning), and `TenantSupportAccessController` (`/api/tenants/{tenantId}/support-grants` + `/api/auth/support-grants/**` — tenant-initiated break-glass support access).

### Core Data Flow

1. **Inventory in** — SBOMs (upload, endpoint fetch, GitHub repo/GHCR), BOM/CBOM uploads, or ServiceNow/SCCM CMDB sync write `assets`, `inventory_components`, `software_identities`, `software_instances`, and normalize CPEs into `cpe_dim` + `inventory_component_cpe_map`. AWS and Azure Discovery connectors add cloud-resource assets via SSM / subscription APIs respectively.
2. **Vulnerability intel in** — NVD, KEV, GHSA, Microsoft/Red Hat CSAF/VEX, EUVD, JVN, advisory imports populate `vulnerabilities`, `vulnerability_targets`, and read-model projections.
3. **Correlation** — CPE joins between `inventory_component_cpe_map` and `vulnerability_targets`, version-checked by `ApplicabilityDecisionService`, write `component_vulnerability_states`.
4. **Projection** — States roll up to `org_cve_records` (one row per CVE per tenant). `FindingService` drives finding create/reopen/resolve.
5. **EOL pipeline** — 4-stage async job: catalog refresh → release cycles → slug resolution → denormalization into `inventory_components.is_eol / eol_date / eol_slug / eol_cycle` (`eolDaysRemaining` is computed in DTOs, not stored).
6. **Remediation Campaigns** — `CampaignController`/`CampaignService` group findings/CVEs into a tracked remediation effort with lifecycle states (DRAFT, ACTIVE, PAUSED, BLOCKED, IN_REVIEW, CLOSED, CANCELLED), per-item exceptions, notify groups, and a watchlist. Frontend at `/vuln-repo/campaigns`.
7. **AI Security / AI Grid** — entitlement-gated (`ai.security`) static definition/configuration discovery → snapshots/facts → ownership/system grouping → posture and exposure assessment → canonical `AI_POSTURE`/`AI_EXPOSURE` findings. Runtime events, logs, activity summaries, execution timelines, readiness, and runtime findings are deferred. `AiRuntimeScope` independently blocks collection/admission/read paths; worker and evaluator perform no work. Setting `APP_AI_SECURITY_RUNTIME_ENABLED=true` fails startup in every environment. `/policies` reports tenant static policies, framework coverage, and assessment totals. Fresh tenant V1 starts without runtime evidence; the runtime-retention scheduler is disabled. The standalone runtime-exclusion doc was archived outside the repo under `Other Docs/Archive/`; the live scope statement is in `docs/business-logic-guide.md#ai-security--ai-grid-pipeline`.

### Projection Tables (Central to Read Performance)

- `component_vulnerability_states` — component-level CPE applicability truth
- `org_cve_records` — tenant/CVE rollup used by CVE Assessment Workbench UI
- `vulnerability_intel_summary` — vuln list read model (all CVEs, not org-filtered)
- `software_inventory_items` — flattened software inventory for reporting
- `software_identity_summary` — per-identity aggregation (asset/component/version counts, EOL breakdown) for Software Identities view
- `quality_issue_projection` — data quality issues by domain/severity for Operations Quality view

### Security Model

Two authentication paths, handled by `ApiKeyAuthenticationFilter`:

**API key** (`X-API-Key` header, enabled when `APP_ALLOW_API_KEY_AUTH=true`):
- Grants `ROLE_OPERATOR` + `ROLE_SECURITY_ANALYST` to all callers.
- `X-Creator-Key` additionally grants `ROLE_CREATOR`, `ROLE_PLATFORM_OWNER`, `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN`.
- `X-User-ID` sets the user identity (defaults to `APP_DEFAULT_USER_ID` / `local-analyst`).
- Defaults: `APP_API_KEY` is empty, so the filter rejects API-key requests ("API key is not configured") until it is set. When no creator key is configured, every valid API-key caller gets creator-level access. `change-me-in-prod` is only the frontend's `import.meta.env.DEV` fallback in `src/api/client.ts`, not a backend default.

**JWT Bearer** (`Authorization: Bearer <token>`):
- Active only when `APP_JWT_ISSUER_URI` is set (wires a `JwtDecoder` bean).
- Token decoded and passed to `JwtTenantAuthenticationService`, which resolves roles from the configured claim (default `roles`; namespaced claims ending in `/roles` also work).
- Roles from JWT are mapped to Spring `GrantedAuthority` values.

Authorization rules: `/api/platform/**` and `/api/operations/**` require `ROLE_PLATFORM_OWNER`. `/api/operations/quality/**` and `GET /api/operations/software-identities/search` also permit `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN`, `ROLE_SECURITY_ANALYST`, and `ROLE_READ_ONLY_AUDITOR`. All other `/api/**` require authentication (including `/actuator/**` beyond health/info), **except `/api/fix-intelligence/**`, which is `permitAll()` unconditionally** — a carve-out added with the Fix Intelligence MVP, not gated by profile or environment; see Known Limitations. Public: OPTIONS, `/actuator/health`, `/actuator/info`, `POST /api/auth/login`, `POST /api/auth/setup-password`, `POST /api/auth/setup-session`, `POST /api/demo-requests`, `/api/demo-invites/**`, `/api/tenant-invites/**`. `GET /api/auth/context` and `GET /api/me` require authentication like any other `/api/**` route (no longer `permitAll()`) but are still CSRF-ignored as read-only endpoints, alongside the public routes above. `POST /api/internal/ai-grid/evidence/{producerId}` requires a new role, `ROLE_SERVICE_ACCOUNT`, plus the authenticated principal matching `producerId` — used by trusted external evidence producers feeding the AI Grid pipeline. `POST /api/internal/ai-grid/runtime/{producerId}/v1/batches` retains its existing authorization boundary but returns HTTP 410 / `RUNTIME_OUT_OF_SCOPE`. Runtime receipt and execution reads are retired. Legacy `/inventory/ai/executions` URLs redirect to static AI inventory.

`APP_ALLOW_HEADER_TENANT_SELECTION=true` enables local header-based tenant selection via `X-Tenant-ID`; must be disabled in production.

### Multi-Tenancy Status

Schema-per-tenant isolation is fully implemented, not aspirational: `TenantAwareDataSource` sets `search_path` + `app.current_tenant_id` per connection checkout (reset on return), `TenantSchemaService` clones `tenant_default` (tables, sequences, defaults, FKs, and RLS policies) to provision new tenant schemas, and `ProductionSafetyValidator` runs 11+ startup checks gating unsafe config in production. AI Grid policy publication requires explicit tenants or publish-all. `AiGridPolicyDeprecationService` still calls `TenantService.getDefaultTenant()` solely to record a platform deprecation event in the default tenant's audit table. Tenant creation is now asynchronous: `POST /api/platform/tenants` returns 202 and the tenant sits in `PROVISIONING` status until the tenant schema control plane (below) actually creates and migrates its schema; `TenantLifecycleGuardService` denies workspace entry to anything other than `ACTIVE`.

Row-level security policies are created on each tenant schema at provisioning time. Full RLS *enforcement* is rolled out per-tenant by the **tenant schema control plane**: a second Flyway migration line under `backend/src/main/resources/db/migration/tenant/` (separate from `postgres_reset/`, its own `tenant_schema_history` table per schema), applied by `TenantSchemaMigrationService` (dev) or the standalone `ProductionBootstrapCli` (production) — never by the application's own startup Flyway run. RLS enforcement (backfilling `tenant_id` and turning on `FORCE ROW LEVEL SECURITY` per table) is baked directly into `tenant/V1__tenant_schema.sql` and rolls out per tenant (template → canary → batches of 10, verified by comparing a structural SHA-256 fingerprint against the template) rather than via a separate later migration. `ProductionSafetyValidator.validateRuntimeRoleCannotBypassRls()` is the pre-flight gate confirming the production/preprod runtime role is non-superuser and lacks `BYPASSRLS` before this rollout is allowed to run. See `docs/database.md#tenant-schema-control-plane` for the full mechanics and the Render deployment procedure.

### Frontend Navigation

`src/App.tsx` uses **React Router v7** (`react-router-dom` 7.x) with path-based routing. `src/app/routes.ts` owns all typed path-builder helpers. Legacy query-param URLs (e.g. `?tab=inventory`) and the older `/vulnerability-intelligence/*` paths are redirected to their current equivalents on first render.

Top-level routes and their paths:

| Path | Component | Purpose |
|------|-----------|---------|
| `/` | Role-based redirect | → `/exposure`, `/configurations`, or `/platform/tenants` depending on actor role |
| `/exposure` | `ExposureDashboardPage` | Risk-focused overview (Overview) |
| `/findings` | `FindingsPage` | Active findings |
| `/findings/:displayId` | `FindingDetailPage` | Single finding detail |
| `/fix-intelligence/:view?` | `FixIntelligencePage` | Fix Intelligence MVP — default `all`; sub-views `patches`, `workarounds`, `compensating-controls`. Demo-data only, see Known Limitations |
| `/fix-intelligence/details/:fixId` | `FixDetailPage` | Single fix detail |
| `/operations/:operationsView?` | `OperationalDashboardPage` | Default `pipeline`; sub-views `pipeline`, `platform-health` (`quality` redirects to `/inventory` with quality-tab search params instead of rendering here — see note below) |
| `/vuln-repo` | `VulnRepoDashboardPage` | Vulnerability Repository dashboard |
| `/vuln-repo/org-cves/:cveId?` | `VulnRepoOrgCvePage` | **Unified Records** — org-correlated CVEs (CVE Assessment Workbench) |
| `/vuln-repo/vulnerabilities` | `VulnRepoVulnerabilitiesPage` | **Intelligence** — all ingested CVEs (global feed) |
| `/vuln-repo/org-cves/:cveId/assets` | `VulnRepoCveAssetsPage` | Per-CVE affected asset breakdown |
| `/vuln-repo/org-cves/:cveId/software` | `VulnRepoCveSoftwarePage` | Per-CVE affected software breakdown |
| `/vuln-repo/campaigns` | `CampaignsPage` | Remediation campaign list |
| `/vuln-repo/campaigns/:id` | `CampaignDetailPage` | Campaign detail — lifecycle, exceptions, notify groups, watchlist |
| `/vuln-repo/software-assets` | `VulnRepoSoftwareAssetsPage` | Software-centric asset breakdown |
| `/vuln-repo/host-assets/:assetId` | `VulnRepoHostAssetRoute` | Host asset detail from vuln-repo context |
| `/vuln-repo/intel/:externalId` | `PlatformVulnIntelDetailPage` | Platform-scoped intel detail |
| `/inventory/:inventoryView?` | `InventoryPage` (dispatches sub-views) | Default `overview`; `ai` sub-view shows `AiInventoryPage` |
| `/inventory/hosts/:assetId` | `InventoryHostAssetRoute` | Host asset detail |
| `/inventory/software-identities/:softwareIdentityId` | `SoftwareIdentityDetailRoute` | Software identity detail |
| `/inventory/ai/assets`, `/inventory/ai/knowledge-data`, `/inventory/ai/mcp`, `/inventory/ai/:assetId` | `AiInventoryAssetsPage`, `AiKnowledgeMcpInventoryPage`, `AiAssetDetailPage` | Static AI artifact inventory — entitlement-gated (`ai.security`) |
| `/inventory/ai/overview`, `/inventory/ai/agents`, `/inventory/ai/agent-versions` | `AiInventoryPage` / `AiInventoryAssetsPage` | Alias routes for AI inventory sub-views (`/inventory/ai/executions` redirects to `/inventory/ai`) |
| `/inventory/ai/declared-resources[/:resourceId]` | `AiBomDeclaredResourcesPage`, `AiBomDeclaredResourceDetailPage` | AI-BOM declared models/datasets, coverage setup actions, and the propose/approve/remove deployment-mapping workflow — entitlement-gated (`ai.security`); declared above `/inventory/ai/:assetId` |
| `/findings/ai`, `/findings/ai/vulnerabilities`, `/findings/ai/:findingId` | `AiFindingsPage` (tabbed: Policy Violations default, Software Vulnerabilities), `AiFindingDetailPage` | Deterministic AI policy-failure findings (Policy Violations) and canonical `VULNERABILITY` findings affecting a declared AI-BOM resource (Software Vulnerabilities) — both separate from the main CVE-workbench finding stream |
| `/findings/ai/exposures[/:exposureId]` | `AiExposuresPage` | AI Grid cross-system validated exposure paths |
| `/policies[/:policyId]` | `AiPoliciesPage`, `AiPolicyDetailPage` | Tenant AI Grid policy catalog — enable/disable plus tenant framework coverage, assessment-state totals, scope, exceptions, and parameters |
| `/connect/:connectView?` | `ConnectPage` | Default `sources`; also `run-history`. `/connect/copilot-studio` is a separate entitlement-gated (`ai.security`) route for `CopilotStudioConnectorPage` |
| `/admin/:adminView?` | `UserManagementPage` | Default `users`; also `invites`, `roles`, `service-accounts`, `audit` |
| `/platform/:platformView?` | `PlatformConsolePage` | Default `tenants`; also `users`, `platform-audit`, `demo-requests`, `operations`, `vuln-intel`, `eol`, `ai-policies`. Platform-owner console; `/platform/ai-policies/:policyId` is the policy detail route (`/vuln-repo/policies` redirects to `/platform/ai-policies`). `ai-policies` sub-view is `PlatformAiPolicyStudio` (global governed AI Grid catalog/distribution/rollout; tenant coverage and telemetry are intentionally not rendered here) |
| `/configurations/:configView?` | `ConfigurationsPage` | Default `sla`; risk policy, SLA, scoring, automation |
| `/authorized-workspaces` | `AuthorizedWorkspacesPage` (via `AuthorizedWorkspacesRoute`) | Platform-owner-only list of tenant-approved support access grants |
| `/login` | `LoginPage` | Credential login |

**`/end-of-life` no longer renders a dedicated EOL page** — it redirects to `/platform/eol` for platform-scope owners, or `/exposure` otherwise. **Legacy redirects:** `/vulnerability-intelligence*` paths redirect to their `/vuln-repo/*` equivalents.

**AI Security routing:** all `/findings/ai*`, `/policies*`, and `/inventory/ai*` routes are wrapped in `AiSecurityRoute`, redirecting to `/exposure` unless `canUseEntitlement(actor, 'ai.security')` is true and the actor is not in platform scope — an **entitlement** (per-tenant plan flag, `src/features/auth/entitlements.ts`), a separate mechanism from the role checks above. There is no shared `:aiView?` optional-param pattern for these routes; each sub-page is its own literal route.

Demo/public routes (outside auth boundary): `/demo`, `/demo/blog`, `/demo/blog/zero-day-response-hours-not-weeks`, `/demo/blog/mythos-readiness`, `/demo/blog/why-your-sbom-tool-doesnt-know-whats-exploitable`, `/demo/request`, `/demo/request/success`, `/demo/expired`, `/invite/:token`, `/tenant-invite/:token`, `/setup/:token`.

Overview (`/exposure`) is reserved for risk metrics and risk-focused summaries only. Do not place operational, pipeline, quality, freshness, correlation-efficiency, or CSAF/VEX analytics panels on Overview; those belong under Operational Dashboard.
Correlation Efficiency and CSAF/VEX Quality Analytics have moved off Operations → Pipeline and now live under Inventory (reached via `/operations/quality` redirecting to `/inventory` with quality-tab search params); `PipelinePayload` itself only carries ingestion/freshness data now.

All API calls go through `src/api/client.ts`. Base URL defaults to `http://localhost:8080/api` (via `VITE_API_BASE`). Auth headers are injected on every request.

### TypeScript Types

Types are **feature-colocated**, not centralised. `src/types/index.ts` re-exports them but the source of truth is in each feature directory:

- `src/features/findings/types.ts` — `Finding` and related
- `src/features/cve-workbench/types.ts` — `OrgSpecificCveExposureRecord`, `CveDetail`, etc.
- `src/features/configurations/types.ts` — `RiskPolicy` (frontend type includes 6 triage weight fields that the backend entity does not have — see Configurations Page), `OwnershipRuleResponse`, `OwnershipRuleRequest`, `SuppressionRule`
- `src/features/inventory/types.ts` — inventory-specific types
- `src/features/connect/types.ts` — connector and CMDB config types
- `src/features/ai-security/types.ts` — AI Security/AI Grid artifact, finding, policy, coverage, and exposure-intelligence types
- `src/types/ownership.ts` — `OwnershipSummary` and related

Always edit the source file in the feature directory, not the re-export in `types/index.ts`.

### Two Distinct CVE Views

These are separate pages backed by separate API endpoints — do not confuse them:

- **`/vuln-repo/org-cves`** → `VulnRepoOrgCvePage` — **"Unified Vulnerability Records"**
  Queries `org_cve_records` via `useOrgSpecificCvesQuery`. Shows only CVEs correlated
  to the org's software inventory. Primary analyst triage and investigation workflow.
  CVEs here always have a CPE match; `matchedAssetCount` / `matchedSoftwareCount`
  reflect the extent of that match.

- **`/vuln-repo/vulnerabilities`** → `VulnRepoVulnerabilitiesPage` — **"Vulnerability Intelligence"**
  Queries `vulnerability_intel_summary` via `useVulnRepoVulnerabilitiesQuery`. Shows
  ALL CVEs ingested from NVD/GHSA/KEV regardless of inventory match. CVEs with
  `matchedSoftwareCount = 0` are expected here — they exist in the global feed but
  have no org inventory correlation.

The Vulnerability Repository sub-nav shows: **Dashboard | Unified Records | Intelligence**.

### S.AI Scoring Layer (`src/lib/riskScoring.ts`)

Pure TypeScript module — no React, no API calls. Computes two frontend-only scores entirely from data already returned by existing API endpoints:

- **`computeCveRiskScore(item, policy?)`** → S.AI Risk Score (0–10, CVE level)
  Stages: CVE Published (CVSS + EPSS) → In CISA KEV → Org Exposure (blast radius) →
  EOL Risk → No Patch → Applicability decision → Findings Created.
  Displayed as a horizontal left-to-right phase timeline via `CveRiskScorePanel`
  injected at the top of the CVE Assessment Workbench.

- **`computeFindingPriorityScore(finding, policy?)`** → S.AI Priority (0–10, finding level)
  Signals: exploitability (KEV/EPSS weight), SLA breach proximity, missing owner,
  EOL component, severity boost, VEX confirmed affected.
  Shown as a column in the Findings table and a row in Finding Detail.

Both functions accept an optional `PolicyWeights` parameter — the 6 triage fields from
`RiskPolicy`. Call sites fetch these via `useRiskPolicyQuery()` and pass `policyQuery.data`
in. `DEFAULT_POLICY` (all weights = 1.0) preserves original behavior when policy is
unavailable. The `PolicyWeights` type mirrors the 6 `triage*` fields on the frontend `RiskPolicy` type (not present on the backend entity):
`triageExploitabilityWeight`, `triageBlastRadiusWeight`, `triageEolRiskWeight`,
`triageSlaBreachWeight`, `triageMissingOwnerBoost`, `triagePatchGapBoost`.

### Configurations Page (`/configurations`)

Sidebar-nav layout. Sections in order (leftmost first):

| # | Tab key | Label | Content |
|---|---------|-------|---------|
| 1 | `sla` | **SLA & Remediation** | Risk score thresholds (critical/high), remediation deadlines per severity, asset criticality SLA multipliers |
| 2 | `triage` | **S.AI Prioritization** `AI` | 6 triage urgency signal weight sliders + live Triage Score Simulator |
| 3 | `automation` | **Workflow Automation** | Auto-close rules (enabled/days), finding generation mode (AUTO/MANUAL) |
| 4 | `ownership` | **Ownership** | Rule-based user/group assignment; conditions stored in `ownership_rules` table (V1 baseline) |
| 5 | `findings-score` | **Findings Score** | Custom attribute-based scoring rules (table + column + operator + value + weight); live simulator; max 10 columns; weights sum to 1.0; stored as `findings_score_config` JSONB in `risk_policies`; evaluated at query time by `FindingsScoreService`; returned as `findingsScore` (0–10) on every `FindingResponse`; `POST /api/risk-policy/recompute-findings-scores` triggers `FindingsScoreRecomputeService.recomputeAll()` for all OPEN findings |
| 6 | `suppress` | **Suppression Rules** | Create rules that suppress CVE or Finding records when matching conditions are met; each rule has name, state (DRAFT/APPROVED/IN_REVIEW/REJECTED/EXPIRED), record type (CVE/FINDING), valid from/to, execution order, and free-form reason; persisted to `suppression_rules` table via `GET/POST/PUT/DELETE /api/suppression-rules` |
| 7 | `auto-findings` | **Auto-Finding Rules** | Automatically create findings based on CVE, software, and asset criteria |

All sections except Ownership persist to a single `RiskPolicy` record via `PUT /api/risk-policy`.
`applyTriageDefaults()` normalises API responses for older backends that predate the 6 triage weight fields
(fills missing triage fields with sensible defaults rather than crashing).
**Verified gap:** the backend `RiskPolicy` entity/DTO and both migration baselines contain no `triage*` fields (grep of `backend/src/main` finds none), so these six weights exist only on the frontend `RiskPolicy` type and are not stored by `PUT /api/risk-policy`. Treat the slider values as client-side state until a backend column is added.

**Vulnerability Sources moved off this page.** The per-tenant feed filter rule editor (`VulnerabilitySourcesSection`, `vulnerability_source_filter_configs`) is no longer a Configurations tab — it now renders inside a collapsible "Vulnerability Intelligence" accordion on the Connect page (`/connect/sources`, gated by `canManageSourceFilters(actor)`).

### Connect Page Architecture

`ConnectPage` (`/connect/:connectView?`) is a connector catalog with views: `sources` (default) and `run-history`. Under `sources`, the catalog renders as a card-grid: connector cards centre in an auto-fill grid (a column ladder in `connect.css` steps five-across down to one as the viewport narrows) rather than a fixed two-column stack, and each card shows the connector's real vendor mark (Microsoft's four squares, the `aws` wordmark, Azure's triangle, ServiceNow's `NOW` tile, BigFix's slate-blue "b", Tanium's red-disc "T") drawn as inline SVG rather than committed logo files, keeping third-party trademark assets out of the repo. Connector health (last sync / failure) is exposed via the status dot's `title`/`aria-label`, not card body text — there's no room for a stacked "Last sync · 2h ago" line in the card design.

**Connector categories (rendered as connector-card grids under `sources`):** three sections, not the CMDB/Cloud/AI split of the previous stacked-card design —

- **Inventory** — absorbs CMDB, cloud, and AI sources in one section: `sbom-github`, `servicenow-cmdb`, `sccm-cmdb`, `aws-discovery`, `azure-discovery`, and (entitlement-gated, `ai.security`) `ai-security-aws` (AWS Bedrock), `ai-security-azure` (Azure AI Foundry), `ai-security-copilot` (Microsoft Copilot Studio); config components `AiSecurityConnectorPage`, `AiSecurityAzureConnectorPage`, `CopilotStudioConnectorPage`
- **BOM Management** — `sbom-endpoint`, `bom-management` (SBOM/AI-BOM/CBOM/Vendor-BOM via URL or upload)
- **Patch Management** — `sccm-patch`, `bigfix-patch`, `tanium-patch`; patch deployment tracking from SCCM/MECM, IBM BigFix, and Tanium for vulnerability remediation. Config components `SccmPatchConnectorPage`, `BigFixPatchConnectorPage`, `TaniumPatchConnectorPage` are reachable from the catalog but are UI-only mock forms today — "Test Connection" / "Save Configuration" only `console.log` their inputs, there is no backend call, and there is no backend service behind them yet (see Known Limitations). Distinct from the `sccm-cmdb` connector under Inventory, which is a real, wired CMDB sync.

There is no "Vulnerability Intelligence" connector-card section anymore — see the accordion note above. `endoflife-date`, `euvd-feed`, `jvn-feed`, and `sbom-github` are still declared in the `ConnectorId` union and `CONNECTORS` array (with `ConnectorDetailContent` cases) but are not included in any of the three rendered category lists above, so they currently have no clickable card anywhere in the UI — likely a real gap worth a follow-up ticket rather than intentional.

Clicking a connector card renders `ConnectorDetailContent` which delegates to a focused component per connector. Adding a new connector requires: add to `ConnectorId` union, `CONNECTORS` array, the appropriate category list, and a `ConnectorDetailContent` case.

Key connector components:
- `SccmConnectorPage` — SCCM/MECM CMDB sync (discovery, auth, field mapping, sync schedule)
- `AwsDiscoveryConnectorPage` — AWS EC2 discovery via SSM, multi-account via `aws_discovery_targets`
- `AzureDiscoveryConnectorPage` — Azure compute/platform resource discovery across subscriptions (mirrors the AWS connector; `CLIENT_SECRET` or `MANAGED_IDENTITY` auth)
- `VulnIntelConnectorPage` / `VulnIntelConfigPage` — NVD, GHSA, KEV, CSAF source configuration
- `NvdConnectorPage`, `KevConnectorPage`, `GhsaConnectorPage`, `MicrosoftCsafConnectorPage`, `RedhatCsafConnectorPage`, `AdvisoryConnectorPage` — per-feed configuration pages
- `IntegrationRunQueuePage` / `InventoryRunQueuePage` — live run queue surfaces
- `GithubPipelineManager` — GitHub SBOM source management
- `IngestionPage` — SBOM endpoint / file upload
- `SccmPatchConnectorPage`, `BigFixPatchConnectorPage`, `TaniumPatchConnectorPage` — patch-management connector config UI (mock only, see above)

### Fix Intelligence (`/fix-intelligence`)

`FixIntelligencePage` (list/filter by `all`/`patches`/`workarounds`/`compensating-controls`) and `FixDetailPage` are an MVP surface for browsing recommended fixes (patches, workarounds, compensating controls) independent of the CVE Assessment Workbench's own fix-recommendation feature (`FixRecordService`, `fix_records` table, surfaced inside `CveDetailController`'s CVE detail response — an older, unrelated feature; don't confuse the two). `FixIntelligenceController` (`/api/fix-intelligence/**`) is backed entirely by `FixDemoDataSeeder.generateDemoFixes()` — a fixed, in-memory, seeded-random (`Random(42)`) list of ~100 synthetic fixes. There is no persistence, no correlation to real inventory or CVE data, and no pagination beyond an in-memory slice. See Known Limitations for the auth and schema gaps around the domain entities (`Fix`, `FixApplicabilityDecision`, `AssetFixStatus`, `CveFixMap`) added alongside this controller but not wired to it.

### Adding a Database Migration

There are now **two independent Flyway migration lines** — pick the right one:

- **Platform/`public` schema**: after the one-time reset, use `postgres_reset/V{next}__description.sql`; `V1__platform_schema.sql` owns `public`, `platform`, and the empty `tenant_default`. Every file must open with `-- migration-guard: platform-only` and must not contain tenant DDL or placeholders.
- **Per-tenant schema DDL** (every table inside `tenant_default`/`tenant_<id>`, including RLS): use `backend/src/main/resources/db/migration/tenant/V{next}__description.sql`, beginning with `-- migration-guard: tenant-only`. This line is applied by `TenantSchemaMigrationService` or `ProductionBootstrapCli`, independently from platform startup Flyway. Files may use `${tenantId}`/`${tenantSchema}` placeholders. **Current heads: platform V1 and tenant V2** (`tenant/V2__ai_bom_correlation_evidence.sql` adds AI-BOM link lifecycle, `ai_bom_correlation_paths`, and independent gaps). Both baselines include the complete current schema, deployment metadata, harm-assessment baselines, AI-BOM integration, and runtime exclusion. `MigrationCatalogTest` asserts both targets; platform migrations next start at V2, tenant at V3, and each must update the test.

Never edit an already-applied migration file. (Before the one-time migration-history reset described below, a narrow exception existed for two pre-reset files that needed a schema-qualification fix — that fix is now simply part of the `V1` baselines, so no live exception currently applies; don't treat historical precedent as license to edit an applied migration today.)

The baseline migrations are `postgres_reset/V1__platform_schema.sql` (74 platform/public tables) and `tenant/V1__tenant_schema.sql` (145 tenant tables). They were regenerated from a disposable fully migrated database, including migration-owned catalog/budget seeds and no customer data. This explicitly authorized development reset replaces the previous V1–V10 platform and V1–V17 tenant histories. Existing databases must be recreated; do not repair their histories or overlay these baselines on populated schemas. Future changes are append-only V2 onward.

### Scheduled Jobs

All source cron callbacks explicitly use UTC. Fixed-delay pollers have no wall-clock time zone. The complete role, enablement and recovery inventory is [the Phase 3 schedule matrix](docs/AWS/PHASE_3_SCHEDULE_MATRIX.md); deployed revisions/settings require separate verification. Manual EOL requests persist queue intent, including on API nodes, and execute through an eligible worker.

| Time | Job |
|---|---|
| `00:15` daily | Lifecycle date sweep (EOL/EOS transitions) |
| `01:00` daily | NVD incremental + KEV sync |
| `01:15` daily | GHSA sync |
| `01:45` daily | Microsoft + Red Hat CSAF/VEX sync |
| `02:00` daily | EUVD sync |
| `02:05` daily | Mark stale assets inactive |
| `02:30` daily | VEX staleness recompute; JVN sync |
| `02:45` daily | OSV platform sync |
| Disabled | Unfinished OSV tenant correlation (`OsvTenantService`) |
| `03:15` daily | EPSS score refresh |
| `07:00` daily | ServiceNow incident status sync (`FindingIncidentSyncService`) |
| `02:00` Sunday | EOL catalog refresh (stage 1) |
| `03:00` Sunday | EOL release data refresh (stage 2) |
| `03:30` Sunday | EOL slug resolution (stage 3) |
| `04:00` Sunday | EOL denormalization (stage 4) |
| Every 5 min | Run enabled GitHub SBOM sources |
| Every 5 min | Run enabled ServiceNow / AWS Discovery scheduled syncs; SCCM and generic Azure remain disabled for the pilot |
| Every 15 min | Reopen expired suppressions |
| Every 2 sec | Drain `finding_delta_queue` (batches of 100) |
| Every 1 min (default) | Recover stale `PROCESSING` finding-delta-queue entries (sibling of the 2s drain, recovers from a worker dying mid-batch) |
| Every 30 min (default) | Entitlement shadow-mode sweep — recomputes corrected-vs-legacy entitlement decisions per tenant/key |
| Every 30 sec (default) | Demo dataset provisioning poll — seeds/repairs requested tenants' demo data once `ACTIVE` |
| Every 3 sec (default) | Poll `ingestion_jobs` for AI Security AWS/Azure discovery jobs |
| Deferred | `AiGridRuntimeIngestionWorker` is blocked and does not claim telemetry batches |
| Daily 02:17 (default) | `AiAgentExecutionRetentionService` — returns immediately while `AiRuntimeScope.excluded()` |
| Every 5 sec (default) | AI Grid assessment worker (`AiGridAssessmentWorker`); AI-BOM projection worker poll (`AiBomProjectionWorker`) |
| Every 60 sec (default) | AI-BOM projection reconcile; Copilot Studio schedule poll (`CopilotStudioScheduleService`) |
| Every 5 min (default) | BOM contribution backfill (`BomContributionBackfillService`) |
| Every 60 sec (default) | Demote AI Grid validated exposures with expired evidence |
| Daily 02:20 (default) | Sweep Azure AI credential profiles for expiry |
| Every 5 sec (default) | Process pending AI Grid policy rollout tasks (`AiGridPolicyRolloutService`) |
| Every 5 sec (default) | Process pending AI Grid policy deprecation tasks (`AiGridPolicyDeprecationService`) |
| Hourly | Policy-based auto-close findings |
| Hourly | Demo tenant expiry check |
| Midnight | Nightly re-run of all approved suppression rules |

A handful of additional infra-level jobs also run (ingestion job polling every 2s, finding-projection maintenance and BOM-projection reconciliation every 5 min, vulnerability queued-run polling every 5s, performance telemetry snapshot every 30s) — see `docs/backend.md` for the full list.

### Known Limitations

- `POST /api/cve-detail/{cveId}/suppress` persists suppression state via `OrgCveRecordService.suppress()` and returns a `SuppressionResponse`. Suppression expiry is handled by the 15-minute reopen job.
- Multi-tenant schema-per-tenant isolation is implemented (see "Multi-Tenancy Status" above). `AiGridPolicyDeprecationService` uses `TenantService.getDefaultTenant()` only as the audit destination for platform policy deprecations; tenant selection and publication do not use it as a fallback. Full RLS enforcement across production tenants remains gated by `ProductionSafetyValidator.validateRuntimeRoleCannotBypassRls()` (confirms the runtime role is non-superuser and lacks `BYPASSRLS` before enforcement is allowed to proceed).
- The live CVE workflow is the CVE Assessment Workbench at `/vuln-repo/org-cves`. `CveDetailPage.tsx` exists but is not mounted in the router.
- GHCR attestation ingestion does not yet perform cryptographic signature verification.
- AI-assisted features (investigation summary, AI solution, AI actions) call OpenAI and are gated by `OPENAI_ENABLED`. Results are persisted on `org_cve_records` / `org_cve_ai_artifacts` so subsequent reads do not re-call the API.
- ServiceNow incident creation (`POST /api/cve-detail/{cveId}/servicenow-incident`) writes `incident_id` / `incident_status` onto findings. The `FindingIncidentSyncService` daily 07:00 job pulls incident state changes back, so the integration is no longer fully one-way — but it is read-only on the ServiceNow side.
- S.AI Risk Score and S.AI Priority are computed entirely in the browser from existing API data — they are not stored in the database and recalculate on every render.
- SCCM sync (`SccmCmdbSyncService`) performs asset discovery and field mapping but does not yet support incremental delta sync — each run is a full sweep.
- AWS Discovery (`aws-discovery` connector) is scoped to EC2 instances via SSM; multi-account/region support via `aws_discovery_targets` with cross-account role ARN + external ID.
- Azure Discovery (`azure-discovery` connector) mirrors the AWS Discovery architecture (config + per-subscription targets, `CLIENT_SECRET` or `MANAGED_IDENTITY` auth) but is newer and less exercised in production than AWS Discovery.
- Remediation Campaigns (`CampaignController`, `/vuln-repo/campaigns`) and CBOM/cloud-posture tracking (`CbomController`, `/api/bom/cbom`) are shipped and now covered in `docs/business-logic-guide.md` and `docs/database.md`, though not at the same field-level depth as the core finding/CVE workflow — read the controllers/DTOs directly if you need more.
- AI-BOM → AI Grid integration (common BOM lifecycle, declared AI inventory, transitive-dependency correlation into canonical findings, and the reviewed deployment-mapping workflow) is fully shipped — see "AI-BOM → AI Grid Integration" in `docs/business-logic-guide.md` and the "BOM Common Lifecycle" / "AI-BOM Declared Resources" tables in `docs/database.md`. Model scanning, new BOM-derived exposure rules, CBOM findings consolidation, and broader package identity normalization were deliberately excluded from scope, not deferred by oversight. BOM coverage policies remain disabled in the AI Grid policy catalog on purpose — `provenance.ai_bom_present` is registered as `COVERAGE_CONTEXT` evidence only, never a `POSTURE_FINDING` input.
- AI Security / AI Grid (`com.prototype.vulnwatch.aisecurity`, entitlement-gated `ai.security`) is a large, separately-governed module — see `docs/business-logic-guide.md#ai-security--ai-grid-pipeline` for the full pipeline. Its tables have no JPA entity/repository (JdbcTemplate-only); Azure discovery is newer/less battle-tested than AWS and has its own kill switch; Macie/Purview integrations are strictly read-only against existing classification results.
- The development migration reset is intentional and explicitly authorized: the complete platform and tenant histories are each consolidated into V1. The reset/adoption procedure doc (`development-v1-baseline-reset.md`) was archived outside the repo under `Other Docs/Archive/`. **`.github/scripts/check-migration-integrity.py` still requires `prototype-app/docs/development-v1-baseline-reset.md` to exist to recognize a reset PR** (`RESET_RECORD`) — restore the file or update the guard before any future baseline reset. Existing development databases must be recreated.
- `com.prototype.vulnwatch.web.PlatformAdminRequestPaths` has no call site found outside its own unit test as of this writing — likely incompletely wired up.
- Several docs and this file previously referenced `docs/p0-production-runbook.md` for the production bootstrap/Render migration procedure and `docs/production-database-roles.sql` for manual DBA role grants — **neither file exists in the repository**. These are pre-existing dangling references (the runbook doc has since been deleted outright); someone should author replacements or remove the remaining references in `backend/CLAUDE.md`, `docs/backend.md`, and `docs/architecture.md`.
- **Fix Intelligence MVP** (`/fix-intelligence`, `FixIntelligenceController`) is demo data only — see "Fix Intelligence" above. Its `/api/fix-intelligence/**` endpoints are `permitAll()` with no auth check and no tenant scoping at all (not even the usual API-key path), which is a real gap against the documented security model, not a deliberate design choice for this data; do not extend this controller to touch real tenant data without closing that first.
- **Patch management infrastructure is mostly unwired scaffolding.** The `sccm-patch`/`bigfix-patch`/`tanium-patch` cards on `/connect` open mock config forms (`SccmPatchConnectorPage`, `BigFixPatchConnectorPage`, `TaniumPatchConnectorPage`) whose "Test Connection"/"Save Configuration" actions only `console.log` — no API call exists yet. The domain entities added alongside them (`AssetFixStatus`, `CveFixMap`, `PatchConnectorCredential`, `JiraIssueBacklog`) and their repositories have **no corresponding Flyway migration** — `asset_fix_status`, `cve_fix_map`, `patch_connector_credentials`, and `jira_issue_backlog` don't exist in either migration line, so any code path that actually touches them will fail against a real Postgres (`ddl-auto=none`). `FixApplicabilityService` and the `dto/patch/*` DTOs (`PatchCoverageMetricsResponse`, `PatchDeploymentDashboardResponse`, `VendorPatchData`, etc.) have no controller or service caller anywhere in the codebase. `PatchConnectorRegistrationConfig`, `PatchSyncSchedulingConfig`, and `JiraIssueStatusSyncService` ship with a `.disabled` file extension, excluding them from the Maven build entirely — treat all of this as scaffolding for future work, not a working patch-management pipeline.
- The production-bundle credential check (`frontend/scripts/verify-production-bundle.mjs`, run as part of `npm run build`) scans `dist/` for literal dev-credential strings (`change-me-in-prod`, `local-creator`, `local-analyst`, provider secret patterns). `src/api/client.ts` already avoids embedding these in production by reading them through an `import.meta.env.DEV ? '<default>' : ''` ternary, which Vite dead-code-eliminates in a prod build. `FixIntelligencePage`/`FixDetailPage` initially bypassed this by calling `fetch()` directly with hardcoded `X-API-Key`/`X-Creator-Key` header values instead of going through `api/client.ts`, which leaked the literals into the production bundle and failed this gate; they were fixed to gate those headers behind `import.meta.env.DEV` inline. Prefer routing new pages through `api/client.ts` rather than raw `fetch()` so this class of bug can't recur.

### GitHub Token

For GitHub SBOM / GHCR / GHSA features, place a token in `backend/secrets/github-api-token` (gitignored). Resolution order: `GITHUB_API_TOKEN_FILE` → `backend/secrets/github-api-token` → `GITHUB_API_TOKEN`.

## Conventions

These are prescriptive. PRs that violate them will be rejected.

### What counts as "done"

A change is done when **all** of these are true:

1. **Behavior is verified.** Backend: at least one test exercises the changed code path (unit, controller IT via `@PostgresControllerIntegrationTest`, or service IT). Frontend: at least one vitest test exercises the changed page or hook. "Verified by manual testing" is not done.
2. **CI is green.** All gates above pass: lint, typecheck, build, coverage thresholds, JaCoCo line floor, SpotBugs, Failsafe ITs.
3. **No new warnings introduced.** ESLint or `tsc` warnings on touched files block merge — fix them in the same PR.
4. **PR template is filled in.** Scope, why, repro, test added/changed, blast radius, rollback. Empty sections = reject.
5. **For UI changes, a screenshot is attached.** Type-check passing is not the same as feature working — see the global guidance on UI changes.

### When to add a test

| Change | Test required |
|---|---|
| Bug fix | Yes — a regression test that fails before the fix and passes after. |
| New API endpoint | Controller IT covering happy path + at least one auth/error case. |
| New service method called from a controller | Service-layer IT or a controller IT that exercises it end-to-end. |
| New frontend page / new top-level component | Vitest page test asserting render + at least one interaction. |
| Refactor with no behavior change | No new test, but existing tests must still pass. If they don't exist, that's a separate gap — file it as an issue, don't silently leave the code uncovered. |
| Migration-only PR | A repo IT that asserts the new schema state, OR a service IT that exercises the new column. |
| Frontend-only style/copy change | No test required if no logic changed. |

### When to refactor vs. leave alone

- **Bug fix scope is the bug.** Don't refactor surrounding code in the same PR even if it's tempting. File a follow-up issue.
- **If you must refactor to fix the bug**, keep the refactor and the fix in **separate commits** so the fix is reviewable without the noise.
- **Don't migrate old code to new patterns opportunistically.** The scaffolding READMEs (`backend/src/test/java/com/prototype/vulnwatch/support/README.md`, `frontend/src/test/README.md`) explicitly say: migrate when you're already in the file for another reason. Otherwise, leave it.
- **Premature abstraction is rejected.** Three similar lines is fine. Don't introduce a helper for two callers, an interface for one implementation, or a feature flag for hypothetical future configurability.

### Naming and commit conventions

- **Migrations**: `V<next>__short_snake_case.sql` in the appropriate independent line: `backend/src/main/resources/db/migration/postgres_reset/` for platform/public DDL or `backend/src/main/resources/db/migration/tenant/` for tenant-schema DDL.
- **Tests**: backend Postgres ITs end with `PostgresIntegrationTest.java` (Surefire-excluded, Failsafe-included). Frontend page tests live next to the page as `<Page>.test.tsx`.
- **Commits**: imperative subject ≤72 chars. Body explains the *why*, not the *what* — the diff already shows the what.
- **Branch names**: `<type>/<short-slug>` where type is `fix`, `feat`, `refactor`, `chore`, `docs`. Example: `fix/correlation-applicable-state-filter`.

### Never-touch list (require explicit approval before changing)

- **Already-applied Flyway migrations** (`backend/src/main/resources/db/migration/postgres_reset/V*.sql`). Add a new migration; never edit an applied one.
- **Security config** (`com.prototype.vulnwatch.config.SecurityConfig`, `ApiKeyAuthenticationFilter`, anything that decides who's authenticated or authorized).
- **Tenant scoping** (`TenantService`, `TenantContext`, multi-tenant filter logic). Cross-tenant leaks are the worst class of bug.
- **Deploy infra** (`infra/`, `Dockerfile`, `.github/workflows/`). Changes here affect deploy/build for everyone — flag in PR description.
- **Golden contract fixtures** (`backend/src/test/resources/fixtures/golden/*.sha256`). Changing a hash means the canonicalized output changed — that's an API contract change. Justify in the PR.
- **`scripts/`** — operator scripts that touch the running database or production-like state.

### Things that get rejected on sight

- Edits to applied migrations (re-edit V21 instead of writing V42).
- New `console.log` / `System.out.println` left in shipped code.
- `// TODO` comments without an owner or linked issue.
- Mocking the database in integration tests instead of using `@PostgresIntegrationTest`.
- Adding `--no-verify` / `--no-gpg-sign` to git commands in CI or scripts.
- Coverage thresholds lowered — floors only move up, never down. Raise them as new tests are added.
- New `any` types in TypeScript or `@SuppressWarnings("unchecked")` in Java without a comment explaining why.
- New external HTTP calls without a corresponding `MockRestServiceServer` test (see `ApiContractGoldenPostgresIntegrationTest`).
- Files added to `frontend/src/components/` larger than ~300 lines — split into a feature directory under `frontend/src/features/<feature>/`.
# Database migration rules

The database uses independent V1 Flyway baselines: platform V1 owns `public`, `platform`, and the empty `tenant_default` schema; tenant V1 owns complete per-tenant DDL, RLS, constraints, and tenant-safe seeds. Migration files are append-only and applied migrations must never be edited, deleted, renamed, or moved. Fresh PostgreSQL validation, migration-validation, PostgreSQL integration, and an up-to-date/merge-queue branch are required before merge. The explicitly authorized development reset/adoption procedure (doc now archived, see Known Limitations); it does not authorize a shared/production database reset.
