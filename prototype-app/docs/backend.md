# VulnWatch Backend

Last updated November 13, 2026 for the UI 2.0 connector contract changes.

## UI 2.0 integration boundary

UI 2.0 is the active frontend presentation. Tenant Fix Intelligence uses the [Fix Intelligence API](#fix-intelligence). The [UI 2.0 wiring fixes](<../Working Knowledge/New UI 2.0/ui2-backend-wiring-fixes-2026-10-30.md>) record the AWS Bedrock and GitHub SBOM contract changes and their verification.

New API-driven screens follow [the UI development standard](<../Working Knowledge/New UI 2.0/ui-development-standard.md>), including explicit loading/error/unavailable states and real persistence checks. Use shared frontend HTTP/auth handling and backend enforcement; changes to shared UI conventions need user approval with pros/cons and an app-wide consistency plan. [Current migration state](<../Working Knowledge/New UI 2.0/CURRENT_STATE.md>) records qualification limits.

## Tech Stack

| Component | Version / Detail |
|-----------|-----------------|
| Java | 17 |
| Spring Boot | 3.5.16 |
| Spring Security | JWT Bearer + API key dual-auth |
| Spring Data JPA | PostgreSQL via HikariCP |
| Database | PostgreSQL (Flyway migrations in `postgres_reset/` for the platform schema; a second `tenant/` line, applied once per tenant schema by the tenant schema control plane, owns per-tenant DDL) |
| Build | Maven, JaCoCo coverage, SpotBugs, Failsafe ITs |
| External HTTP | Custom `OutboundHttpClient` with circuit-breaker + retry |

Package root: `com.prototype.vulnwatch`

---

## Authentication

### JWT modes and current authority

`APP_JWT_AUTH_MODE` selects `LOCAL` or `EXTERNAL` in `JwtDecoderConfig`. LOCAL uses a configured local issuer and at least 32 bytes of HMAC secret, without external issuer/JWK settings. EXTERNAL requires an issuer URI and no local HMAC secret; its JWK URI is optional. Both validate issuer, audience and `token_use=access`. Local login, setup and context-token issuance require LOCAL mode; EXTERNAL does not issue local tokens.

`JwtTenantAuthenticationService` checks the current ACTIVE user, stored global grants (including supported owner aliases/compatibility state), and current membership or support grant on each authentication. Human role claims do not create global grants or tenant membership. A stale PLATFORM_OWNER claim without current stored ownership is rejected. `TenantRolePolicy` allows only `TENANT_ADMIN`, `INVENTORY_ADMIN`, `SECURITY_ANALYST` and `READ_ONLY_AUDITOR` for membership assignment and consumption; platform, compatibility and machine roles cannot be assigned as tenant roles.

Tenant claims select a registered workspace; they do not authorize it. A platform owner entering a tenant must carry an explicit current membership or support mode/reference. Revoked/expired support or membership and inactive users fail on revalidation. SERVICE_ACCOUNT tokens must claim only that role and select an explicit tenant; `ServiceAccountJwtAuthorizationService` requires an ACTIVE, same-tenant registry entry keyed by the verified JWT subject. The registry key ID alone is not a credential.

### Local API-key compatibility

`ApiKeyAuthenticationFilter` still supports `X-API-Key` only when `APP_ALLOW_API_KEY_AUTH=true` and an actual `APP_API_KEY` is configured (empty by default). It grants OPERATOR/SECURITY_ANALYST; a matching `X-Creator-Key`, or an unconfigured creator key, additionally grants CREATOR/PLATFORM_OWNER/TENANT_ADMIN/INVENTORY_ADMIN. `X-User-ID` selects the local identity, default `local-analyst`. These are local compatibility authorities, not the deployed JWT authority model. Deployed validation rejects API-key auth and creator-key configuration. A Bearer failure never falls back to API-key authentication.

### Public and protected endpoints

`SecurityConfig` permits OPTIONS, health/readiness/liveness/info, POST login/setup-password/setup-session and demo-requests, GET `/api/auth/csrf`, and GET/POST demo-invite and tenant-invite exchange routes. Public exchange does not bypass token/lifecycle checks. Setup-password uses its setup cookie plus CSRF; verified header authentication bypasses CSRF only after successful authentication, with setup-password explicitly excluded.

Other actuator routes and `/api/**` require authentication, with additional route/controller/service checks. `/api/platform/**` and `/api/operations/**` require PLATFORM_OWNER; GET operations quality and software-identity search also admit the listed tenant reader/admin roles in `SecurityConfig`. `/api/auth/context` and `/api/me` require authentication. `/api/fix-intelligence/**` requires authentication (the former denyAll rule was removed when Fix Intelligence shipped); writes are role-checked in `FixIntelligenceController`. Static host-context evidence requires SERVICE_ACCOUNT plus producer/principal binding; runtime ingestion/read paths remain HTTP 410 / `RUNTIME_OUT_OF_SCOPE`.

## Tenant context and isolation

The servlet `TenantResolutionFilter` supplies only explicitly enabled local header/default-workspace compatibility before the security chain. JWT authentication installs the revalidated tenant ID/schema before downstream transactions. `TenantAwareDataSource` sets search path and tenant RLS context at connection acquisition; explicit platform work uses `platform,public`, and missing required tenant context uses a sentinel that matches no tenant. Reset failures or unfinished transactions evict/abort the physical connection. `TenantSchemaExecutionService` rejects a tenant/schema switch through its runner during an active transaction; establish platform scope before its transaction as well. Establish context before starting the transaction, including all async work.

`TenantLifecycleGuardService` denies non-ACTIVE/expired workspaces; `TenantStatusFilter` additionally reports a missing row as 410 and a blocked status as 423 for applicable API routes. Migration compatibility is checked separately at tenant request entry.

## Authorization Rules

The route summary above comes from `SecurityConfig`; controller roles, support restrictions and service-level capability checks also apply.

`TenantEntitlementService` uses one effective resolver for backend enforcement and the `/me` snapshot. Corrected precedence is an active tenant override, then plan value, then disabled default; expired overrides fall through. LEGACY and SHADOW retain legacy allow behavior; ENFORCE applies corrected decisions only to explicit tenant UUIDs or `slug:<tenant-slug>` cohort entries. Outside that cohort behavior remains SHADOW; null/platform snapshots are empty. Wildcards and invalid modes/cohorts are rejected. Deployed pilot startup requires ENFORCE and a named cohort (committed default `slug:scoutgrid-internal-pilot`); effective deployed settings still need qualification. Roles, lifecycle, provider availability and independent containment remain additional checks: an entitlement never enables generic Azure, runtime evidence or pilot generative assistance.

## Durable work, scheduling and delivery

`BackgroundTaskExecutionPolicy` requires an explicit `all`, `api`, `worker` or `schema-migrator` role. API and schema-migrator roles suppress background callbacks. All 36 cron annotations explicitly use UTC; the [schedule matrix](<../Working Knowledge/AWS/PHASE_3_SCHEDULE_MATRIX.md>) inventories the callbacks and their flags/ownership/recovery. Manual triggers commit durable intent even on API nodes; an eligible worker performs the work. Role defaults are configuration, not evidence of actual service topology.

Source mutations and their queue/projection intents share a transaction. `TenantWorkRunner` selects the tenant before opening each transaction. Accepted jobs retain attempt/claim/lease identity, heartbeat and commit fencing; bounded recovery excludes healthy owners and stale owners cannot publish. Delta queue work uses its existing attempt identity and row locks. Rollout tasks preserve the exact accepted assessment request through WAITING_FOR_ASSESSMENT, bounded failed retries, explicit retry and revocation. Four task executors drain accepted work with a bounded default 20-second wait; actual host termination grace remains unqualified.

`InvitationEmailOutboxService` persists encrypted immutable intent in `platform.invitation_email_outbox`; `CampaignEmailOutboxService` uses a separate tenant/RLS outbox. Retries reuse the logical delivery UUID/message, with at most eight automatic attempts and a conservative 23-hour replay cutoff. Uncertain acceptance becomes UNKNOWN for authorized operator reconciliation; provider acceptance does not prove inbox delivery. Terminal accepted/failed/cancelled payloads are removed. Expiry/rotation cancels never-attempted unavailable intent while preserving uncertain attempts and their outcomes. A late accepted old token cannot replace the current invitation, overwrite accepted/rejected request state or restore tenant access. There is no in-flight cancellation guarantee.

New invitation links carry a token in a URL fragment and exchange it by POST; persisted invitation records contain SHA-256 digests and cleared legacy raw token values. Legacy path links require controlled reissue. Setup-password uses a bounded setup session cookie and CSRF. Reissue, controlled delivery, legacy credential conversion and provider reconciliation in an environment remain separately authorized operations. See [cleanup bounds](<../Working Knowledge/AWS/PHASE_3_CLEANUP_MATRIX.md>) and [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).

---

## REST Controllers

67 controllers total (48 under `com.prototype.vulnwatch.controller`, described in this section, plus 19 under the separate `com.prototype.vulnwatch.aisecurity.controller` package, described in its own [AI Security / AI Grid](#ai-security--ai-grid) section below), verified against `@RequestMapping`/`@GetMapping`/etc. annotations directly (several base paths below differ from older drafts of this doc — connector controllers moved under a shared `/api/connectors/` prefix at some point, and quite a few controllers have grown far beyond simple CRUD).

### Assets / Ingestion

**AssetController — `/api/assets`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List tenant assets |
| POST | `/cmdb-sync` | Sync CMDB asset data |
| GET | `/assignment-groups` | List assignment groups |
| GET | `/assigned-to` | List assigned-to users |
| GET | `/hosts/{assetId}` | Get host detail by asset UUID |

Asset domain: `Asset` entity. Types: `AssetType` enum. Criticality: `BusinessCriticality` enum.

**IngestionController — `/api`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sbom-fetch` | Queue endpoint SBOM fetch job |
| GET | `/ingestions` | Paginated upload list, filterable by source system/date |
| POST | `/ingestion/nvd-sync` | Trigger NVD incremental sync (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/ingestion/nvd-full-sync` | Trigger NVD full sync (`PLATFORM_OWNER`) |
| POST | `/ingestion/nvd-cve/{cveId}` | Refresh single CVE from NVD (`PLATFORM_OWNER`) |
| POST | `/ingestion/kev-sync` | Trigger CISA KEV sync (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/ingestion/ghsa-sync` | Trigger GHSA sync (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/ingestion/euvd-sync` | Trigger EUVD sync (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/ingestion/jvn-sync` | Trigger JVN sync (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/ingestion/csaf/microsoft-sync` | Trigger Microsoft CSAF sync (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/ingestion/csaf/redhat-sync` | Trigger Red Hat CSAF sync (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/ingestion/vex-assertion-repair` | Repair VEX assertions (`PLATFORM_OWNER`) |
| POST | `/ingestion/vex-rollout-backfill` | VEX rollout backfill (`PLATFORM_OWNER`) |
| GET | `/ingestion/vex-assertion-repair/summary` | Get VEX repair summary |
| POST | `/ingestion/advisories` | Ingest advisory batch (`PLATFORM_OWNER`) |

Supported SBOM formats (`SbomFormat` enum): CycloneDX, SPDX.

**IngestionJobController — `/api/ingestion-jobs`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{jobId}` | Get job status by UUID |
| GET | `/` | Paginated list of ingestion jobs |

**GithubSbomSourceController — `/api/github-sbom-sources`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List configured GitHub SBOM sources |
| POST | `/` | Create source (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| PUT | `/{id}` | Update source config |
| DELETE | `/{id}` | Delete source |
| POST | `/ghcr/run` | Trigger GHCR ingestion once |
| POST | `/repository/run` | Trigger repository SBOM ingestion |
| POST | `/{id}/run` | Trigger a specific source's sync |

`GithubSbomSource` entity. Frequency: `GithubIngestionFrequency` enum (EVERY_5_MIN, HOURLY, DAILY).

For saved-source and standalone repository runs, `assetsIngested` counts repositories that successfully ingested an SBOM. A partially successful run reports its repository failures separately.

**BomController — `/api/bom`** *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| POST | `/fetch` | Fetch BOM from URL (`INVENTORY_ADMIN`/`TENANT_ADMIN`/`CREATOR`) |
| POST | `/upload` | Upload BOM file (multipart; same roles as `/fetch`) |
| GET | `/sources` | List BOM sources |
| GET | `/inventory` | Paginated BOM inventory list |
| GET | `/components` | Paginated BOM components list |
| GET | `/components/{componentId}` | Get component detail |
| GET | `/assets/{assetId}/cves` | Get application CVEs for an asset |
| GET | `/application-risk` | Application risk summary |
| GET | `/dashboard` | BOM dashboard metrics |
| GET | `/support` | BOM support matrix |
| GET | `/inventory/{bomId}` | Get single BOM detail |
| GET | `/inventory/{bomId}/lineage` | Get BOM lineage |
| DELETE | `/inventory/{bomId}` | Soft-delete a BOM (`INVENTORY_ADMIN`/`TENANT_ADMIN`/`CREATOR`) |

**AiBomDeclaredResourceController — `/api/bom/declared-resources`** — declared AI-BOM models/datasets. Reads (`SECURITY_ANALYST`/`INVENTORY_ADMIN`/`TENANT_ADMIN`/`CREATOR`/`OPERATOR`): `GET /`, `/setup-actions`, `/{resourceId}`, `/{resourceId}/findings`, `/{resourceId}/correlation`. Reviewed deployment-mapping workflow: `POST /{resourceId}/mapping/propose` (adds `SECURITY_ANALYST`), `/mapping/approve` and `/mapping/remove` (`INVENTORY_ADMIN`/`TENANT_ADMIN`/`CREATOR`), all `@SensitiveTenantAction`.

**CbomController — `/api/bom/cbom`** *(undocumented until now — cloud/container BOM posture tracking)*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/posture` | List CBOM posture summary |
| GET | `/posture/{assetId}` | Get asset CBOM posture |
| GET | `/components` | List components for an asset |
| GET | `/findings` | List risk findings for an asset |
| POST | `/findings/{findingId}/accept` | Accept a finding (`SECURITY_ANALYST`/`TENANT_ADMIN`/`CREATOR`) |

### Inventory

**InventoryController — `/api/inventory`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/components` | Paginated components (filters: assetType, status, sourceSystem, ecosystem, …) |
| GET | `/components/filters` | Available filter values |
| GET | `/software-identities` | Paginated software identities |
| GET | `/software-identities/funnel` | Software identity funnel analytics |
| GET | `/software-identities/{id}` | Get software identity detail |
| GET | `/software-identities/{id}/metadata` | Get software identity metadata |
| PUT | `/software-identities/{id}/metadata` | Save metadata (`@SensitiveTenantAction`) |

`InventoryComponent` entity. CPE mappings via `InventoryComponentCpeMap`.

### Vulnerabilities / Intelligence

**VulnerabilityController — `/api/vulnerabilities`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{externalId}` | Get vulnerability detail by CVE ID |

**VulnerabilityIntelligenceController — `/api/vulnerability-intelligence`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Paginated intel list (filters: query, severity, source, inKev, …) |
| GET | `/sources` | List available vulnerability sources |
| GET | `/filters` | Available filter values |
| GET | `/{externalId}` | Get vulnerability intel detail |
| GET | `/org-cves` | Paginated org-specific CVE exposure |
| GET | `/org-cves/status` | Get org CVE automation status |
| POST | `/org-cves/recompute` | Recompute org-specific CVEs (`TENANT_ADMIN`/`SECURITY_ANALYST`) |
| POST | `/org-cves/refresh` | Refresh tenant exposure (`TENANT_ADMIN`/`SECURITY_ANALYST`) |

Backed by `vulnerability_intel_summary` + `vulnerability_intel_observations` projections.

**GithubAdvisoryPlatformController — `/api/platform/ghsa`** (`PLATFORM_OWNER`) — `GET /sync-status`, `POST /sync/trigger`, `GET /health`.

**GithubAdvisoryTenantController — `/api/tenants/{tenantId}/ghsa`** (`TENANT_ADMIN`/`INVENTORY_ADMIN`/`PLATFORM_OWNER`) — per-tenant GHSA integration: `GET /integration-status`, `POST /enable`, `POST /disable`, `PUT /settings`, `GET /advisories`, `GET`/`DELETE /component-advisories/{sourceId}`, `POST /correlate/{sourceId}`.

**OsvTenantController — `/api/tenants/{tenantId}/osv`** (`TENANT_ADMIN`/`INVENTORY_ADMIN`/`SECURITY_ANALYST`) — `GET /component-advisories`, `GET /coverage`.

### Findings

**FindingController — `/api/findings`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Paginated findings (cursor/limit or page/size) |
| GET | `/groups` | Grouped findings |
| GET | `/summary` | Finding summary metrics |
| GET | `/distributions` | Finding distribution analytics |
| GET | `/backlog-health` | Backlog health metrics |
| GET | `/projection-status` | Finding projection status (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/projection-rebuild` | Rebuild finding projection (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| GET | `/queues` | List saved finding queues |
| GET | `/queues/{queueKey}` | Get queue definition |
| POST | `/queues` | Create queue (`TENANT_ADMIN`/`SECURITY_ANALYST`) |
| PUT | `/queues/{queueRef}` | Update queue |
| POST | `/queues/{queueRef}/duplicate` | Duplicate queue |
| POST | `/queues/{queueRef}/default` | Set default queue |
| DELETE | `/queues/{queueRef}` | Delete queue |
| GET | `/filters` | Available filters |
| GET | `/{findingId}` | Get finding by UUID |
| PUT | `/{findingId}/workflow` | Update finding workflow (status, assignee, etc.) |
| POST | `/bulk-workflow` | Bulk update workflow |
| DELETE | `/bulk` | Bulk delete findings |

`Finding` entity. Status: `FindingStatus` enum (OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, SUPPRESSED, FALSE_POSITIVE, RISK_ACCEPTED). Decision state: `FindingDecisionState`. Creation source: `FindingCreationSource` enum.

**CveDetailController — `/api/cve-detail`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{cveId}` | Full CVE detail (summary, signals, investigations, assessments) |
| GET | `/{cveId}/vex-evidence` | Get VEX evidence for a component |
| POST | `/{cveId}/investigation` | Create investigation |
| PUT | `/investigation/{investigationId}` | Update investigation |
| POST | `/{cveId}/investigation/submit` | Upsert investigation |
| POST | `/{cveId}/assessment/submit` | Upsert applicability assessment |
| POST | `/{cveId}/applicability-assessment` | Create assessment |
| PUT | `/applicability-assessment/{assessmentId}` | Update assessment |
| POST | `/applicability-assessment/{assessmentId}/complete` | Complete assessment |
| POST | `/{cveId}/manual-finding` | Create manual finding |
| POST | `/{cveId}/suppress` | Suppress CVE org-wide |
| POST | `/{cveId}/export` | Export CVE report (`…`/`READ_ONLY_AUDITOR`) |
| POST | `/{cveId}/investigation-summary` | Generate deterministic investigation summary |
| POST | `/{cveId}/investigation-ai-summary` | Generate AI investigation summary (OpenAI) |
| GET | `/{cveId}/saved-investigation-summary` | Get saved investigation summary |
| GET | `/{cveId}/fixes` | Get previously generated fix records |
| GET | `/software-fixes` | Get fix records by software name |
| POST | `/{cveId}/generate-fixes` | Generate AI fix records |
| POST | `/{cveId}/analyst-fixes` | Save analyst-entered fixes |
| GET | `/{cveId}/ai-solution` | Get saved AI remediation recommendation |
| POST | `/{cveId}/ai-solution` | Generate AI solution |
| GET | `/{cveId}/ai-actions` | Get saved AI required actions |
| POST | `/{cveId}/ai-actions` | Generate AI actions |
| GET | `/{cveId}/investigation/runbook` | Get investigation runbook |
| PUT | `/{cveId}/investigation/runbook` | Save runbook |
| POST | `/{cveId}/investigation/log` | Append runbook log entry |
| POST | `/{cveId}/investigation/resolve-inventory` | Resolve inventory criteria |
| POST | `/{cveId}/investigation/confirm-applicability` | Confirm applicability |
| POST | `/{cveId}/investigation/false-positive-analysis` | Analyze false positives |
| POST | `/{cveId}/investigation/eol-analysis` | Analyze EOL status |
| POST | `/{cveId}/investigation/run-agent` | Run investigation agent |
| GET | `/{cveId}/advisory-equivalences` | Advisory equivalence groups for a CVE (`TENANT_ADMIN`/`INVENTORY_ADMIN`/`SECURITY_ANALYST`) |

`OrgCveRecord` entity stores per-tenant CVE state. `OrgCveAiArtifact` stores persisted AI outputs. Most write endpoints require `TENANT_ADMIN`/`SECURITY_ANALYST`.

**ServiceNowIncidentController — `/api/cve-detail`** (separate controller, same base path)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/servicenow/assignment-groups` | List assignment groups from ServiceNow |
| POST | `/{cveId}/servicenow-incident` | Create remediation ticket(s) for a CVE — path and response shape unchanged, but routed to the tenant's active ticketing system (Jira overrides ServiceNow) |
| POST | `/{cveId}/ticket` | Provider-neutral equivalent; each response names the system holding the ticket |

### Dashboards

**DashboardController — `/api/dashboard`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Main dashboard summary |
| GET | `/exposure-summary` | Exposure summary |
| GET | `/applicable-software` | Paginated applicable software |
| GET | `/impacted-cves` | Paginated impacted CVEs |
| GET | `/cve-inventory-map` | CVE-to-inventory mapping |
| GET | `/grid-exposure` | Grid exposure matrix |

Results are cached in memory (Caffeine).

**VulnRepoDashboardController — `/api/vuln-repo`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Vulnerability repo dashboard |
| GET | `/vulnerabilities` | List vulnerabilities (filterable) |
| GET | `/org-cves` | List org-specific CVEs |
| GET | `/org-cves/status` | CVE automation status |
| POST | `/org-cves/recompute` | Recompute org CVEs |
| POST | `/org-cves/refresh` | Refresh tenant exposure |
| GET | `/software-assets/{softwareIdentityId}` | Get software assets |

**OperationalDashboardController — `/api/operations`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Operational dashboard |
| GET | `/overview` | Operational overview |
| GET | `/ingestion-efficiency` | Ingestion efficiency metrics |
| GET | `/normalization-quality` | Normalization quality metrics |
| GET | `/correlation-effectiveness` | Correlation effectiveness metrics |
| GET | `/noise-lifecycle` | Noise lifecycle metrics |
| GET | `/api-read-path` | API read path metrics |
| GET | `/freshness-drift` | Freshness drift metrics |
| GET | `/metric-catalog` | Metric catalog |
| GET | `/performance-scorecard` | Performance scorecard |
| GET | `/tenant-attention` | Tenants needing attention |
| GET | `/connector-issues` | Connector issues |
| GET | `/quality/summary` | Quality summary |
| GET | `/quality/issues` | Paginated quality issues |
| GET | `/quality/issues/{issueId}` | Quality issue detail |
| GET | `/quality/filters` | Quality filter values |

Requires `ROLE_PLATFORM_OWNER` (plus `TENANT_ADMIN`/`INVENTORY_ADMIN`/`SECURITY_ANALYST`/`READ_ONLY_AUDITOR` for `/quality/**`).

### End of Life

**EolController — `/api/eol`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status/summary` | EOL summary counts |
| GET | `/status/components` | Paginated component EOL statuses |
| GET | `/status/packages` | Paginated package EOL statuses |
| GET | `/status/packages/assets` | Assets with a given package installed |
| GET | `/products` | List all EOL products |
| GET | `/products/{slug}/releases` | List releases for a product |
| GET | `/mappings/suggestions` | AI-suggested EOL slugs for unmatched components |
| GET | `/mappings/unresolved` | Paginated unresolved mappings |
| POST | `/mappings/confirm` | Confirm/reject a suggested EOL mapping (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/catalog` | Trigger catalog refresh (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/releases` | Trigger release refresh (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/mappings` | Trigger mapping resolve (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/denormalize` | Trigger denormalize (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/full` | Trigger full refresh (`PLATFORM_OWNER`) |

`EolProductCatalog`, `EolRelease`, `SoftwareEolMapping` entities. Data sourced from endoflife.date API.

### Policy / Rules

**RiskPolicyController — `/api/risk-policy`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get tenant risk policy |
| POST | `/` | Update risk policy (`TENANT_ADMIN`) |
| POST | `/recompute-findings-scores` | Recompute all finding scores (`TENANT_ADMIN`) |
| POST | `/auto-close/execute-now` | Run the auto-close job immediately (`TENANT_ADMIN`) |

`RiskPolicy` entity. Fields include: `sla*`, `triage*` (6 weight fields), `autoClose*`, `findingGenerationMode`, `findingsScoreConfig` (JSONB).

**SuppressionRuleController — `/api/suppression-rules`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List suppression rules |
| POST | `/` | Create rule (`TENANT_ADMIN`) |
| PUT | `/{id}` | Update rule |
| DELETE | `/{id}` | Delete rule |
| POST | `/{id}/execute` | Execute a rule immediately |
| POST | `/{id}/reopen-all` | Reopen findings suppressed by a rule |
| POST | `/cve-reopen/{recordId}` | Reopen a specific suppressed CVE record |

All write endpoints require `TENANT_ADMIN`. `SuppressionRule` entity. States: DRAFT, APPROVED, IN_REVIEW, REJECTED, EXPIRED. Types: CVE, FINDING.

**OwnershipRuleController — `/api/ownership-rules`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List ownership rules |
| POST | `/` | Create rule (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| PUT | `/{id}` | Update rule |
| DELETE | `/{id}` | Delete rule |
| POST | `/apply` | Apply all rules |
| POST | `/{id}/apply` | Apply a specific rule |

`OwnershipRule` entity. Conditions stored as JSONB. Evaluated by priority to auto-assign findings. This is the legacy model; it stays until each tenant's CORE ownership cutover. The UI shows it as "Legacy rules" in the Ownership & Directory hub.

**Ownership and directory controllers (ownership MVP Release 1)**

Every method is guarded by `@PreAuthorize("@ownershipAuthorization.can('ACTION')")`. `OwnershipAuthorization` holds the role matrix; an unknown action is denied. Wrong-tenant IDs return 404. Directory writes return 503 when the tenant data key is not ready.

| Action | Roles |
|---|---|
| `VIEW_OWNERSHIP` | `TENANT_ADMIN`, `INVENTORY_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_AUDITOR` |
| `VIEW_DIRECTORY` | `TENANT_ADMIN`, `INVENTORY_ADMIN`, `SECURITY_ANALYST` |
| `MANUAL_ASSIGN` | `TENANT_ADMIN`, `INVENTORY_ADMIN`, `SECURITY_ANALYST` (the service limits analysts to an open finding assigned to them) |
| `WRITE_TEAMS`, `REVOKE_ASSIGNMENT`, `RESOLVE_REVIEW` | `TENANT_ADMIN`, `INVENTORY_ADMIN` |
| `WRITE_DIRECTORY`, `IMPORT_DIRECTORY`, `MANAGE_ENCRYPTION`, `MANAGE_AUTHORITY` | `TENANT_ADMIN` |
| `INGEST_CLAIMS` | `SERVICE_ACCOUNT` (no endpoint yet) |

`DirectoryController` — `/api/directory`

| Method | Path | Action | Description |
|---|---|---|---|
| GET | `/users`, `/users/{id}` | `VIEW_DIRECTORY` | Search people (name prefix from 2 letters) or read one; email and employee ID are masked |
| POST, PATCH | `/users`, `/users/{id}` | `WRITE_DIRECTORY` | Add a person; update details, manager or status (PATCH requires the loaded `version`) |
| GET | `/groups`, `/groups/{id}/members` | `VIEW_DIRECTORY` | List groups and members |
| POST, PATCH | `/groups`, `/groups/{id}` | `WRITE_DIRECTORY` | Create a group; update or deactivate/reactivate |
| POST, DELETE | `/groups/{id}/members`, `/groups/{id}/members/{userId}` | `WRITE_DIRECTORY` | Add or remove a member |
| GET | `/imports/templates/{kind}` | `IMPORT_DIRECTORY` | CSV template |
| POST | `/imports/preview` | `IMPORT_DIRECTORY` | Dry run (multipart); records a `VALIDATED` import run and returns a preview token |
| POST | `/imports/{previewToken}/commit` | `IMPORT_DIRECTORY` | Commit the same file (same SHA-256, tenant and importer, within 30 minutes); one transaction per row |

`OwnershipAdminController` — `/api/ownership`

| Method | Path | Action | Description |
|---|---|---|---|
| GET | `/teams`, `/teams/{id}`, `/teams/{id}/aliases` | `VIEW_OWNERSHIP` | Teams (search, active/archived) and aliases |
| POST, PATCH | `/teams`, `/teams/{id}` | `WRITE_TEAMS` | Create; rename, set parent team and ticket group, archive/restore. PATCH requires the loaded `version` and returns 409 if the team changed |
| POST, DELETE | `/teams/{id}/aliases`, `/teams/{id}/aliases/{aliasId}` | `WRITE_TEAMS` | Add or remove an alias (shared namespace with team names) |
| GET | `/review-items` | `VIEW_OWNERSHIP` | Review queue by status and type |
| PATCH | `/review-items/{id}` | `RESOLVE_REVIEW` | Resolve or dismiss with a note |
| GET, POST | `/encryption`, `/encryption/provision` | `MANAGE_ENCRYPTION` | Tenant data-key readiness; provision the tenant key |
| GET | `/authority/{domain}/qualification` | `MANAGE_AUTHORITY` | Cutover qualification report and legacy-vs-canonical comparison |
| POST | `/authority/{domain}` | `MANAGE_AUTHORITY` | Move LEGACY → DARK, or DARK → CANONICAL with the passing report hash; CANONICAL cannot be reverted |

`OwnershipReadController` — `/api/ownership` (`VIEW_OWNERSHIP`): GET `/assets?ids=` and `/findings?ids=` return ownership envelopes for a batch of IDs; GET `/assets/filter` and `/findings/filter` (`ownerTeamId`, `status`, `after`, `limit` default 100) return matching IDs in keyset pages; GET `/coverage?consumer=INVENTORY|FINDINGS` returns coverage counts and the authority state. Filters and coverage use the effective cache when it is enabled.

`OwnershipSubjectController` — `/api/ownership/subjects/{type}/{id}`: GET (explanation, `VIEW_OWNERSHIP`); POST `/manual-assignment/preview` and `/manual-assignment` (`MANUAL_ASSIGN`; reason required, expiry at most 30 days, impact preview capped at 100 descendants or 1,000 findings); POST `/manual-assignment/revoke` (`REVOKE_ASSIGNMENT`). Assignment and revocation return 409 unless the subject's domain is CANONICAL.

`GET /api/findings` accepts `ownerTeamId` and `ownershipStatus` (`OWNED`, `UNOWNED`, `CONFLICT`) on the cursor/projection path for VULNERABILITY findings. They return 409 while findings ownership is not canonical, 400 for an unknown status, and 400 on the offset/JPA paging path.

**VulnerabilitySourceFilterConfigController — `/api/connectors/vulnerability-sources`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List all source filter configs |
| GET | `/{sourceSystem}` | Get config for a source (nvd, ghsa, etc.) |
| PUT | `/{sourceSystem}` | Save config (`PLATFORM_OWNER`/`TENANT_ADMIN`/`SECURITY_ANALYST`) |

Per-tenant configuration of which vulnerability intelligence sources participate in correlation.

### Remediation Campaigns

**CampaignController — `/api/campaigns`** *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List campaigns (optional status filter) |
| GET | `/{campaignId}` | Get campaign detail |
| POST | `/` | Create campaign |
| POST | `/{campaignId}/status` | Update campaign status |
| POST | `/{campaignId}/notes` | Add note |
| POST | `/{campaignId}/exceptions` | Add exception |
| POST | `/{campaignId}/exceptions/{exceptionId}/status` | Update exception status |
| POST | `/{campaignId}/notify-groups/{notifyGroupId}` | Update notify group |
| POST | `/{campaignId}/watchlist/{watchlistEntryId}` | Update watchlist entry |
| POST | `/{campaignId}/ai-insights` | Generate AI insights (`CampaignAiService`) |
| POST | `/{campaignId}/ai-advisories` | Generate AI advisories |

All write endpoints: `PLATFORM_OWNER`/`TENANT_ADMIN`/`SECURITY_ANALYST`.

### Fix Intelligence

**FixIntelligenceController — `/api/fix-intelligence`** serves `GET /summary`, `/fixes`, `/fixes/{id}` and `/context` to every tenant role. `POST /fixes` and `PUT /fixes/{id}` need `TENANT_ADMIN` or `SECURITY_ANALYST`; `POST /fixes/{id}/approve` and `/retire` need `TENANT_ADMIN`, and the approver must differ from the proposer. Reads are tenant-filtered SQL in `service/fix/FixIntelligenceQueryService`; writes are in `FixManagementService`. Fixes are remediation context only and never change finding status.

The independent CVE Workbench `FixRecordService` remains subject to normal authorization and deterministic/generative policy. Unwired patch entities (`AssetFixStatus`, `CveFixMap`, `PatchConnectorCredential`, `JiraIssueBacklog`) lack backing migrations; `.disabled` patch scheduling/registration files are excluded from the build.

**P30 frontend containment:** unsupported patch catalog entries, detail mounts and four mock modules have been retired, removing their input/credential logging. Query IDs are rejected and direct paths cannot mount the forms. [Repair evidence](<../Working Knowledge/AWS/DOCUMENTATION_RECONCILIATION.md#p30-frontend-repair>) records the new frontend regressions/gates; backend containment is unchanged. No patch backend integration was added.

### AI Security / AI Grid

19 controllers under `com.prototype.vulnwatch.aisecurity.controller` (separate package from the rest of this doc — see [Service Layer](#ai-security--ai-grid-service-layer) below for the full pipeline). Tenant-facing endpoints additionally require the `ai.security` tenant entitlement (`AiSecurityAccessService.assertEntitled`); the global `/api/ai-frameworks` reference endpoint is the deliberate exception because platform owners need it before selecting a tenant. `SecurityConfig` has no dedicated path rule for `/api/ai-security/**` or `/api/ai-grid/**` — authorization is per-endpoint `@PreAuthorize` or service-level entitlement under the generic authenticated-`/api/**` rule. Two of the 19 — `AiGridPhase1PreviewController` (`/api/platform/ai-grid/releases/phase-1/preview`) and `AiGridPhase1ReleaseBoardController` (`/api/platform/ai-grid/releases/phase-1`) — aren't itemized below; read them directly if you need their surface. `AiGridPolicyRolloutController` (`/api/platform/ai-grid`) exposes `GET /policies/shipping-status`, `GET /policy-rollouts[/{rolloutId}]`, and `POST /policy-rollouts/{rolloutId}/retry` over `AiGridPolicyRolloutService` (the scheduled drain is in the Scheduled Jobs table).

**AiSecurityController — `/api/ai-security`** (shared artifact/finding/graph/run API — reads open to entitled callers; finding review mutations `PLATFORM_OWNER`/`TENANT_ADMIN`/`SECURITY_ANALYST`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/summary` | Artifact/finding counts, incomplete-scope counts |
| GET | `/artifacts`, `/artifact-summaries` | Paginated artifact list / summary projection |
| GET | `/inventory/knowledge-data`, `/inventory/mcp` | Knowledge-source / MCP-server artifact inventory |
| GET | `/artifacts/{id}`, `/artifacts/{id}/versions`, `/artifacts/{id}/relationships` | Artifact detail, versions + relationships |
| GET | `/artifacts-export` | Artifact CSV export |
| GET/PUT | `/agent-deployment/settings` | Agent deployment settings (PUT: `PLATFORM_OWNER`/`TENANT_ADMIN`) |
| GET | `/artifacts/{id}/activity-evidence` | Curated, expiring `activity.*` host-context facts for one artifact (latest 100 by `observed_at`), each flagged `expired` when `valid_until` has passed. Advisory only — see [AWS activity evidence](#aws-activity-evidence). Currently returns HTTP 410 `RUNTIME_OUT_OF_SCOPE` (`AiRuntimeScope`) |
| GET | `/graph` | Artifact relationship graph |
| GET | `/severity-grid`, `/top-risk-artifacts` | Inventory rollups |
| GET | `/findings`, `/findings/{id}` | AI policy-failure findings |
| PUT | `/findings/{id}/review` | Set review disposition (CONFIRMED/FALSE_POSITIVE/NEEDS_INVESTIGATION) |
| GET | `/runs`, `/runs/{id}/scopes` | Discovery run history + per-scope detail |

**AiSecurityConnectorController — `/api/connectors/ai-security/aws`** — AWS Bedrock connector config. Requests require the tenant's AI Security entitlement. Writes require `PLATFORM_OWNER`, `TENANT_ADMIN` or `INVENTORY_ADMIN`. `GET` returns HTTP 200 with `application/json` and either the saved configuration or the JSON literal `null` for an unconfigured connector. Other operations are `PUT` config, `GET /requirements`, `POST /test`, `POST /preflight` and `POST /run`.

**AiSecurityAzureConnectorController — `/api/connectors/ai-security/azure`** — multi-step Azure connector (credential profiles + connector config): list/save connector, `/requirements`, `/{id}/test`, `/{id}/run`, `/targets/{id}/run`, plus `/credentials` CRUD + test/rotate/revoke.

**AiSecurityAzureFoundryConfigController — `/api/connectors/ai-security/azure-foundry`** — newer single-form Azure setup orchestrating config+target+credential+connector in one save. `GET`, `PUT`, `POST /test`, `POST /run`, `POST /runtime-run` (HTTP 410 while runtime is out of scope).

**AiSecurityConnectorFeatureFlagController — `/api/connectors/ai-security/feature-flags`** — `GET /` list, `PUT /{feature}` (`PLATFORM_OWNER`/`TENANT_ADMIN`/`INVENTORY_ADMIN`).

**CopilotStudioConnectorController — `/api/connectors/ai-security/copilot-studio`** — `GET /`, `PUT /` save, `POST /{connectorId}/test`, `POST /{connectorId}/run` (writes `PLATFORM_OWNER`/`TENANT_ADMIN`/`INVENTORY_ADMIN`), `POST /{connectorId}/runtime-run` (HTTP 410 while runtime is out of scope).

**AiSecurityDigestBaselineController — `/api/ai-security/artifacts/{artifactId}/digest-baselines`** — `GET /`, `/observations`, `/history`; `POST /approve`, `/reapprove`, `/revoke`, `/approve-observation` (`PLATFORM_OWNER`/`TENANT_ADMIN`/`SECURITY_ANALYST`).

**AiGridController — `/api`** — the main AI Grid read/write API.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ai-systems`, `/ai-systems/{id}` | Agent-rooted AI system list/detail |
| GET | `/ai-systems/{id}/facts`, `/graph`, `/lineage`, `/findings` | Per-system detail views |
| POST | `/ai-systems/{id}/memberships` | Adjust system membership |
| POST | `/ai-artifacts/{id}/host-context` | Ingest CIEM/DSPM/ASM/runtime host-context evidence |
| PUT | `/ai-artifacts/{id}/owner` | Confirm artifact owner (`TENANT_ADMIN`+) |
| GET | `/ai-exposures`, `/ai-exposures/{id}` | Validated cross-system exposure list/detail |
| POST | `/ai-exposures/{id}/disposition` | Accept / false-positive an exposure |
| GET | `/ai-coverage[/details,/dimensions]` | Coverage-gap rollups |
| GET | `/ai-frameworks` | Global framework/control registry; authenticated platform owners can read it without selecting a tenant |
| GET | `/ai-framework-coverage?framework=&version=` | Tenant framework breadth/effective coverage for the current or requested retained coverage epoch |
| GET | `/ai-policy-readiness`, `/ai-setup-actions` | Per-policy readiness + prioritized setup queue |
| GET | `/ai-runtime-telemetry-readiness` | Tenant Program 2 numeric entry gate over the rolling pilot window (HTTP 410 while runtime is out of scope) |
| GET | `/ai-assessment-states/latest` | Latest per-policy-version totals in the customer vocabulary PASS/FAIL/UNKNOWN/NOT_ASSESSED |
| GET | `/ai-assessment-runs`, `/ai-assessment-runs/{id}/metrics` | Run history + economics telemetry |
| POST | `/ai-assessment-runs/{id}/replay` | Re-run the latest assessment after a policy edit |
| GET | `/ai-policies`, `/ai-policies/{id}` | Canonical governed policy summaries and rich policy detail |
| PUT | `/ai-policies/{id}/selection` | Change REQUIRED/ENABLED/PREVIEW/DISABLED selection (`TENANT_ADMIN`+) |
| POST | `/ai-policies/enable-all` | Enable every distributed policy whose effective selection changes; admin-only, audited, and refreshes projections only when needed |
| GET/PUT | `/ai-policies/{id}/configuration` (GET only), `/scope`, `/parameters` (PUT) | Governed policy configuration |
| POST/DELETE | `/ai-policies/{id}/exceptions[/{artifactId}]`, `POST /ai-policies/{id}/exception-rules` | Governed per-artifact exception / exception rule |
| GET | `/ai-policies/{id}/assist/explain` | Policy explanation using governed configuration |
| GET/PUT/POST | `/ai-approved-manifests[...]`, `/ai-component-allowlist[...]` | Tenant V2 approved agent-version manifests and component allowlist; writes/revocations are admin-only sensitive actions |
| GET | `/ai-overview` | Explainable prioritized exposure-intelligence overview |
| GET | `/ai-exposure-priorities`, `/ai-action-queue`, `/ai-assets/{id}/posture`, `/ai-changes`, `/ai-connector-capabilities` | Prioritized exposures, action queue, per-asset posture, change feed, connector capability matrix |
| POST/GET | `/ai-assessments/execute`, `/ai-assessments/{runId}/status`, `/ai-assessments/requests/{requestId}/retry`, `/ai-policies/{id}/assessment-status` | On-demand assessment execution/status/retry (writes `PLATFORM_OWNER`/`TENANT_ADMIN`/`SECURITY_ANALYST`) |
| GET | `/ai-policies/{id}/versions` | Policy version history |

**AiGridEvidenceIngestionController — `/api/internal/ai-grid/evidence`** — `POST /{producerId}`, `ROLE_SERVICE_ACCOUNT` only, principal must equal `producerId`. Trusted third-party evidence ingestion port.

**AiGridRuntimeIngestionController — `/api/internal/ai-grid/runtime`** — *currently returns HTTP 410 `RUNTIME_OUT_OF_SCOPE` (`AiRuntimeScope.requireInScope()`); the description below is the deferred design.* `POST /{producerId}/v1/batches`, `ROLE_SERVICE_ACCOUNT` only, principal must equal `producerId` — the governed customer-telemetry adapter for frameworks/gateways/enforcement points that can supply consequential-action decisions a provider connector cannot. Body is a raw metadata-only batch (JSON); `AiGridRuntimeIngestionService.accept()` enforces, in order, a 2 MiB body cap, a 100-execution-per-batch cap, then the existing per-execution event/metadata limits, and recursively rejects any forbidden raw-content field (prompt/response/argument/credential/document/message-body/raw-payload). Returns `202 Accepted` with an `AdmissionResult` (receipt ID, accepted/duplicate/quarantined counts) or `429` + `Retry-After` on backlog or per-tenant quota exhaustion.

**AiGridRuntimeIngestionReceiptController — `/api/ai-security/runtime-ingestion/receipts`** — `GET /{receiptId}` (receipt lookups are deferred with the runtime adapter), ordinary tenant auth + entitlement, `404` if the receipt doesn't belong to the caller's tenant. Lets a producer or operator poll a submitted batch's processing status.

**AiAgentExecutionController — `/api/ai-security/executions`** — read-only, tenant- and entitlement-scoped access to collected runtime metadata. All three endpoints currently return HTTP 410 `RUNTIME_OUT_OF_SCOPE`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Paginated execution metadata, filterable by agent, version, status, source, and time window |
| GET | `/{executionId}/timeline` | Bounded metadata-only event timeline for one execution |
| GET | `/{executionId}/relationships` | Inventory relationships correlated to one execution |

**AiGridFindingIncidentController — `/api/findings`** — `POST /{findingId}/servicenow-incident` (not AI-specific despite living in this package; kept for existing clients and routed through `TicketingService`, so it lands in whichever system the tenant has active).

**FindingTicketController** — `GET /api/ticketing/status` (active provider, configured providers, and which ones the active provider overrides) and `POST /api/findings/{findingId}/ticket` (`PLATFORM_OWNER`/`TENANT_ADMIN`/`SECURITY_ANALYST`; provider-neutral body, response names the provider, key, URL and status).

**AiGridOperationsGovernanceController — `/api/ai-governance`** — tenant scan budget & retention operations. Reads `TENANT_ADMIN`+`SECURITY_ANALYST`; writes `PLATFORM_OWNER`/`TENANT_ADMIN`. `GET`/`PUT /budget`, `PUT /cadence`, `POST /budget-alerts/{id}/acknowledge`, `GET /retention`, `PUT /retention/policies`, `POST /retention/holds[/…/release]`, `POST /retention/sweep`.

**AiGridPolicyCatalogController — `/api/platform/ai-grid/policies`** (`PLATFORM_OWNER` only) — policy package import/distribution/rollout and portfolio. `GET /` list, `GET /{policyId}/versions/{version}` detail, `PUT /{policyId}/distribution`.

**AiGridValidationGovernanceController — `/api/platform/ai-grid/validation`** (`PLATFORM_OWNER` only) — answer-key/precision/bias review, policy-ID lifecycle, and R1/R2 release certification. `GET/POST /answer-keys[...]`, `POST /precision-reviews[...]`, `POST /policies/{id}/approve`, `POST /policies/{id}/dev-deploy`, `POST /policies/{id}/publish`, `POST /policies/{id}/deprecate`, and `POST /release-bindings/{id}/revoke`; legacy version-keyed digest/readiness/publish routes return an explicit migration error. DEV is reachable only through `dev-deploy` with a cohort and pinned approved version; `publish` performs CANARY (`publishAll=false`) or GA (`publishAll=true`). The catalog distribution endpoint intentionally rejects DEV and exposure-increasing writes. `GET/POST /releases/r1/*`, `GET/POST /releases/r2/*` remain available.

### GCP Cloud Discovery

**GcpDiscoveryController — `/api/connectors/gcp-discovery`** (same shape, roles, audit events and demo block as AWS): `GET /`, `PUT /` (body `credentialJson` = the customer's service account key, required on first save, write-only, omitted to keep the stored key; first save adds the key's project as a target), `POST /test`, `POST /sync`, `GET /sync/status`, `GET/POST /targets`, `PUT/DELETE /targets/{id}`, `POST /targets/{id}/test`, `POST /targets/{id}/sync`. Writes require `TENANT_ADMIN`/`INVENTORY_ADMIN`.

Credentials: the key is validated by `GcpServiceAccountKey` (only `service_account` keys with `token_uri` = `https://oauth2.googleapis.com/token` and the `googleapis.com` universe), encrypted with `CredentialEncryptionService`, and exchanged for 1-hour tokens by `GoogleGcpTokenSource`. A connector without a key refuses test, admission and execution.

Collection (`GcpDiscoveryClient`, REST through `OutboundHttpClient` provider `gcp`): Compute `aggregated/instances` (with `returnPartialSuccess`; unreachable zones make the listing incomplete), VM Manager inventories per zone, Cloud Asset `searchAllResources` for the selected types, and Resource Manager `testIamPermissions` for the per-permission test. Listings stop after 200 pages and are then incomplete. `GcpDiscoverySyncService` mirrors AWS: configuration-row admission lock, one active run per tenant, durable `GCP_DISCOVERY` ingestion jobs, each project succeeding or failing independently. `GcpResourceIngestionService` marks assets INACTIVE only for types listed completely and non-empty in the run.

**CloudResourceController — `GET /api/cloud-resources`** — paged list of assets with cloud metadata (any provider) with optional `provider`, `accountId`, `region`, `resourceType`, `state`, `search` (wildcards escaped), `page`, `size` (max 200), plus facet counts. Tenant-scoped by the request schema.

### Ticketing framework and Jira connector

`com.prototype.vulnwatch.ticketing` puts every ticketing system behind `TicketingProvider` (`ServiceNowTicketingProvider`, an adapter over `ServiceNowIncidentService`, and `JiraTicketingProvider`). `TicketingService` owns eligibility, CVE asset grouping and the write-back to `findings` (`incident_id`, `incident_status`, `incident_provider`, `incident_pushed_status`, `incident_pushed_at`), so a provider never writes findings itself. `TicketingProviderRegistry` decides where **new** tickets go — the configured provider with the highest `TicketingSystem.precedence()`, so Jira overrides ServiceNow — while an **existing** ticket stays with the system recorded on its finding (null means ServiceNow, which predates provider tracking).

`FindingIncidentSyncService` (07:00 UTC) syncs both directions per finding: it pulls each ticket's state from its owning system (a resolved ticket resolves the finding through `FindingWorkflowService`) and pushes finding resolve/reopen back to the ticket. `incident_pushed_status` is the loop breaker — both directions write it, so a ticket-driven close is never echoed back.

**JiraTicketingConfigController — `/api/connectors/jira-ticketing`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get the tenant's Jira config (the token is write-only; only `hasCredentialSecret` is returned) |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`; blocked for demo tenants; audited as `connector.jira_ticketing.saved`) |
| POST | `/test` | Probe credentials (`/rest/api/3/myself`) then project reachability (`/rest/api/3/project/{key}`) |

One Jira connector per tenant (`uk_jira_ticketing_configs_tenant`) and no environment-level fallback. The token is encrypted with `CredentialEncryptionService` and is covered by `ProviderCredentialMigrator`. Outbound calls use the `jira` provider key, which has **no default host**: add the Jira host to the `jira=` entry of `HTTP_OUTBOUND_ALLOWED_HOSTS` or saving is rejected with 400. A Jira connector counts against the tenant connector quota.

### Connectors

**ServiceNowCmdbConfigController — `/api/connectors/servicenow-cmdb`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get CMDB config |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| POST | `/test` | Test connection |
| POST | `/sync` | Trigger sync |

**SccmCmdbController — `/api/connectors/sccm-cmdb`** — save/test/sync (`TENANT_ADMIN`/`INVENTORY_ADMIN`). Save validates the JDBC URL with `SccmJdbcPolicy` (400 with an operator-facing reason; host must be in `SCCM_ALLOWED_HOSTS`), stores the password encrypted, and rejects mock mode and Windows integrated authentication. Sync admission and scheduling use the same configuration-row lock and durable `SCCM_CMDB` ingestion jobs as ServiceNow and AWS.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get SCCM config |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| POST | `/test` | Test connection |
| POST | `/sync` | Trigger sync |
| GET | `/sync/status` | Get sync status |

**AwsDiscoveryController — `/api/connectors/aws-discovery`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get discovery config |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| POST | `/test` | Test AWS credentials |
| POST | `/sync` | Trigger global sync |
| GET | `/sync/status` | Get sync status |
| GET | `/targets` | List discovery targets |
| POST | `/targets` | Create target (account + region) |
| PUT | `/targets/{targetId}` | Update target |
| DELETE | `/targets/{targetId}` | Delete target |
| POST | `/targets/{targetId}/test` | Test target connection |
| POST | `/targets/{targetId}/sync` | Trigger target sync |

`AwsDiscoveryConfig`, `AwsDiscoveryTarget` entities. Discovery scoped to EC2 instances via SSM; multi-account via cross-account role ARN + external ID.

**AzureDiscoveryController — `/api/connectors/azure-discovery`** — generic Azure is contained by `GenericAzureDiscoveryPolicy` at configuration/test/admission/execution/client boundaries. Saved settings/inventory remain; static Azure AI discovery is a separate retained capability. Routes below are retained contracts, not enablement instructions. *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get discovery config |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| POST | `/test` | Test connection |
| POST | `/sync` | Trigger global sync |
| GET | `/sync/status` | Get sync status |
| GET | `/targets` | List discovery targets |
| POST | `/targets` | Create target (per-subscription scope) |
| PUT | `/targets/{targetId}` | Update target |
| DELETE | `/targets/{targetId}` | Delete target |
| POST | `/targets/{targetId}/test` | Test target connection |
| POST | `/targets/{targetId}/sync` | Trigger target sync |

Historical generic Azure scaffolding, currently contained. Auth types in retained config: `CLIENT_SECRET` or `MANAGED_IDENTITY` (`azure_discovery_configs`/`azure_discovery_targets`, tenant V1 baseline).

**SyncController — `/api/sync-runs`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List sync runs |
| GET | `/sources-summary` | Vulnerability source summary |

`SyncRun` entity tracks each connector sync job.

**Patch management connectors (SCCM/MECM, Microsoft Intune, HCL BigFix, Tanium Cloud)** are served by `PatchConnectorController` (`/api/connectors/patch/{provider}`, `TENANT_ADMIN` or `INVENTORY_ADMIN`) with providers under `service/patch/`. Syncs run as durable `PATCH_SYNC` jobs. BigFix hosts must be listed in `BIGFIX_ALLOWED_HOSTS`; Tanium must be a `*.cloud.tanium.com` host; Intune uses `graph.microsoft.com` and `login.microsoftonline.com`. Intune, BigFix and Tanium are verified only against mocked APIs.

### Auth / Admin

**AuthContextController — `/api`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/context` or `/me` | Get current auth context (roles, tenant, demo status, etc.) |
| GET | `/auth/authorized-workspaces` | List tenants the caller is allowed to enter (`AllowedTenantContextService`) |

**LocalAuthController — `/api/auth`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/login` | Credential login (email + password) |
| POST | `/setup-password` | Set password via one-time setup token |
| POST | `/setup-session` | Start a setup session from a one-time setup token |
| POST | `/tenant-context` | Switch acting tenant context (`PLATFORM_OWNER`) |
| DELETE | `/tenant-context` | Clear acting tenant context (`PLATFORM_OWNER`) |

**TestPersonaController — `/api/dev/test-personas`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List available personas |
| POST | `/{personaKey}/token` | Issue JWT for persona |

The controller is always registered; `TestPersonaService` rejects calls unless `app.test-personas.enabled=true` (and `ProductionSafetyValidator` refuses production startup if it is on).

**TenantAdministrationController — `/api`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants` | List tenants accessible to the caller |
| POST | `/platform/tenants` | Create tenant (`PLATFORM_OWNER`) — returns **202 Accepted**, not 200 |
| POST | `/platform/tenants/{tenantId}/provisioning-retry` | Retry a `PROVISIONING_FAILED` tenant (`PLATFORM_OWNER`) — returns 202 |
| GET | `/platform/tenants/{tenantId}` | Get tenant (`PLATFORM_OWNER`) |
| POST | `/platform/tenants/{tenantId}/owner-recovery` | Recover a tenant owner (`PLATFORM_OWNER`) |
| PATCH | `/platform/tenants/{tenantId}/status` | Update tenant status |
| PATCH | `/platform/tenants/{tenantId}/demo-expiry` | Extend a demo tenant's expiry |
| PATCH | `/platform/tenants/{tenantId}/quotas` | Update entitlement quotas |
| DELETE | `/platform/tenants/{tenantId}` | Delete tenant |
| GET | `/platform/users` | List platform users |
| GET | `/platform/inventory-connectors/health` | Connector health across tenants |
| POST | `/platform/users` | Upsert platform user |
| DELETE | `/platform/users/{userId}/roles/{role}` | Revoke a role |
| POST | `/platform/users/{userId}/setup-link` | Issue password setup link |
| GET | `/tenants/{tenantId}/members` | List members (`TENANT_ADMIN`) |
| POST | `/tenants/{tenantId}/members` | Add member |
| PATCH | `/tenants/{tenantId}/members/{memberId}` | Update member |
| DELETE | `/tenants/{tenantId}/members/{memberId}` | Remove member |
| GET | `/tenants/{tenantId}/invites` | List invites |
| POST | `/tenants/{tenantId}/invites` | Create invite |
| POST | `/tenants/{tenantId}/invites/bulk` | Bulk invite |
| POST | `/tenants/{tenantId}/invites/{inviteId}/resend` | Resend invite |
| DELETE | `/tenants/{tenantId}/invites/{inviteId}` | Cancel invite |

`TenantService.createTenant()` no longer provisions the tenant schema synchronously — it saves the tenant with status `PROVISIONING` and returns immediately; the schema is actually created and migrated the next time the tenant schema control plane runs (`TenantSchemaMigrationService.provisionNewTenant`/`ProductionBootstrapCli`). `TenantLifecycleGuardService.isTenantAccessible()` now allow-lists only `ACTIVE` tenants (previously a deny-list of `DELETED`/`PURGING`/expired-demo), so `PROVISIONING` and `PROVISIONING_FAILED` tenants cannot be entered until provisioning completes — the Platform Console's "Enter workspace" action reflects this, and surfaces a "Retry provisioning" action for `PROVISIONING_FAILED` tenants.

**TenantInviteController — `/api/tenant-invites`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{token}` | Validate invite token |
| POST | `/{token}/accept` | Accept invite |

**TenantSupportAccessController — `/api`** *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants/{tenantId}/support-grants` | List support-access grants for a tenant (`TENANT_ADMIN`) |
| POST | `/tenants/{tenantId}/support-grants` | Tenant admin grants a time-boxed, break-glass platform-owner access grant |
| DELETE | `/tenants/{tenantId}/support-grants/{grantId}` | Revoke a grant |
| GET | `/auth/support-grants` | List grants pending the current platform owner's acceptance (`PLATFORM_OWNER`) |
| POST | `/auth/support-grants/{grantId}/accept` | Platform owner accepts an offered grant |
| POST | `/tenants/{tenantId}/platform-memberships` | Grant a platform membership directly |

Distinct from — and layers on top of — the existing `tenant_support_grants` table/`TenantSupportGrant` lifecycle: the new piece is that a *tenant* can initiate the grant, not only the platform owner requesting access. This capability is included in the tenant V1 baseline.

**ServiceAccountController — `/api/service-accounts`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List service accounts (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/` | Create service account (`TENANT_ADMIN`) |
| DELETE | `/{accountId}` | Delete account |
| POST | `/{accountId}/deactivate` | Deactivate account |
| POST | `/{accountId}/reactivate` | Reactivate account |

### Demo

**DemoController — `/api/demo`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/seed` | Seed demo data advisories (`PLATFORM_OWNER`) |

**DemoLifecycleController — `/api`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/demo-requests` | Submit a demo request (public) |
| GET | `/platform/demo-requests` | List demo requests (`PLATFORM_OWNER`) |
| POST | `/platform/demo-requests/{requestId}/approve` | Approve |
| POST | `/platform/demo-requests/{requestId}/reject` | Reject |
| POST | `/platform/demo-requests/{requestId}/resend-invite` | Resend invite |
| POST | `/platform/demo-requests/{requestId}/issue-setup-link` | Issue setup link |
| DELETE | `/platform/demo-requests/{requestId}` | Delete request |
| GET | `/demo-invites/{token}` | Validate invite token |
| POST | `/demo-invites/{token}/accept` | Accept invite (returns setup token) |
| GET | `/demo/status` | Get demo status for the current tenant |

**DemoDatasetController — `/api/platform/tenants`** *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| POST | `/{tenantId}/demo-data` | Manually trigger demo dataset provisioning for a tenant (`PLATFORM_OWNER`) |

Companion to `DemoDatasetProvisioningService` (polls every 30s by default, seeds/repairs a requested tenant's demo dataset once it reaches `ACTIVE`) — see [Scheduled Jobs](#scheduled-jobs).

### Platform

**PlatformVulnRepoController — `/api/platform/vuln-repo`** (all endpoints `PLATFORM_OWNER`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Platform-wide vulnerability repo dashboard |
| GET | `/vulnerabilities` | List all vulnerabilities, platform-wide |
| GET | `/source-stats` | Source statistics |
| GET | `/intel/{externalId}` | Vulnerability intel detail |

**TenantSchemaStatusController — `/api/platform/tenant-schema-status`** *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Paginated per-tenant schema migration status (`PLATFORM_OWNER`) — current/target version, structural checksum, failure code/message, migration timestamps |

Backed by `platform.tenant_schema_versions` via `TenantSchemaStatusService`. Shown in the Platform Console. See "Tenant Schema Control Plane" below.

**OperationsOverrideController — `/api/operations`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/quality/issues/{issueId}/normalize/impact` | Normalization override impact preview |
| POST | `/quality/issues/{issueId}/normalize` | Apply normalization override (`@SensitiveTenantAction`) |
| DELETE | `/quality/issues/{issueId}/normalize` | Revoke normalization override |
| POST | `/quality/issues/{issueId}/correlate` | Apply correlation override |
| DELETE | `/quality/issues/{issueId}/correlate` | Revoke correlation override |
| GET | `/software-identities/search` | Software identity autocomplete search |

**VulnerabilityArchiveController — `/api/operations/vulnerability-archive`** (all endpoints `PLATFORM_OWNER`) — retained API inventory only. Local archive write/migrate/file-read operations are unavailable before filesystem access. Canonical descriptions/payloads remain in PostgreSQL; historical references/files are retained, not migrated or deleted.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/migrate` | Migrate existing vulnerability data to archive |
| GET | `/{externalId}/description` | Get archived description |
| GET | `/{externalId}/raw-payload` | Get archived raw payload |
| GET | `/status` | Get archive migration status |

**UpgradeRecommendationController — `/api/upgrade-recommendation`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/` | Get upgrade recommendation (`TENANT_ADMIN`/`SECURITY_ANALYST`) |

**AuditEventController — `/api/audit-events`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List audit events (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| GET | `/export` | Export as CSV (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| GET | `/support-bundle` | Get support bundle (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| GET | `/platform-users` | Platform user audit events (`PLATFORM_OWNER`) |

**SloController — `/api/slo`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | SLO compliance status (`PLATFORM_OWNER`) |

### ApiExceptionHandler

`@RestControllerAdvice` providing consistent error responses for all controllers: 404 (entity/resource not found), 400 (validation, malformed body, illegal argument/state, data-integrity violations), 405 (method not supported), 403 (authorization), 429 (quota exceeded, public rate limit), demo access violations, 409 (lock contention), `ResponseStatusException` passthrough, 500 (generic).

---

## External Integrations (Clients)

### NVD API (`NvdApiClient`)

Fetches CVE data from NIST National Vulnerability Database. Used in daily incremental sync (`01:00` UTC) and on-demand CVE lookups. API key via `NVD_API_KEY` (or `NVD_API_KEY_FILE`).

### EUVD API (`EuvdApiClient`)

European Union Vulnerability Database — alternative CVE source.

### JVN API (`JvnApiClient`)

Japan Vulnerability Notes — Japanese CVE database.

### GitHub API (`GithubApiClient`)

SBOM ingestion from GitHub repos (dependency graph export) and GHCR (container image attestations). Also GHSA (GitHub Security Advisory) feed sync. Token resolved via `GITHUB_API_TOKEN_FILE`, then `backend/secrets/github-api-token`, then `GITHUB_API_TOKEN` (`GithubTokenProvider`).

### EOL API (`EolApiClient`)

Fetches product lifecycle data from endoflife.date. Drives the 4-stage EOL pipeline (Sunday, stages 1–4).

### AWS (`AwsDiscoveryClient`, `AwsCredentialProvider`)

Discovers EC2 instances via AWS SSM. Supports IAM role assumption, access keys, and instance profile auth. Multi-account via cross-account role ARN + external ID in `AwsDiscoveryTarget`.

### Azure (`AzureDiscoveryClient`, `AzureCredentialProvider`)

Generic Azure is unavailable under `GenericAzureDiscoveryPolicy`; saved settings do not enable network collection. The following client description is retained design context.

Discovers compute/platform resources per subscription. Supports `CLIENT_SECRET` and `MANAGED_IDENTITY` auth. Multi-subscription via `AzureDiscoveryTarget` (`azure_discovery_configs`/`azure_discovery_targets`, part of the tenant V1 baseline). Mirrors the AWS Discovery client architecture; newer and less exercised in production.

### OpenAI (`OpenAiClient`)

Generative assistance defaults off (`OPENAI_ENABLED=false`). `GenerativeAssistancePolicy` denies production/preproduction before resolving `app.openai.api-key`, `OPENAI_API_KEY`, `openai_API_KEY` or `openai.api.key`; pilot startup rejects enablement. Direct investigation summaries share that gate. Retained deterministic recommendations/fallbacks preserve source and generation-time metadata and do not invent verified versions or vendor attribution. Persisted historical AI artifacts are not proof of a new provider call or verified vendor evidence. Static AI Grid assessment and deterministic EOL resolution are independent.

### AI Security discovery (`aisecurity.aws.AwsBedrockDiscoveryService`, `aisecurity.azure.AzureAiManagementClient`)

Separate from the general-purpose AWS/Azure Discovery clients above. `AwsBedrockDiscoveryService` uses AWS SDK v2 to discover Bedrock agents/knowledge bases/guardrails/models, AgentCore gateways, and SageMaker resources; checks IAM/Lambda/S3 for common misconfigurations; optionally reads existing AWS Macie PII findings (`AwsMaciePiiLookupService`, read-only). `AzureAiManagementClient` makes raw ARM API calls to discover Cognitive Services/AI Foundry/ML/Search/Bot resources; `AzurePurviewClassificationClient` optionally reads existing Microsoft Purview classification results (read-only). Both are gated by admission-control semaphores and the `AiGridBudgetService` daily budget. See [AI Security / AI Grid Service Layer](#ai-security--ai-grid-service-layer) below.

#### AWS connector maturity: versions, definition graph, identity, AgentCore

Beyond the agent-level posture above, `AwsBedrockDiscoveryService` builds a **version-rooted definition graph** so posture is evaluated against what is actually served rather than mutable `DRAFT` composition. Agent→alias uses `HAS_COMPONENT`, alias→version uses `SERVES_VERSION`, versions own model/prompt/tool/knowledge/guardrail/role edges, and tools link to their implementation with `IMPLEMENTED_BY`. No direct agent→Lambda/knowledge-base/role compatibility edges are emitted. AgentCore inventory is retained independently and is root-eligible only when a stable provider identity, authoritative workload boundary, and provider-backed membership edge are all present.

These collector layers are governed by one provider-call ceiling checked before every call and retry. Connector enablement, provider kill switch, scan budgets, semaphores, retries, and the separately cost-sensitive Macie switch remain; the granular maturity rollout flags were removed.

Prompt and tool **bodies are never persisted**: prompts store a tenant-keyed digest via `AiSecurityDigestService` (`promptDigest` + `digestAlgorithm` + `digestKeyVersion` + `promptLength`, `bodyStored: false`), and action groups store `definitionBodyStored: false`. `ProductionSafetyValidator` refuses to start in production when `APP_AI_SECURITY_IDENTITY_HMAC_KEY` is unset or a placeholder.

IAM evidence is isolated **per role**: a role whose trust or policy documents cannot be parsed or read degrades only that role — the `IAM_GLOBAL` scope drops to `PARTIAL` with an `IAM_ROLE_EVIDENCE_PARTIAL` diagnostic (the role ARN appears only as a truncated SHA-256, never in plaintext) while every other role's evidence stands. A whole-scope `AccessDeniedException` now yields `UNAUTHORIZED` rather than the generic `FAILED`.

A disabled collector reports scope status `DISABLED` rather than an empty `COMPLETE` scan, so intentional disablement is never mistaken for "scanned and found nothing".

#### AWS activity evidence

**Status: deferred.** `AiGridHostContextService` calls `AiRuntimeScope.requireInScope()` for any `activity.*` fact and for the `SCOUT_AWS_ACTIVITY` producer, so ingestion and the activity-evidence read currently fail with HTTP 410 `RUNTIME_OUT_OF_SCOPE`; the design below is retained for when runtime returns.

The AWS activity-evidence path deliberately does **not** ingest CloudWatch logs or write `ai_agent_executions`. Instead `AiGridHostContextService` registers a trusted producer `SCOUT_AWS_ACTIVITY` (provenance `OBSERVED`, evidence class `RUNTIME_OBSERVATION`, source port `ASSET`, method version `1.0.0`) accepted through the existing `POST /api/internal/ai-grid/evidence/{producerId}` port. It authorizes exactly seven fact keys — `activity.agent_invocation_observed`, `activity.tool_use_observed`, `activity.identity_use_observed`, `activity.external_action_observed`, `activity.sensitive_data_access_observed`, `activity.invocation_count_observed`, `activity.agent_last_observed_at` (registered in the platform V1 baseline, allowed workflow uses `ACTIVITY_CONTEXT`/`EXPOSURE_PRIORITIZATION`, 24h default max age). Historical Azure/Copilot execution collection is also blocked by current runtime exclusion. None of this deferred design authorizes execution or activity writes.

In the historical design, every key ended in `_observed` and was **non-validating**: they can raise an exposure's rank and drive the "activity observed" UI state, but they can never promote an exposure to `VALIDATED_EXPOSURE`. Unlike the other producers, this one *requires* `validUntil` and buckets `observedAt` to the UTC day, so re-pushing the same producer/artifact/fact/window updates in place rather than accumulating rows. The historical design added activity priority points; current exclusion prevents historical activity from influencing priority. Absence of activity evidence is never rendered as proof of non-use.

### Resend (`ResendEmailClient`)

Transactional email transport configured through `RESEND_API_KEY`; invitation and campaign delivery use the separate durable outboxes described [above](#durable-work-scheduling-and-delivery). Bootstrap owner setup-link delivery is a separate explicit CLI operation; it is not an app-startup send.

### Outbound HTTP Infrastructure

All outbound HTTP calls go through `OutboundHttpClient` which wraps Spring's `RestClient`. Configured via `OutboundPolicy` / `OutboundPolicyFactory`. `OutboundFailureClassifier` categorizes failures. `OutboundFailureDecision` controls retry vs. circuit-break behavior. `OutboundPolicyDefaults` provides sensible per-service defaults. `AdvisoryFetchService` handles bulk advisory fetching for CSAF/VEX sources.

---

## Service Layer

### SBOM Ingestion (`service/sbomingestion/`)

Parses CycloneDX and SPDX SBOMs, normalizes component names and versions, resolves CPEs against `cpe_dim`, writes `inventory_components` and `inventory_component_cpe_map`. Deduplicates components within a tenant by normalized identity.

### CMDB Ingestion (`service/cmdbingestion/`)

ServiceNow CMDB sync: pulls CI records, resolves identity via `CiResolutionService`, writes `assets` and `cis`. SCCM/MECM sync reads `v_R_System` joined to `v_GS_INSTALLED_SOFTWARE` over JDBC and ingests through the same CMDB pipeline. Supported CMDB ingestion writes to `software_instances` and `discovery_models`.

### Vulnerability Ingestion (`service/vulningestion/`)

Processes NVD CVE JSON, GHSA advisories, CISA KEV list, and Microsoft/Red Hat CSAF/VEX documents. Writes `vulnerabilities`, `vulnerability_targets`, and `vex_assertions`. `ApplicabilityDecisionService` re-evaluates component states after new intel arrives.

### Finding Service

`FindingService` drives finding lifecycle: create when `component_vulnerability_state` flips to applicable, reopen when suppression expires or VEX assertion is withdrawn, resolve when component is patched or suppressed. Delta queue (`finding_delta_queue`) batches state changes, drained every 2 seconds in batches of 100.

### EOL Pipeline

Four-stage weekly pipeline (Sunday):
1. Catalog refresh — fetch product list from endoflife.date
2. Release data — fetch release cycles per product
3. Slug resolution — match `inventory_components` to EOL catalog slugs (deterministic tiered matching in `EolSlugResolverService`, which also returns confidence-scored suggestions; no OpenAI call)
4. Denormalization — write `eol_slug`, `eol_cycle`, `eol_date`, `is_eol` and support-phase fields onto `inventory_components` and `software_instances` (days remaining is computed at query time from `eol_date`)

### Ownership Rule Evaluation

`OwnershipRuleService` (`applyOwnerGroupToFinding`, `applyToAll`, `applyRule`) evaluates `ownership_rules` by priority when findings are created or updated. First matching rule assigns ownership. Evaluated server-side, not stored as a trigger. Legacy until the CORE ownership cutover.

### Canonical Ownership (Release 1)

`service/ownership/` implements the ownership MVP; see [the Phase 0A design](ownership-phase-0a-design.md) §8.1 for the full as-built contract.

- **Single writers.** `OwnershipSubjectService` (subjects and edges; rejects cycles and chains over 6 hops under a tenant advisory lock), `OwnershipClaimService` (claims), `OwnershipResolutionService` (the only writer of `ownership_assignment`; unchanged inputs write nothing), `OwnershipReviewService`, `OwnershipEvents` (append-only) and `OwnershipEffectiveCacheService` (cache and invalidation queue). `TeamNamespaceService` owns team names and aliases. `DirectoryService` and `DirectoryImportService` own people, groups, memberships and CSV imports.
- **Resolution.** `OwnershipResolver.resolve` is a pure function with a `RESOLVER_VERSION`. Priority, lower wins: manual, ServiceNow, cloud account/project, AI Grid, cloud tag/label, Entra/Okta. A direct claim beats any inherited result; inheritance is applied only by the `ownership_effective_assignment` view. A claim is stale after twice its source's sync interval and ineligible after 7 days without re-observation; these thresholds still need product sign-off.
- **Authority and cutover.** `OwnershipAuthorityService.stateFor` is the only authority lookup. `OwnershipCutoverService` runs LEGACY → DARK → CANONICAL per domain. Release 1 handles CORE only: APPLICATION/HOST assets and VULNERABILITY findings. CRYPTO findings and container/cloud assets are `CLOUD_BOM` (Release 2); AI findings are `AI_GRID` (Release 3).
- **Read adapter.** `OwnershipReadAdapter` returns the envelope (`authorityState`, `ownerTeamId`, `ownershipStatus`, `assignmentId`, `stale`, `inheritanceDepth`, `legacyOwnerLabel`). Read waves `app.ownership.read-waves.inventory` and `.findings` (`*` or tenant IDs, empty by default) decide whether reads run at all. `FindingQueryService`, `AssetQueryService` and `HostInventoryReadService` fill the existing response fields from it; nothing is written back.
- **Producers.** `ServiceNowOwnershipProducer` publishes claims from synced CMDB `support_group` after a successful `ServiceNowCmdbSyncService` run, only with `app.ownership.servicenow.producer-enabled=true` and only when the domain is DARK or CANONICAL. It pauses with a `PRODUCER_ANOMALY` review item when more than 20% (minimum 50) of active claims would change, and ends absent CIs' claims only after a complete scan.
- **Tenant data keys.** `security/tenantkey/`: `TenantDataCipher` (`AesGcmTenantDataCipher`, `enc:t1:` prefix, AAD `tenantId|purpose|keyVersion`, HMAC blind indexes), `TenantKeyRegistry` (cached DEKs, bounded TTL), `KeyWrapper` with `LocalKeyWrapper` for local/test only. There is no AWS KMS wrapper yet.

### Findings Score

`FindingsScoreService` evaluates the `findings_score_config` JSONB from `risk_policies` against each finding's attributes. Score (0–10) returned as `findingsScore` on every `FindingResponse`. `FindingsScoreRecomputeService.recomputeAll()` is triggered by `POST /api/risk-policy/recompute-findings-scores`.

### Suppression

Suppression rules evaluated at finding creation and on the 15-minute reopen sweep (`FindingWorkflowService.reopenExpiredSuppressions`). `SuppressionRuleService` handles rule execution, reopen-all, and finding state changes triggered by rule changes. All approved rules are also re-run nightly (midnight).

### Remediation Campaigns

`CampaignController`/`CampaignService` group findings/CVEs under a tracked remediation effort with lifecycle states (DRAFT, ACTIVE, PAUSED, BLOCKED, IN_REVIEW, CLOSED, CANCELLED), per-item exceptions, notify groups, and a watchlist. Frontend at `/vuln-repo/campaigns`.

### BOM / CBOM

`BomController` (`/api/bom`) handles general Bill-of-Materials ingestion (fetch by URL or upload) with dashboard/support/lineage views. `CbomController` (`/api/bom/cbom`) tracks cloud/container BOM posture and risk findings per asset, with an accept-finding workflow.

### AI Security / AI Grid Service Layer

71 services under `com.prototype.vulnwatch.aisecurity.service`, backing the controllers in [AI Security / AI Grid](#ai-security--ai-grid) above. All tables are accessed via `JdbcTemplate` directly — there are no JPA entities or Spring Data repositories for this module. `AiSecurityJobWorkerService` polls `ingestion_jobs` (every 3s by default) for `AI_SECURITY_AWS_BEDROCK`, `AI_SECURITY_AZURE_DISCOVERY`, and `AI_SECURITY_COPILOT_STUDIO` jobs, dispatching to the corresponding provider under per-tenant/provider admission limits. Copilot's manual and scheduled discovery requests enqueue the same durable job as AWS/Azure; the worker applies its kill switch and budget admission before the Dataverse sweep, so it has the same queue visibility and terminal job record. All providers emit sanitized `ObservationEnvelopeV1` chunks (`AiSecurityMetadataSanitizer` — allow-listed fields only, no prompt bodies/secrets/PII). Once a scan scope completes, `AiSecurityObservationService` hands off to `AiGridPipelineService.processCompleteScope()`, which runs in order: **snapshot** (`AiGridSnapshotService` — immutable, hash-deduped, derives facts) → **ownership** (`AiGridOwnershipService` — CONFIRMED/INFERRED/CANDIDATE/UNOWNED, reuses the tenant's `ownership_rules`) → **system grouping** (`AiGridSystemService` — bounded BFS, depth 6/fan-out 100, with split/merge/successor lineage) → **policy assessment** (`AiGridAssessmentService` + `AiGridPredicateEngine`, a JSON predicate evaluator) → **R2 exposure correlation** (`AiGridExposureService` — three hardcoded graph-traversal templates, promoting hypotheses to "validated" only on exact, fresh evidence; `AiGridExposureFreshnessService` demotes stale ones) → **coverage/setup** (`AiGridReconciliationService`, `AiGridCoverageService`, `AiGridReadinessService`) → **finding bridge** (`AiGridFindingService`/`AiGridExposureFindingService` — writes into the canonical `findings` table with `finding_kind = AI_POSTURE`/`AI_EXPOSURE`, reusing `FindingWorkflowService`/SLA/ServiceNow, not a separate table). The governance track's `AiGridPolicyRolloutService` and `AiGridPolicyDeprecationService` each run their own `@Scheduled` worker (every 5s by default) draining a pending-task queue for GA/canary distribution and deprecation, respectively — see the Scheduled Jobs table above.

**Scope-owned artifact attributes.** Several AWS scopes enrich the *same* agent artifact (agent basics, IAM evidence, Lambda URL auth, knowledge-base counts), so `AiSecurityObservationService.upsertArtifact()` does not blanket-replace `attributes_json`. Each attribute key a scope emits is recorded in `ai_security_artifact_attribute_ownership` keyed by `scope_key`. Only a scope that lands a single-chunk `COMPLETE` observation clears its own previously-owned keys before writing the new set — a `PARTIAL`, `FAILED`, `UNAUTHORIZED`, or `DISABLED` scope leaves prior values intact, and a key also owned by another scope is never removed. Net effect: a field the provider stopped reporting disappears after a genuinely complete scan, while a transient failure in one scope cannot erase authoritative evidence produced by another.

**Capability observations.** `AiGridCapabilityService.recordScope()` writes one `ai_grid_capability_observations` row per capability a completed scope contributes to, with `status`, `reason_code` (`OBSERVED`, `CONNECTOR_DISABLED`, `MISSING_PERMISSION`, `UNSUPPORTED_API`, `COLLECTOR_ERROR`, `PARTIAL_EVIDENCE`, `MISSING_EVIDENCE_SCOPE`) and `evidence_scopes_json` naming the contributing collector scopes. **Composite** capabilities are aggregated rather than inferred from a single scope: `BEDROCK_PROMPTS_TOOLS` requires both `BEDROCK_PROMPTS` and `BEDROCK_AGENT_DEFINITIONS`, `AGENTCORE_RUNTIME_TOOLS` requires runtimes + browsers + code interpreters, `BEDROCK_KNOWLEDGE_BASES` requires knowledge bases + data sources + data stores, and `BEDROCK_MODELS_JOBS` requires deployable models + inference profiles + customization jobs. Any required family that is missing from this run's `ai_security_snapshot_scopes`, or present in a non-`COMPLETE` status, holds the capability below `COMPLETE` — successful enumeration of one family is not sufficient. Because the aggregate is recomputed as each scope lands, a composite capability's row is written more than once per run and the latest `observed_at` wins.

A platform-owner-only governance track gates content before it reaches tenants: `AiGridPolicyCatalogService` imports packages as validated and prevents direct publishing; `AiGridValidationGovernanceService` requires digest-bound approval, then creates policy-ID release bindings for explicit active-tenant canary cohorts (with no default-workspace publication fallback; callers must name target tenants or explicitly publish all), supports binding revocation and explicit deprecation; `AiGridR1CertificationService`/`AiGridR2CertificationService` provide release-gate certification; and `AiGridPolicyPortfolioService` provides registered framework coverage + RICE-scored candidate backlog. Coverage uses `release_family`, not policy-name prefixes, and calls the shared `platform.ai_grid_policy_visible_to_tenant` function so reporting cannot credit a policy the tenant cannot receive. AI Grid is the sole policy and tenant-configuration authority. Operationally, `AiGridBudgetService` enforces per-tenant daily scan/API-call/byte budgets (new tenants start `OBSERVE`-only) and `AiGridRetentionService` classifies evidence into HOT/ARCHIVE/RESTRICTED_EVIDENCE tiers with legal-hold support and an audited purge sweep.

`AiGridFindingService.AssessmentResult.deriveAssessmentState` is the single customer-facing state projection: PASS and FAIL are direct, ERROR and incomplete/stale evidence are UNKNOWN, and OUT_OF_SCOPE/CAPABILITY_UNAVAILABLE/NOT_APPLICABLE are NOT_ASSESSED. `AiGridApiService.latestAssessmentStates` applies that derivation to the latest run for each policy version and exposes totals at `/api/ai-assessment-states/latest`; do not reproduce the mapping in SQL.

**Runtime status: deferred.** `AiRuntimeScope` (`excluded()` is hard-coded `true`, `requireInScope()` throws HTTP 410 `RUNTIME_OUT_OF_SCOPE`) blocks the runtime paragraphs below — execution ingestion, readiness, runtime policy evaluation, the telemetry adapter and its worker/retention jobs do no work, and `ProductionSafetyValidator` fails startup if `APP_AI_SECURITY_RUNTIME_ENABLED=true`. They document the deferred design.

`AiAgentExecutionIngestionService` is the shared metadata-only runtime write boundary. It HMACs provider identifiers before persistence, bounds event count and metadata size, applies lookback/overlap cursors, and uses receipts for idempotency. `AzureFoundryRuntimeCollectionService`, Azure ML job discovery, and `CopilotStudioRuntimeCollectionService` call this boundary directly as provider connectors; `AiGridRuntimeIngestionService`/`AiGridRuntimeIngestionWorker` call the same boundary indirectly for the governed customer-telemetry adapter (below). Raw prompts, responses, tool payloads, and provider log streams are outside its contract. Tenants read the resulting execution, timeline, and relationship projections through `AiAgentExecutionController`.

`AiGridRuntimeTelemetryReadinessService.readiness()` owns the Program 2 entry gate rather than accepting thresholds from the client. Sources are enumerated from `ai_runtime_source_configurations` (seeded `AZURE_FOUNDRY_RUNTIME`, `COPILOT_STUDIO_RUNTIME`) unioned with registered `ai_runtime_evidence_producers` rows — not a hardcoded two-provider list — and the gate passes once at least two `PROVIDER_CONNECTOR`-kind sources each independently pass over a rolling 14-day window: ≥100 executions, ≥95% `approval_state`/`policy_state`/`action_outcome` fill **measured over consequential events only** (`action_category IN (WRITE,DELETE,SEND,EXECUTE,ADMIN,PAYMENT,PUBLISH)`), ≥90% agent correlation, and ≥80% version correlation over a version-applicable sample of ≥50 executions (below that floor the version-correlation criterion reports `VERSION_SAMPLE_INSUFFICIENT` rather than passing vacuously). Execution-scoped fill rates are still computed and returned for continuity but no longer gate release. `TELEMETRY_ADAPTER`-kind sources are reported and certified separately and never substitute for a provider connector in the two-source gate. `AiAgentExecutionRetentionService` deletes expired execution parents in bounded batches (events cascade), stops after 100 batches or 30 seconds per tenant, counts remaining eligible rows, and warns when work remains.

**Runtime policy evaluation.** `AiGridRuntimeEvaluationService.evaluateRun()` evaluates the `EXECUTION`-subject policies that `AiGridAssessmentService`'s artifact loop deliberately skips (`AiGridAssessmentService.isRuntimeMode`), bounded to 2000 executions per policy per run. It loads only `ENABLED`/`REQUIRED` selections (a `PREVIEW`/`DISABLED` runtime package stays inert) and dispatches by `evaluation_mode`: `RUNTIME_FACTS` (a bounded conjunction of execution-scoped conditions), `RUNTIME_SEQUENCE` (ordered event-scoped steps within a duration bound), `RUNTIME_AGGREGATE` (a registered metric over a grouping key vs. threshold), and the meta-mode `RUNTIME_COVERAGE` (one finding per provider/workspace/capability-family/window rather than per execution). Field references resolve only against `platform.ai_grid_runtime_field_definitions`; an unpopulated governed field settles `UNKNOWN`, not `PASS`. Results persist to `ai_grid_assessments` and reconcile into `finding_kind = AI_RUNTIME` findings via `AiGridFindingService`, deduplicated by the sequence's dedup key or the aggregate's grouping key. Lookback window: `app.ai-security.runtime.evaluation-lookback-days` (default 14).

**Governed customer telemetry adapter.** `AiGridRuntimeIngestionService.accept()` is the admission boundary behind `POST /api/internal/ai-grid/runtime/{producerId}/v1/batches` (see [AI Security / AI Grid](#ai-security--ai-grid) above for the controller). It checks caps in the order they're meant to bind — 2 MiB request body, then 100 executions/batch, then the existing per-execution event/metadata limits — recursively rejects forbidden raw-content keys, requires the producer to be an `ACTIVE` `RUNTIME_EVIDENCE_PRODUCER` registered to the resolved tenant, and only honors a submitted `AUTHORITATIVE` evidence class when that producer's `certification_state = 'CERTIFIED'`. A per-tenant backlog cap and the rolling quota in `ai_runtime_quota_windows` (soft limit at 80% of the configured window, hard limit rejects with `TENANT_QUOTA_EXHAUSTED`, never sampled or silently truncated) gate admission before an `ai_runtime_ingestion_receipts` row and an `AI_GRID_RUNTIME_ADAPTER` `ingestion_jobs` row are written. `AiGridRuntimeIngestionWorker` (every 2s by default, one job per tenant per tick) drains that queue through `AiAgentExecutionIngestionService` and completes the receipt. `AiGridManifestApprovalService` is the tenant control plane behind `/ai-approved-manifests` and `/ai-component-allowlist` (tenant V2) that runtime policies AGCF-RT-002/003/008 read against.

Runtime policy packages (`AGCF-RT-001`…`009`, wave 2A/2B) ship `PREVIEW`/`PAUSED` under `policy-packages/agcf/AGCF-RT-*`, governed by `policy-packages/agcf/runtime-wave-contract.json` and validated by `scripts/validate-ai-grid-runtime-catalog.mjs`; five further wave-2C controls (`AGCF-RT-010`–`014`) are declared paused-pending-evidence in the same contract with no package files yet, each blocked on a named unsupported capability (`RUNTIME_HANDOFF_EVIDENCE`/`RUNTIME_MEMORY_EVIDENCE`/`RUNTIME_PROVENANCE_EVIDENCE`/`RUNTIME_CONTAINMENT_EVIDENCE`). Historical tenant seeding preserved PREVIEW defaults. Current runtime exclusion keeps runtime distributions unavailable/paused and overrides disabled; no tenant override authorizes runtime evaluation.

Full narrative: [business-logic-guide.md](business-logic-guide.md#ai-security--ai-grid-pipeline). Schema: [database.md](database.md#ai-security--ai-grid-tables).

### Tenant Schema Control Plane *(new)*

Per-tenant DDL now runs on its own Flyway line, separate from the platform's startup migration:

- **`TenantSchemaMigrationService`** — drives the rollout: acquire a Postgres advisory lock (`scout-tenant-schema-migrator`) → migrate the `tenant_default` template and compute a SHA-256 structural fingerprint → migrate a canary tenant → migrate remaining tenants in batches of 10, comparing each tenant's fingerprint against the template and halting the batch on drift. Runs against `classpath:db/migration/tenant`, with its own `tenant_schema_history` table per schema, starting at V1. Also drives `provisionNewTenant(tenant)` for on-demand provisioning of a single new tenant.
- **`TenantSchemaStatusService`** — reads/writes `platform.tenant_schema_versions` (list for the Platform Console, `readinessFailures(minVersion)` for the health indicator, `markMigrating`/`markCurrent`/`markFailure` called by the migration service).
- **`PlatformSchemaStartupValidator` / `TenantSchemaReadinessHealthIndicator`** — when schema enforcement is enabled, startup/readiness share a read-only structural and SELECT-grant check for required platform work, the schedule-occurrence index and V6 waiting-state constraint. Missing shared dependencies fail startup or readiness. Readiness stays UP for compatible tenants while reporting `unreadyTenantCount`; an incompatible individual tenant is rejected at request entry. Required tenant floor and supported maximum are both V23, even if a lower minimum is configured. Platform head is V16. These checks do not establish actual deployed history or rollback compatibility.
- **`TenantSchemaMigratorRunner`** — a legacy/test-only `ApplicationReadyEvent` listener, gated behind `app.schema-migration.legacy-test-runner-enabled=true` (off by default); superseded in production by `ProductionBootstrapCli` below but still used by some integration tests.
- **`ProductionBootstrapCli`** (`com.prototype.vulnwatch.migration`) — standalone production bootstrap entry point; does **not** start Spring/JPA. Runs platform migrations, optionally reconciles the configured platform-owner identity (`APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED`), registers/migrates the default tenant, migrates every other tenant (canary + batches of 10, same drift-checking as above), provisions/rotates the least-privilege `scout_runtime` Postgres role, verifies the full control-plane invariants (RLS coverage on every active tenant table, no unsafe role attributes, runtime role actually denied DDL at runtime), and — when `PLATFORM_OWNER_SETUP_LINK_ENABLED=true` — emails a one-time password-setup link via `ResendEmailClient`. Prints a single-line `production_bootstrap_report=<json>` summary and exits non-zero on any phase failure. Invoked via `/app/scripts/run-schema-migration.sh --run-once` in a standalone ECS task; `backend/scripts/provision-runtime-role.sql` is the equivalent automated role-provisioning script. See [bootstrap wrapper](../backend/scripts/run-schema-migration.sh), [runtime grants](../backend/scripts/provision-runtime-role.sql) and [qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).
- **`TenantLifecycleGuardService`** — centralizes tenant-accessibility checks (demo-tenant detection/expiry, `DELETED`/`PURGING`/`EXPIRED`/non-`ACTIVE` status → `ResponseStatusException` with the appropriate HTTP status) previously duplicated across tenant-status filtering call sites.

---

## Configuration Properties

| Property | Env var | Default | Description |
|----------|---------|---------|-------------|
| `app.environment` | `APP_ENVIRONMENT` | empty (must declare) | local/test/production/preproduction; deployed intent cannot be local/test |
| `app.runtime.role` | `APP_RUNTIME_ROLE` | empty (must declare) | all/api/worker/schema-migrator; API/migrator suppress jobs |
| `app.security.jwt.mode` | `APP_JWT_AUTH_MODE` | `LOCAL` | Explicit mode contract described above; EXTERNAL disables local issuance |
| `app.entitlements.mode` | `APP_ENTITLEMENTS_MODE` | `LEGACY` (base) | Deployed pilot requires ENFORCE and explicit cohort; allow never overrides independent containment |
| `app.security.api-key` | `APP_API_KEY` | (empty — API-key auth rejects until set) | API key for `X-API-Key` auth |
| `app.security.creator-key` | `APP_CREATOR_KEY` | (none) | Creator key for elevated access |
| `app.security.allow-api-key-auth` | `APP_ALLOW_API_KEY_AUTH` | `true` (base profile; `false` in `prod`/`preprod`) | Enable API key auth path |
| `app.tenancy.allow-header-tenant-selection` | `APP_ALLOW_HEADER_TENANT_SELECTION` | `false` | Allow `X-Tenant-ID` header |
| `app.tenancy.require-tenant-context` | `APP_REQUIRE_TENANT_CONTEXT` | `true` | Reject requests without tenant |
| `app.test-personas.enabled` | `APP_TEST_PERSONAS_ENABLED` | `false` | Enable test persona endpoints |
| `app.security.jwt.hmac-secret` | `APP_JWT_HMAC_SECRET` | — | HMAC secret for HS256 JWT signing |
| `app.security.jwt.issuer-uri` | `APP_JWT_ISSUER_URI` | — | OIDC issuer for RS256 JWT validation |
| `app.security.bootstrap.platform-owners.enabled` | `APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED` | `false` | Local/test startup seed only; deployed runtime rejects it |
| `app.security.bootstrap.platform-owners.users[n].email` | `APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_<N>_EMAIL` | — | Login email for a seeded platform owner |
| `app.security.jwt.allow-hmac-in-production` | `APP_ALLOW_HMAC_IN_PRODUCTION` | `false` | Permits HS256 JWT signing (`APP_JWT_HMAC_SECRET`) when `require-production-secrets=true` — used by the Render preprod profile ahead of full OIDC |
| `app.cors.allowed-origins` | `APP_CORS_ALLOWED_ORIGINS` (read by `application-prod.yml` only) | `http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174` in `application.yml` | Comma-separated CORS origins |
| `app.security.credential-encryption-key` | `APP_CREDENTIAL_ENCRYPTION_KEY` | — | AES-256 key (base64) for credential storage |
| `app.schema-migration.enabled` | `APP_SCHEMA_MIGRATION_ENABLED` | `false` | Deployed validation requires false; `TenantSchemaMigratorRunner` is gated by `legacy-test-runner-enabled` below |
| `app.schema-migration.report-only` | `APP_SCHEMA_MIGRATION_REPORT_ONLY` | `false` | Runs the tenant schema rollout in read-only drift-report mode (read by `TenantSchemaMigratorRunner`) |
| `app.schema-migration.legacy-test-runner-enabled` | — | `false` | Gates `TenantSchemaMigratorRunner` registration (legacy/test path; production uses `ProductionBootstrapCli`) |
| `app.tenancy.enforce-schema-version` | `APP_ENFORCE_TENANT_SCHEMA_VERSION` | `false` (production: `true`) | Checks required platform work structures at startup/readiness and tenant compatibility at request entry |
| `app.tenancy.minimum-compatible-schema-version` | `APP_MINIMUM_TENANT_SCHEMA_VERSION` | `5` | Required tenant floor V23 (`TenantSchemaCompatibility`); configured values cannot lower it. Supported tenant range is V23–V23; independent platform head is V16 |
| `app.security.tenant-keys.wrapper` | `APP_TENANT_KEY_WRAPPER` | `disabled` | Per-tenant data-key wrapper. `disabled` makes every directory/PII write fail closed; `local` is refused unless `APP_ENVIRONMENT` is local/test |
| `app.security.tenant-keys.local-master-key` | `APP_TENANT_KEY_LOCAL_MASTER_KEY` | — | Master key for the `local` wrapper |
| `app.security.tenant-keys.cache-ttl` / `cache-max-keys` | `APP_TENANT_KEY_CACHE_TTL` / `APP_TENANT_KEY_CACHE_MAX_KEYS` | `PT10M` / `10000` | In-memory DEK cache bounds |
| `app.ownership.effective-cache.enabled` | `APP_OWNERSHIP_EFFECTIVE_CACHE_ENABLED` | `false` | Cached ownership filter/coverage reads and the per-minute cache refresh; needed before read waves at expected size |
| `app.ownership.read-waves.inventory` / `.findings` | — | empty (off) | `*` or tenant IDs whose asset/finding reads use canonical ownership |
| `app.ownership.servicenow.producer-enabled` | — | `false` | Publish ServiceNow ownership claims after each successful CMDB sync (`department-claims` adds the department field, default `false`) |
| `app.ownership.maintenance.cron` / `batch-size` / `max-batches-per-tenant` | — | `0 * * * * *` / `500` / `20` | Ownership maintenance schedule and bounds |
| `spring.datasource.url` | `DB_URL` (or `DB_HOST`/`DB_PORT`/`DB_NAME`) | `jdbc:postgresql://localhost:5432/vulnwatch` | Database URL |
| `app.openai.enabled` | `OPENAI_ENABLED` | `false` | Local opt-in only; deployed pilot hard off before key resolution |
| `app.openai.api-key` | `OPENAI_API_KEY` | — | OpenAI API key |
| `app.nvd.api-key` | `NVD_API_KEY` | — | NVD API key (higher rate limit) |
| `app.email.resend.api-key` | `RESEND_API_KEY` | — | Resend email API key |
| `app.github.api-token` | `GITHUB_API_TOKEN` | — | GitHub personal access token |
| `app.ai-security.jobs.poll-interval-ms` | — | `3000` | `AiSecurityJobWorkerService` poll interval |
| `app.ai-security.grid.exposure-freshness-ms` | — | `60000` | `AiGridExposureFreshnessService` sweep interval |
| `app.ai-security.azure.credential-expiry-cron` | — | `0 20 2 * * *` | `AiSecurityAzureCredentialExpiryService` daily cron |
| `app.ai-security.runtime.enabled` | `APP_AI_SECURITY_RUNTIME_ENABLED` | `false` | Must stay `false` — `ProductionSafetyValidator` fails startup in every environment if set (`RUNTIME_OUT_OF_SCOPE`) |
| `app.ai-security.runtime.adapter.poll-interval-ms` | — | `2000` | `AiGridRuntimeIngestionWorker` poll interval (worker is inert while runtime is out of scope) |
| `app.ai-security.runtime.adapter.worker-enabled` | — | `true` | Kill switch for `AiGridRuntimeIngestionWorker` |
| `app.ai-security.runtime.adapter.max-backlog-per-tenant` | — | `100` | Per-tenant queued-batch cap before admission returns `INGESTION_CAPACITY_EXHAUSTED` |
| `app.ai-security.runtime.evaluation-lookback-days` | — | `14` | `AiGridRuntimeEvaluationService` lookback window (deferred with runtime) |

---

## Scheduled Jobs

All cron times below are UTC. The [schedule matrix](<../Working Knowledge/AWS/PHASE_3_SCHEDULE_MATRIX.md>) is the complete role/flag/claim inventory; deployed settings and replicas remain unverified.

| Time | Job |
|------|-----|
| `00:15` daily | Lifecycle date sweep (EOL/EOS transitions) |
| `01:00` daily | NVD incremental + KEV sync |
| `01:15` daily | GHSA sync |
| `01:45` daily | Microsoft + Red Hat CSAF/VEX sync |
| `02:05` daily | Mark stale assets inactive |
| `02:30` daily | VEX staleness recompute |
| `03:15` daily | EPSS score refresh |
| `02:00` daily | EUVD sync |
| `02:30` daily | JVN sync |
| `02:45` daily | OSV advisory sync (`OsvPlatformService`) |
| Disabled | Unfinished per-tenant OSV correlation (`OsvTenantService`) |
| `07:00` daily | Bidirectional ticket sync (ServiceNow and Jira) |
| `02:00` Sunday | EOL catalog refresh (stage 1) |
| `03:00` Sunday | EOL release data (stage 2) |
| `03:30` Sunday | EOL slug resolution (stage 3) |
| `04:00` Sunday | EOL denormalization (stage 4) |
| Every 5 min | GitHub SBOM sources |
| Every 5 min | Enabled ServiceNow / SCCM / AWS / GCP Discovery scheduled syncs; generic Azure contained |
| Every 15 min | Reopen expired suppressions |
| Every 2 sec | Drain `finding_delta_queue` (batches of 100) |
| Every 2 sec | Poll `ingestion_jobs` queue (`IngestionJobWorkerService`) |
| Every 5 sec | Poll queued vulnerability ingestion runs (`VulnerabilityQueuedRunWorkerService`) |
| Every 5 min | Refresh stale finding projections (`FindingProjectionMaintenanceService`) |
| Every 5 min | Reconcile BOM projection drift (`BomProjectionReconciliationService`) |
| Every 30 sec | Performance telemetry snapshot refresh |
| Hourly | Policy-based auto-close findings |
| Hourly (at :10) | Demo tenant expiry check |
| Every 30 min (default) | Entitlement shadow-mode sweep (`EntitlementShadowSweepService`) — recomputes corrected-vs-legacy entitlement decisions for every active tenant/key |
| Every 30 sec (default) | Demo dataset provisioning poll (`DemoDatasetProvisioningService`) — seeds/repairs requested tenants' demo data once `ACTIVE` |
| Every 1 min (default) | Recover stale `PROCESSING` finding-delta-queue entries (`FindingDeltaQueueService.recoverStaleProcessingEntriesOnSchedule` — sibling of the 2s drain above) |
| Every 3 sec (default) | Poll `ingestion_jobs` for AI Security AWS/Azure/Copilot Studio discovery jobs (`AiSecurityJobWorkerService`) |
| Every 2 sec (default) | `AiGridRuntimeIngestionWorker` poll — returns immediately while runtime is out of scope (`AiRuntimeScope.excluded()`) |
| Every 5 sec (default) | Claim and process AI Grid assessment work (`AiGridAssessmentWorker.recover`) and AI-BOM projection jobs (`AiBomProjectionWorker.poll`); AI-BOM reconcile every 60 sec |
| Every 60 sec (default) | Poll Copilot Studio connector schedules (`CopilotStudioScheduleService`) |
| Every 5 min (default) | BOM contribution backfill (`BomContributionBackfillService`) |
| Daily `02:17` (default) | AI runtime execution retention purge (`AiAgentExecutionRetentionService`) — no-op while runtime is out of scope |
| Every 60 sec (default) | Demote AI Grid validated exposures with expired evidence (`AiGridExposureFreshnessService`) |
| Daily `02:20` (default) | Sweep Azure AI credential profiles for expiry (`AiSecurityAzureCredentialExpiryService`) |
| Every 5 sec (default) | Process pending AI Grid policy rollout tasks (`AiGridPolicyRolloutService.processPendingTasks`) |
| Every 5 sec (default) | Process pending AI Grid policy deprecation tasks (`AiGridPolicyDeprecationService.processPendingTasks`) |
| Midnight | Re-run all approved suppression rules |
| Every 1 min (default) | Ownership maintenance (`OwnershipMaintenanceJob.run`): claim expiry, re-resolution queue, CORE asset/finding linking once CORE leaves LEGACY, effective-cache refresh when enabled. Skipped on `api` and `schema-migrator` nodes |
| Hourly at `:07` (default) | Ownership effective-cache reconciliation (`OwnershipMaintenanceJob.reconcileCache`); no-op while the cache is off |

---

## Actuator Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /actuator/health` | Overall health |
| `GET /actuator/health/readiness` | Readiness probe |
| `GET /actuator/health/liveness` | Liveness probe (health probes are enabled in the base profile; `application-prod.yml` additionally enables the liveness/readiness state indicators and adds `tenantSchemaReadiness` to the readiness group) |
| `GET /actuator/info` | Build info |
| `GET /actuator/prometheus` | Micrometer/Prometheus scrape endpoint; only exposed when `MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE` adds `prometheus` (default exposure is `health,info`) |

---

## Operational Metrics

`OperationalMetricsInterceptor` tracks response time (ms) and status for 40 metric keys (41 request routes; the three GitHub SBOM run routes share one key). Metrics are exposed for query via `OperationalDashboardController`.


## AI-BOM dependency correlation evidence

`AiBomDeclaredResourceController` adds `GET /api/bom/declared-resources/{resourceId}/correlation?history=false&page=0&size=50`. The caller must own the resource and have an existing declared-resource read role. `history=true` returns retired dependency paths/associations; current reads return active support and unresolved gaps. Page size is capped at 100, and component labels are loaded in one batch. Detail responses include the first current evidence page in the additive `correlation` field. Existing `/findings` responses preserve their shape and include only ACTIVE associations, regardless of the independent finding workflow status.

Evidence contains ordered component and relationship IDs, source revision, match method, lifecycle history, uncertainty qualification, and gap remediation. Gaps can exist without a finding/link. The production sweep establishes tenant context before invoking the transaction-owning reconciler through a Spring proxy; locks source then resource, validates captured revision, and holds the source lock until commit. Replacement uploads and document soft deletion acquire the same source lock. A failed unit rolls back and does not prevent other resources or tenants from progressing.

`AI_BOM_CORRELATION_WRITES_ENABLED=true` and `AI_BOM_CORRELATION_RETIREMENT_ENABLED=false` are the defaults. Observe desired versus active associations and backfill/repair subjects before enabling retirement. Set both flags false for rollback without undoing the forward migration or interrupting canonical software correlation. Traversal limits use `AI_BOM_CORRELATION_MAX_DEPTH/NODES/EDGES/PATHS`; see the archived release evidence (`Other Docs/Archive/ai-bom-correlation-release-evidence.md`) for validation and rollout accounting. Scheduling-state updates cannot overwrite the source's current document/revision.
