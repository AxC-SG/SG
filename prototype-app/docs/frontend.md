# Frontend Reference

This document describes the React/TypeScript frontend for VulnWatch (package name `vulnwatch-frontend`). It is derived entirely from reading the source code in `frontend/src/`.

Last updated: 2026-10-21

---

## 1. Tech Stack

| Concern | Library / Version |
|---|---|
| UI framework | React 18.3.1 |
| Language | TypeScript 5.5.4 |
| Build tool | Vite 5.4.2 |
| Routing | React Router DOM 7.13.2 |
| Server state | @tanstack/react-query 5.95.2 |
| Table | @tanstack/react-table 8.21.3 |
| Error monitoring | @sentry/react 10.51.0 |
| Report export | docx 9.6.1 |
| HTTP | Native `fetch` (no axios) |
| Test runner | Vitest 4.0.18 |
| Test utilities | @testing-library/react 16.3.2, @testing-library/jest-dom 6.9.1 |
| Coverage | @vitest/coverage-v8 4.1.5 |
| Lint | ESLint 9.39.4 + typescript-eslint 8.57.2 + eslint-plugin-react-hooks 7.0.1 |
| DOM environment | jsdom 29.0.1 |

The app is a pure SPA. There is no SSR. All pages are lazy-loaded via `React.lazy`. The dev server runs strictly on port 5173 (`--strictPort`). Vite proxies `/api/**` to `http://localhost:8080` in dev so the frontend calls the backend without a separate CORS config.

**CI gate order:** `lint` → `typecheck` → `build` → `test:coverage`. All four must pass.

---

## 2. Application Structure

```
frontend/src/
  main.tsx                  Entry point — Sentry init, QueryClientProvider, BrowserRouter, StrictMode
  App.tsx                   Root component — lazy routes, AppShell, AuthSessionBoundary, theme, impersonation
  api/
    client.ts               Single api object; 350+ backend calls; auth header injection
  api/base.ts               resolveApiBase (VITE_API_BASE / dev proxy / production default)
  app/
    routes.ts               Typed path-builder helpers and legacy query-param redirect logic
  features/                 Feature-colocated modules; types live here, not in src/types/
    auth/                   ActorContext type, context/provider, role helpers, entitlements, queries
    findings/               Finding type, queries, filters
    cve-workbench/          OrgSpecificCveExposureRecord, CveDetail, assessment helpers, scoring
    configurations/         RiskPolicy, OwnershipRule, SuppressionRule
    inventory/              Asset, HostAssetDetail, InventoryComponentPage, searchState, helpers
    connect/                Connector configs, SyncRun types, queries
    operations/             OperationalDashboard, SLO, quality types and queries
    dashboard/              Dashboard type and queries
    vuln-repo-dashboard/    VulnRepoDashboard type and queries
    software-identities/    SoftwareIdentitySummary, detail, funnel queries
    eol/                    EolSummary, PackageEolStatus, catalog queries
    admin/                  Tenant, PlatformUser, ServiceAccount, AuditEvent, admin queries
    campaigns/              Remediation campaign types + CampaignDetailPage; API calls inlined (no queries.ts)
    ai-security/            AI Security / AI Grid types, dependency graph, category helpers (entitlement-gated)
    widgets/                FplWidgets.tsx — DonutChart, HBarChart, WidgetCard SVG components
  lib/
    riskScoring.ts          Pure TS: computeCveRiskScore, computeFindingPriorityScore
    queryClient.ts          createQueryClient factory (retry:1, staleTime:10s, no refetchOnWindowFocus)
    polling.ts              Refresh interval constants
    queryPolling.ts         visibleInterval / isDocumentVisible helpers
    performanceMonitoring.tsx  API/render timing telemetry
    time.ts                 timeAgo, formatTimestamp helpers
  pages/                    One file per route; lazy-loaded in App.tsx
  components/               Shared presentational components (max ~300 lines each)
  hooks/
    useDebouncedValue.ts    Debounce hook with immediate-clear for empty strings
  types/
    index.ts                Re-exports only — source of truth is always the feature directory
    ownership.ts            OwnershipSummary type
  styles/
    index.css               Imports all CSS files
    base.css                CSS custom properties + font imports
    shared.css              Global layout classes, buttons, pills, badges
    cve-workbench.css       CVE workbench-specific styles
    connect.css             Connector page styles + SBOM wizard
    eol.css                 EOL page styles
    vuln-repo.css           Vuln repo page styles
    user-management.css     User management page styles
    exposure-dashboard.css  Exposure dashboard exec-* classes
    finding-detail.css      Finding detail page styles
    findings-list.css       Findings list page styles
    ai-security.css         AI Security / AI Grid page styles
  test/
    setup.ts                @testing-library/jest-dom/vitest import; ResizeObserver and DOMMatrixReadOnly stubs for @xyflow/react
    test-utils.tsx          renderWithProviders — QueryClientProvider (retry: false) + MemoryRouter
    fixtures.ts             buildFinding, defaultRiskPolicy, defaultFindingFilterValues, pageOf, findingPageOf
```

### Route Table

All routes are registered in `src/App.tsx` using React Router v7 nested routes. Pages are loaded with `React.lazy`. The `AuthSessionBoundary` component wraps every authenticated route and redirects to `/login` when `useActorQuery()` returns no data.

| Path | Page Component | Purpose |
|---|---|---|
| `/` | `HomeRoute` (role-based redirect) | → `/exposure`, `/configurations`, or `/platform/tenants` depending on actor role |
| `/exposure` | `ExposureDashboardPage` | Risk-focused exec overview (Overview tab) |
| `/findings` | `FindingsPage` | Active findings list with server+client-side filters |
| `/findings/:displayId` | `FindingDetailPage` | Single finding detail, workflow, and AI remediation |
| `/fix-intelligence/*` | Redirect to `/findings` | Synthetic Fix Intelligence is unavailable |

| `/operations/:operationsView?` | `OperationalDashboardPage` | Default `pipeline`; also `platform-health` (the `quality` view now redirects to `/inventory` with quality-tab search params instead of rendering here — see note below) |
| `/vuln-repo` | `VulnRepoDashboardPage` | Vulnerability Repository dashboard |
| `/vuln-repo/org-cves/:cveId?` | `VulnRepoWorkbenchRoute` (`VulnRepoOrgCvePage`) | Unified Vulnerability Records — CVE Assessment Workbench |
| `/vuln-repo/vulnerabilities` | `VulnRepoVulnerabilitiesPage` | Vulnerability Intelligence — global CVE feed |
| `/vuln-repo/intel/:externalId` | `PlatformVulnIntelDetailPage` | Platform-scoped intel detail |
| `/vuln-repo/campaigns` | `CampaignsPage` | Remediation campaign list |
| `/vuln-repo/campaigns/:id` | `CampaignDetailPage` | Campaign detail — lifecycle, exceptions, notify groups, watchlist |
| `/vuln-repo/software-assets` | `VulnRepoSoftwareAssetsPage` | Software-centric asset breakdown |
| `/vuln-repo/host-assets/:assetId` | `VulnRepoHostAssetRoute` | Host asset detail (vuln-repo context) |
| `/vuln-repo/org-cves/:cveId/assets` | `VulnRepoCveAssetsPage` | Per-CVE affected asset breakdown |
| `/vuln-repo/org-cves/:cveId/software` | `VulnRepoCveSoftwarePage` | Per-CVE affected software breakdown |
| `/inventory/:inventoryView?` | `InventoryRoute` (dispatches sub-views) | Default `overview`; `ai` sub-view shows `AiInventoryPage` |
| `/inventory/hosts/:assetId` | `InventoryHostAssetRoute` | Host asset detail |
| `/inventory/software-identities/:softwareIdentityId` | `SoftwareIdentityDetailRoute` | Software identity detail |
| `/inventory/ai/assets` | `AiInventoryAssetsPage` | Filterable list of all discovered AI artifacts (AWS/Azure) — entitlement-gated (`ai.security`) |
| `/inventory/ai/knowledge-data` | `AiKnowledgeMcpInventoryPage kind="knowledge-data"` | AI knowledge/data-source artifact inventory with sensitivity/PII posture |
| `/inventory/ai/mcp` | `AiKnowledgeMcpInventoryPage kind="mcp"` | MCP (Model Context Protocol) server artifact inventory |
| `/inventory/ai/overview`, `/inventory/ai/agents`, `/inventory/ai/agent-versions` | `AiInventoryPage` / `AiInventoryAssetsPage` | Alias routes for AI inventory sub-views — entitlement-gated (`ai.security`) |
| `/inventory/ai/declared-resources[/:resourceId]` | `AiBomDeclaredResourcesPage`, `AiBomDeclaredResourceDetailPage` | AI-BOM declared models/datasets and deployment-mapping workflow — entitlement-gated; declared above `/inventory/ai/:assetId` |
| `/inventory/ai/executions` | Redirect | Legacy bookmarks return to `/inventory/ai`; no runtime request |
| `/inventory/ai/:assetId` | `AiAssetDetailPage` (via `InventoryAiAssetRoute`) | Single AI artifact detail — overview/policies/findings/relationships + dependency graph |
| `/findings/ai` | `AiFindingsPage` | Deterministic AI policy-failure findings (separate stream from CVE findings) |
| `/findings/ai/vulnerabilities` | `AiFindingsPage` (Software Vulnerabilities tab) | Canonical `VULNERABILITY` findings affecting declared AI-BOM resources |
| `/findings/ai/:findingId` | `AiFindingDetailPage` (via `AiFindingDetailRoute`) | AI finding detail — evidence, review workflow, ServiceNow incident creation |
| `/findings/ai/exposures` | `AiExposuresPage` | Cross-system "AI Grid" validated exposure paths |
| `/findings/ai/exposures/:exposureId` | `AiExposuresPage` (detail branch) | Single exposure detail — root cause, evidence history, accept/false-positive disposition |
| `/policies` | `AiPoliciesPage` | Tenant AI Grid workspace — policy selection plus framework coverage, latest assessment-state totals, with runtime telemetry deferred |
| `/policies/:policyId` | `AiPolicyDetailPage` (via `AiPolicyDetailRoute`) | AI policy detail — overview/configure(scope, exceptions, parameters)/findings/artifacts tabs |
| `/connect/:connectView?` | `ConnectRoute` (`ConnectPage`) | Default `sources`; also `run-history` |
| `/connect/copilot-studio` | `CopilotStudioConnectorPage` | Microsoft Copilot Studio connector config — entitlement-gated (`ai.security`) |
| `/admin/:adminView?` | `AdminRoute` (`UserManagementPage`) | Default `users`; also `invites`, `roles`, `service-accounts`, `audit` (no `support-access` route view exists) |
| `/platform/:platformView?` | `PlatformRoute` (`PlatformConsolePage`) | Default `tenants`; platform owner console. `ai-policies` sub-view renders `PlatformAiPolicyStudio` for global governed catalog/distribution/rollout; tenant coverage and telemetry are intentionally absent until a workspace is selected. Nav label: "Policy Distribution" |
| `/platform/ai-policies/:policyId` | `PlatformAiPolicyDetailRoute` | Platform AI policy detail (`/vuln-repo/policies` redirects to `/platform/ai-policies`) |
| `/configurations/:configView?` | `ConfigurationsPage` | Default `sla`; SLA, Triage, Automation, Ownership, Findings Score, Suppression, Auto-Finding (Vulnerability Sources moved to the Connect page — see below) |
| `/authorized-workspaces` | `AuthorizedWorkspacesRoute` (`AuthorizedWorkspacesPage`) | Platform-owner-only list of tenant-approved support access grants |
| `/demo` | `DemoLandingPage` | Public demo landing |
| `/demo/blog` | `BlogIndexPage` | Public demo blog index |
| `/demo/blog/zero-day-response-hours-not-weeks` | `ZeroDayBlogPage` | Public demo blog post |
| `/demo/blog/mythos-readiness` | `MythosReadinessBlogPage` | Public demo blog post |
| `/demo/blog/why-your-sbom-tool-doesnt-know-whats-exploitable` | `SbomExploitabilityBlogPage` | Public demo blog post |
| `/demo/request` | `DemoRequestPage` | Demo request form |
| `/demo/request/success` | `DemoRequestSuccessPage` | Demo request success |
| `/demo/expired` | `DemoExpiredPage` | Demo expiry notice |
| `/invite/:token` | `DemoInvitePage` (public) | Demo invite accept flow |
| `/tenant-invite/:token` | `TenantInvitePage` (public) | Tenant invite accept flow |
| `/setup/:token` | `SetupSessionPage` (public) | Platform-owner one-time password-setup link |
| `/login` | `LoginPage` | Login |
| `*` | Redirect to `/` | Catch-all fallback |

**`/end-of-life` no longer renders a dedicated `EolPage`.** `EndOfLifeRoute` redirects to `/platform/eol` for platform-scope owners, or `/exposure` otherwise.

**Legacy redirects:** `LegacyQueryRedirect` in `App.tsx` intercepts old `?tab=inventory&inventoryView=hosts` style URLs and converts them via `buildLegacyCompatiblePath()` in `src/app/routes.ts`. Separately, `/vulnerability-intelligence`, `/vulnerability-intelligence/vulnerabilities`, and `/vulnerability-intelligence/org-cves/:cveId?` redirect to their `/vuln-repo/*` equivalents.

**AI Security routing:** all `/findings/ai*`, `/policies*`, and `/inventory/ai*` routes are wrapped in `AiSecurityRoute`, which redirects to `/exposure` unless `canUseEntitlement(actor, 'ai.security')` is true and the actor is not in platform scope. Unlike `/operations/:operationsView?` or `/inventory/:inventoryView?`, there is no shared `:aiView?` optional-param pattern — each AI Security sub-page is its own literal route. Nav entry points: the sidebar "Findings" button expands into "Vulnerability Findings" / "AI Findings" sub-items when the entitlement is enabled; a top-level "Policies" nav tab appears next to Vuln Repo/Campaigns; the Inventory pill list gains an "AI Inventory" entry; the Connect page gains two connector cards (`ai-security-aws`, `ai-security-azure`); and the Platform Console gains an `ai-policies` sidebar view.

---

Generic Azure and SCCM pages show disabled/read-only status; their APIs independently refuse changes/tests/runs. `/fix-intelligence/*` redirects to `/findings`. Unsupported patch cards/forms have been retired as documented [in the connector inventory](#connect-srcfeaturesconnect); old query IDs and direct paths cannot mount them.

## 3. Authentication and Auth Flow

JWT authority is revalidated server-side against current users, global grants, memberships/support and machine registry. Claims select a tenant; they do not grant membership or ownership. Browser role/entitlement gates are presentation controls alongside server checks.

### Token storage

- `getStoredAuthToken()` reads only the `localStorage` key `vulnwatch.authToken` (empty string if absent). It does not read an environment fallback.
- `applyAuthHeaders()` separately uses development-only `VITE_AUTH_TOKEN` after the stored token. The stored token takes precedence; production static-auth inputs are rejected at build time.
- Managed by `getStoredAuthToken()`, `setStoredAuthToken()`, `clearStoredAuthToken()` exported from `src/api/client.ts`.

### Request auth header injection

`applyAuthHeaders()` in `src/api/client.ts` runs on every authenticated request:

1. If `getStoredAuthToken()` returns a token, sends `Authorization: Bearer <token>`.
2. Otherwise (local dev), falls back to `X-API-Key: <VITE_API_KEY>` + `X-Creator-Key: <VITE_CREATOR_KEY>`.

### Session lifecycle

1. `useActorQuery()` in `src/features/auth/queries.tsx` calls `GET /api/me` (via `authApi.getActorContext`). The React Query key includes the raw token value with a 60-second stale time. This remains a raw-token key in current source, not an opaque epoch; logout also clears the shared query cache. Do not log/export query keys or token-bearing state.
   - `staleTime`: 60 seconds.
   - `AUTH_CONTEXT_QUERY_ROOT = ['auth-context']`.
2. `AuthSessionBoundary` in `App.tsx` wraps all authenticated routes. It renders a redirect to `/login` when the query fails or returns no actor data.
3. The loaded `ActorContext` is published into React context via `ActorContextState = React.createContext<ActorContext | null>(null)`. Read it with `useActor()` from `src/features/auth/context.ts`.

### ActorContext type (source: `src/features/auth/types.ts`)

Key fields:
- `creator`, `principal`, `userId`, `tenantId`, `tenantName`
- `roles: string[]`, `allowedTenants: AllowedTenant[]`
- `platformScope?: boolean` — user is a platform owner who has not yet entered a tenant; in this state, tenant-scoped routes redirect to `/platform/tenants`
- `actingAsPlatformOwner?: boolean` — set after `selectTenantContext` when acting on behalf of a tenant
- `sensitiveActionConfirmationRequired?: boolean`
- `planCode?`, `demoExpiresAt?`, `demoDaysRemaining?`

### Role helpers (source: `src/features/auth/roles.ts`)

All role checks must go through these helpers — never read `actor.roles` directly. They normalize `ROLE_` prefixes and handle `platformScope` edge cases.

| Function | Purpose |
|---|---|
| `hasRole(actor, role)` | Check for a single role |
| `hasAnyRole(actor, roles)` | Check for any of the listed roles (takes an array) |
| `canManageTenant(actor)` | ROLE_TENANT_ADMIN |
| `canAccessPlatformConsole(actor)` | ROLE_PLATFORM_OWNER |
| `canManageInventorySources(actor)` | ROLE_TENANT_ADMIN or ROLE_INVENTORY_ADMIN |
| `canManageRiskPolicy(actor)` | ROLE_PLATFORM_OWNER or ROLE_TENANT_ADMIN, not in platform scope |
| `canRunSecurityWorkflow(actor)` | ROLE_PLATFORM_OWNER, ROLE_TENANT_ADMIN, or ROLE_SECURITY_ANALYST, not in platform scope |
| `canViewReadOnly(actor)` | Any role, not in platform scope |
| `canRefreshTenantExposure(actor)` | Same roles as `canRunSecurityWorkflow` |
| `canManageUsers(actor)` | ROLE_TENANT_ADMIN |
| `canManageServiceAccounts(actor)` | ROLE_TENANT_ADMIN |
| `canExportAudit(actor)` | ROLE_TENANT_ADMIN or ROLE_READ_ONLY_AUDITOR |
| `canManageSourceFilters(actor)` | ROLE_PLATFORM_OWNER, or ROLE_TENANT_ADMIN / ROLE_SECURITY_ANALYST when not in platform scope |

`isPlatformScopeOnly` (`platformScope` and ROLE_PLATFORM_OWNER) is a module-private helper in `roles.ts`, not exported.

### Entitlements (distinct from roles)

`TenantEntitlementService` uses one effective resolver for backend enforcement and the `/me` snapshot. Corrected precedence is an active tenant override, then plan value, then disabled default; expired overrides fall through. LEGACY and SHADOW retain legacy allow behavior; ENFORCE applies corrected decisions only to explicit tenant UUIDs or `slug:<tenant-slug>` cohort entries. Outside that cohort behavior remains SHADOW; null/platform snapshots are empty. Wildcards and invalid modes/cohorts are rejected. Deployed pilot startup requires ENFORCE and a named cohort (committed default `slug:scoutgrid-internal-pilot`); effective deployed settings still need qualification. Roles, lifecycle, provider availability and independent containment remain additional checks: an entitlement never enables SCCM JDBC, generic Azure, runtime evidence or pilot generative assistance.

`src/features/auth/entitlements.ts` introduces a second, orthogonal access concept alongside roles: **entitlements** are per-tenant, plan-based feature flags (e.g. `ai.security`) rather than per-user permissions. `canUseEntitlement(actor, key)` checks the actor's entitlement snapshot from the backend and **fails closed** — an entitlement not explicitly present/enabled is treated as disabled. `AI_ENTITLEMENT_KEYS` currently gates the entire AI Security / AI Grid feature surface (routes, nav items, `AiInventoryOverviewStrip`). Role helpers (`hasRole`, etc.) still govern *what an authenticated user with access can do*; entitlements govern *whether the tenant's plan includes the feature at all*.

### Multi-tenant switching

- `api.selectTenantContext(tenantId)` — LOCAL-mode authorized membership/support selection; returns an `AuthTokenResponse` with an explicit access mode/reference, revalidated on later requests. EXTERNAL disables local token issuance.
- `api.clearTenantContext()` — LOCAL-mode return to platform scope (also an `AuthTokenResponse`).
- Both are used in `PlatformConsolePage` and the `AppShell` tenant switcher.
- `setStoredAuthToken()` is also called on login to store the returned token.

---

## 4. Feature Modules

Each module under `src/features/<feature>/` owns its TypeScript types, queries, and optionally API calls and helpers.

### auth (`src/features/auth/`)

Files: `types.ts`, `context.ts`, `provider.tsx`, `roles.ts`, `entitlements.ts`, `api.ts`, `queries.tsx`

`ActorContext` and `AllowedTenant` types; `ActorContextState` React context; `useActor()` hook; `useActorQuery()` React Query hook; all role-check functions.

### findings (`src/features/findings/`)

Files: `types.ts`, `queries.ts`, `hooks.ts`, `components/`

**Finding type** (50+ fields): `id`, `displayId`, `componentId`, `assetName`, `vulnerabilityId`, `severity` (CRITICAL/HIGH/MEDIUM/LOW), `status` (OPEN/RESOLVED/SUPPRESSED/AUTO_CLOSED), `decisionState`, `inKev`, `epss`, `riskScore`, `vexStatus`, `isEol`, `incidentId`, `findingsScore`, `ownership: OwnershipSummary`, and many more.

Supporting types: `FindingPage`, `FindingFilterValues`, `FindingBulkWorkflowRequest`, `FindingBulkWorkflowResponse`, `FindingTimeline`, `VulnerabilityDetail`.

Queries:
- `useFindingsQuery(params)` — queryKey `['findings', params]`, uses `keepPreviousData`
- `useFindingFiltersQuery()` — queryKey `['finding-filters']`
- Also `useFindingSummaryQuery`, `useFindingDistributionsQuery`, `useFindingBacklogHealthQuery`, `useFindingProjectionStatusQuery`, `useFindingQueuesQuery`, `useFindingGroupsQueries`, `useRebuildFindingProjectionMutation`

### cve-workbench (`src/features/cve-workbench/`)

Files: `types.ts`, `api.ts`, `queries.ts`, `assessment-helpers.ts`, `formatting.ts`, `asset-report.ts`, `workflow.ts`, `view-helpers.ts`, `view-models.ts`, `investigation-context.ts`, `eol-helpers.ts`

**Core types:**
- `OrgSpecificCveExposureRecord` — org-correlated CVE with `recordId`, `vulnerabilityId`, `severity`, `cvssScore`, `epssScore`, `inKev`, `matchedAssetCount`, `matchedSoftwareCount`, `eolComponentCount`, `openFindings`, `applicability`, VEX component counts
- `CveDetail` — full CVE detail with `summary`, `signals`, `investigations`, `assessments`, `matchedSoftware`, `vendorIntelligence`, `sourceRecords`, `fixes`
- Payload/response types for all CVE workflow operations

**`cveWorkbenchApi` object** (separate from the main `api`): `listVulnRepoVulnerabilities`, `listOrgSpecificCves`, `getCveDetail`, `createManualFindings`, `createServiceNowIncident`, `getSavedInvestigationSummary`, `getSavedAiSolution`, `generateAiSolution`, `generateAiRequiredActions`, `getFixRecords`, `generateFixRecords`, `saveAnalystFixes`

**Queries:** `useVulnRepoVulnerabilitiesQuery()`, `useOrgSpecificCvesQuery()`, `useOrgSpecificCveAutomationStatusQuery()` (polls at `ORG_CVE_STATUS_REFRESH_INTERVAL_MS = 10s` when `pendingEventCount > 0`), `useCveDetailQuery()`, `useSavedInvestigationSummaryQuery()`, `useSavedAiSolutionQuery()`, `useRiskPolicyQuery()`

**Assessment helpers** (`assessment-helpers.ts`): `parseCvssVector`, `confidenceFromApplicability`, `matchBasisLabel`, `buildSoftwareGroups`, `applicableSoftwareRows`, `buildFindingDisplayRows`, `computedImpactStateOf`, `deriveAssessmentResult`, `exactMatchMeta`, `explainApplicability`, `initialApplicabilityDecision`, `priorityFromSeverityAndImpact`, `vendorStatementFor`

Types: `ApplicabilityDecision` (`APPLICABLE | NOT_APPLICABLE | NEEDS_REVIEW`), `ImpactDecision` (`IMPACTED | NOT_IMPACTED | UNKNOWN`), `SoftwareGroup`, `FindingDisplayRow`

**Formatting helpers** (`formatting.ts`): `formatDateTime`, `formatDate`, `formatLabel`, `severityClassName`, `statusClassName`, `softwareLabel`

### configurations (`src/features/configurations/`)

Files: `types.ts`

**RiskPolicy** (key fields):
- Score thresholds: `criticalThreshold`, `highThreshold`
- SLA deadlines: `criticalSlaDays`, `highSlaDays`, `mediumSlaDays`, `lowSlaDays`
- Asset SLA multipliers (criticality-based)
- Automation: `autoCloseEnabled`, `autoCloseAfterDays`, `findingGenerationMode`
- Custom scoring: `findingsScoreConfig` (JSONB)
- **6 triage weight fields (frontend-only; the backend `RiskPolicy` has none):** `triageExploitabilityWeight`, `triageBlastRadiusWeight`, `triageEolRiskWeight`, `triageSlaBreachWeight`, `triageMissingOwnerBoost`, `triagePatchGapBoost`

Other types: `SuppressionRule`, `SuppressionRuleRequest` (fields: `name`, `state` DRAFT/APPROVED/IN_REVIEW/REJECTED/EXPIRED, `recordType` CVE/FINDING, `validFrom`, `validTo`, `executionOrder`, `reason`), `OwnershipRuleResponse`, `OwnershipRuleRequest`

### inventory (`src/features/inventory/`)

Files: `types.ts`, `api-types.ts`, `queries.ts`, `helpers.ts`, `searchState.ts`, `useInventoryData.ts`, `InventoryShell.tsx`

**InventoryViewKey:** `'overview' | 'software-identities' | 'hosts' | 'container-images' | 'sbom'`

**API types:** `Asset`, `HostAssetSummary`, `HostAliasRecord`, `HostSoftwareInstanceRecord`, `HostFindingRecord`, `HostApplicableCveRecord`, `HostAssetDetail`, `InventoryComponentRecord`, `InventoryComponentPage`, `InventoryComponentFilterValues`

**Queries:** `useInventoryComponentsQuery(params)`, `useInventoryComponentFiltersQuery()`, `useHostAssetDetailQuery(assetId, sourceSystem?)`

**Search state** (`searchState.ts`): URL search parameter helpers for inventory views. Keys: `INVENTORY_QUERY_QUERY_KEY`, `INVENTORY_SOURCE_SYSTEM_QUERY_KEY`, `INVENTORY_GROUP_BY_QUERY_KEY`, `HOST_QUICK_FILTER_QUERY_KEY`, `HOST_ENVIRONMENT_QUERY_KEY`, `HOST_OPERATING_SYSTEM_QUERY_KEY`, `HOST_ASSET_QUERY_KEY`, `HOST_REVIEW_CATEGORY_QUERY_KEY`. Helpers: `readInventoryQueryFromSearch`, `writeInventoryQueryToSearch`, `readInventoryGroupByFromSearch`, `writeInventoryGroupByToSearch`, `readSearchValueFromSearch`, `writeSearchValueToSearch`, `readSearchValuesFromSearch`, `writeSearchValuesToSearch`, `readHostReviewCategoriesFromSearch`, `writeHostReviewCategoriesToSearch`, `clearHostInventorySearchState`

**Helpers** (`helpers.ts`): `defaultAssetTypeForView`, `formatAssetType`, `formatInventorySourceSystem` (maps `upload`->`Legacy Upload`, `api`->`API Endpoint`, `github`->`GitHub Generated`, `servicenow`->`ServiceNow`), `formatInventoryLabel`, `formatHostReviewLabel`, `buildHostReviewLabels`, `normalizeHostReviewCategory`

**`useInventoryData(args)`** (`useInventoryData.ts`): wraps `useInventoryComponentsQuery` and `useInventoryComponentFiltersQuery`, normalizes filter option values, exposes `refreshInventory()`.

**Host group-by options in InventoryPage:** `operatingSystem`, `environment`, `status`, `owner`, `sourceSystem`

**Host quick filters:** `all | online | with-findings | with-cves | with-eol | external-with-cves | linux | windows`

### connect (`src/features/connect/`)

Files: `types.ts`, `queries.ts`

**Types:** `SyncRun`, `IngestionResult`, `SyncTriggerResponse`, `ServiceNowCmdbConfig/Request`, `SccmCmdbConfig/Request`, `AwsDiscoveryConfig/Request`, `AwsDiscoveryTarget/Request`, `GithubSbomSource`, `VulnerabilitySourceFilterConfig/Request`

**Queries:** `useSyncRunsQuery(params)` — auto-polls at `RUN_QUEUE_REFRESH_INTERVAL_MS = 3s` while any run has status RUNNING/STARTED/QUEUED; `useIngestionJobsQuery(enabled?)` — `refetchOnMount: 'always'` (so opening the run queue always reconciles with the server instead of trusting a possibly-stale cached list) and auto-polls at the same 3s interval while any job is QUEUED or RUNNING (widened from QUEUED-only); `useVexAssertionRepairSummaryQuery()`, `useSourceFilterConfigQuery(sourceSystem)`, `useGithubSbomSourcesQuery()`, `useServiceNowCmdbConfigQuery()`, `useSccmCmdbConfigQuery()`, `useAwsDiscoveryConfigQuery()`, `useAwsDiscoveryTargetsQuery()`

**Run Queue (`InventoryRunQueuePage`, at `/connect/run-history`):** merges `useSyncRunsQuery`'s completed/active `SyncRun` rows with, for the async AI Security providers, in-flight `IngestionJob` rows from `useIngestionJobsQuery` while they're QUEUED, RUNNING, or FAILED (previously QUEUED-only, so a claimed/running job used to disappear from the queue). `hasReplacementSyncRun()` drops an ingestion-job row once a matching `SyncRun` for the same connector shows up, so a job doesn't double-render as it transitions from queued/running to a completed sync run. `formatSyncType` labels: `AI_SECURITY_AWS_BEDROCK` → "AWS AI Discovery", `AI_SECURITY_AZURE_DISCOVERY` → "Azure AI Discovery", and `AI_SECURITY_COPILOT_STUDIO` → "Microsoft Copilot Discovery". All three enter through `ingestion_jobs`; the worker creates the provider `SyncRun` only after it claims the job. Triggering a run from `AiSecurityAzureConnectorPage` or `CopilotStudioConnectorPage` invalidates the `ingestion-jobs` and `sync-runs` query caches (in addition to the connector's own scoped `ai-security-runs` query) so the new run appears in this queue immediately rather than on the next poll tick.

**Connector catalog card-grid rework (`ConnectPage`, `/connect/sources`):** the catalog no longer stacks connectors in a fixed two-column list; cards center in an auto-fill grid (`connect.css` steps the column count from five down to one as the viewport narrows — this ladder has to live in `connect.css`, not `base.css`, because `cve-workbench.css` loads later and would otherwise collapse the grid to one column below 1220px). Cards show each connector's real vendor mark as inline SVG (Microsoft's four squares, the `aws` wordmark, Azure's triangle, ServiceNow's `NOW` tile, BigFix's slate-blue "b", Tanium's red-disc "T") rather than a generic icon-well glyph, so no third-party logo files are committed to the repo. There's no room in the card for a stacked "Last sync · 2h ago" / "Failed · …" line, so connector health now lives on the status dot's `title`/`aria-label` — assert against the accessible label in tests, not card body text, when checking a failed-connector state.

Two connector-card sections render under `sources`: **Inventory** (CMDB, cloud, and entitlement-gated static AI sources) and **BOM Management** (`sbom-endpoint`, `bom-management`). Unsupported Patch Management IDs/cards and detail branches were removed; `SccmPatchConnectorPage`, `BigFixPatchConnectorPage`, `TaniumPatchConnectorPage` and the unused `PatchConnectorPage` mock catalog were retired, removing all their input/credential logging. The URL is the single selection source: only catalog IDs are accepted, invalid IDs are removed without dropping other query parameters, and direct unsupported `/connect/:connectView` paths normalize to Sources. Catalog, query, app-route and in-page navigation regressions cover this containment. See [repair evidence](<../Working Knowledge/AWS/DOCUMENTATION_RECONCILIATION.md#p30-frontend-repair>). Backend patch scaffolding remains unwired.

### operations (`src/features/operations/`)

Files: `types.ts`, `queries.ts`

**Types:** `OperationalDashboard` with sections `executiveHealth`, `ingestionEfficiency`, `normalizationQuality`, `correlationEffectiveness`, `noiseLifecycle`, `apiReadPath`, `freshnessDrift`, `metricCatalog`; `OperationalQualityIssue`, `OperationalQualityIssueDetail`, `SloStatus`, `SloEntry`. The type still exists but is no longer what the Pipeline view actually fetches — see `PipelinePayload` below.

**Queries:**
- `useOperationsViewQuery(selectedView)` — loads Pipeline or Platform Health data in parallel via `Promise.all`; `refetchInterval = OPERATIONS_REFRESH_INTERVAL_MS = 15s`. The Pipeline branch resolves a `PipelinePayload` (`{ ingestion, freshness }` only — normalization/correlation/noise are no longer fetched here; that analysis moved to Inventory's quality tabs).
- `useOperationalQualitySummaryQuery()`, `useOperationalQualityIssuesQuery()`, `useOperationalQualityIssueDetailQuery()`
- Mutations: `useApplyNormalizationOverrideMutation`, `useRevokeNormalizationOverrideMutation`, `useApplyCorrelationOverrideMutation`, `useRevokeCorrelationOverrideMutation`

### dashboard (`src/features/dashboard/`)

Files: `types.ts`, `queries.ts`

**Dashboard type:** `assets`, `components`, `openFindings`, severity counts, `topVulnerabilities`, `latestFindings`, `noiseReduction`, `csafVexAnalytics`, `correlationEfficiency`, `topAssetsAtRisk`, `openCritical/High/Medium/Low`, `averageOpenRiskScore`, `criticalFindings`

**Queries:** `useDashboardSummaryQuery()` — queryKey `['dashboard-summary']`, polls at `DASHBOARD_REFRESH_INTERVAL_MS = 4h`; `useDashboardCveInventoryMapQuery(limit)`, `useExposureSummaryQuery()`, `useGridExposureQuery()` (all on the same interval)

### vuln-repo-dashboard (`src/features/vuln-repo-dashboard/`)

Files: `types.ts`, `queries.ts`

**VulnRepoDashboard type:** `generatedAt`, `summaryCards: VulnRepoDashboardSummaryCards` (trackedCount, exploitCount, impactedKevCount, criticalUninvestigatedCount, kevReinvestigationCount, weekly deltas, etc.), `severityBreakdown`, `resolutionStatus`, `criticalUnresolved`, `topAffectedSoftware`, `recentAdvisories`, `impactedAssets`

**Query:** `useVulnRepoDashboardQuery(platformScope?)` — queryKey `['vuln-repo-dashboard', 'tenant' | 'platform']`

### software-identities (`src/features/software-identities/`)

Files: `types.ts`, `queries.ts`

**Types:** `SoftwareIdentitySummary`, `SoftwareIdentityDetail`, `SoftwareIdentityVersion`, `SoftwareIdentityAsset`, `SoftwareIdentityMetadata`, `SoftwareIdentityFunnel`, `VulnRepoSoftwareAssetsDetail`

**Queries:** `useSoftwareIdentitiesQuery(params)`, `useSoftwareIdentityFunnelQuery()`, `useSoftwareIdentityDetailQuery(softwareIdentityId)`, `useSoftwareIdentityMetadataQuery(softwareIdentityId)`, `useVulnRepoSoftwareAssetsQuery(softwareIdentityId)`

### eol (`src/features/eol/`)

Files: `types.ts`, `queries.ts`

**Types:** `EolSummary` (eolCount, nearEolCount), `ComponentEolStatus`, `EolProductCatalog`, `EolRelease`, `EolComponentPage`, `UnresolvedEolMapping`, `EolSlugSuggestion`, `PackageEolStatus`

**Queries:** `useEolSummaryQuery()`, `useEolComponentStatusesQuery(params)`, `useEolProductsQuery()`, `useEolReleasesQuery(slug)`, `useEolUnresolvedMappingsQuery(params)`, `useEolSlugSuggestionsQuery(normalizedKey)` (staleTime 5 min), `useEolPackageStatusesQuery(params)`, `useEolPackageAssetsQuery(params)`

### admin (`src/features/admin/`)

Files: `types.ts`, `queries.ts`, `csv.ts`

**Types:** `Tenant`, `TenantMember`, `PlatformUser`, `ServiceAccount`, `AuditEvent`, `AuthContext`, `DemoRequest`, `DemoInvite`, `AuthTokenResponse`, `TenantSupportGrant`, `InventoryConnectorHealth`, `TenantSchemaStatusItem`, `TenantSchemaStatusPage` *(new — tenant, schema, current/target version, structural checksum, failure code/message, migration timestamps)*

**Queries and mutations:** `useAuthContextQuery()`, `useTenantMembersQuery()`, `useTenantInvitesQuery()`, `useAddTenantMemberMutation()`, `useUpdateTenantMemberMutation()`, `useDeleteTenantMemberMutation()`, `useCreateTenantInviteMutation()`, `useCreateTenantBulkInvitesMutation()`, `useResendTenantInviteMutation()`, `useCancelTenantInviteMutation()`, `useServiceAccountsQuery()`, `useCreateServiceAccountMutation()`, `useDeleteServiceAccountMutation()`, `useDeactivateServiceAccountMutation()`, `useReactivateServiceAccountMutation()`, `useAuditEventsQuery()`. Support grants (`api.listTenantSupportGrants`, `createTenantSupportGrant`, `revokeTenantSupportGrant`, `listInvitedSupportGrants`, `acceptSupportGrant`) and `api.listInventoryConnectorHealth` are called directly, not through `queries.ts` hooks.

**Tenant schema status (new):** `api.getTenantSchemaStatus()` (`GET /platform/tenant-schema-status?page=0&size=200`) and `api.retryTenantProvisioning(tenantId)` (`POST /platform/tenants/{tenantId}/provisioning-retry`) are called directly from `PlatformConsolePage` (not via a `queries.ts` hook). The tenant lifecycle panel there joins each tenant row against its schema-status entry, disables "Enter workspace" for any tenant not `ACTIVE` (previously only `PURGING`/`DELETED` were blocked — tenant creation is asynchronous now, so a freshly-created tenant sits in `PROVISIONING` until the backend's tenant schema control plane actually migrates its schema), and shows a "Retry provisioning" action for tenants in `PROVISIONING_FAILED`.

### campaigns (`src/features/campaigns/`)

Files: `types.ts`, `CampaignDetailPage.tsx` — undocumented until now; a fully shipped feature, not scaffolding.

**Types:** Campaign lifecycle types covering status (`DRAFT`/`ACTIVE`/`PAUSED`/`BLOCKED`/`IN_REVIEW`/`CLOSED`/`CANCELLED`), exceptions, notifications, linked assets/findings, and evidence rows.

**No separate `queries.ts`** — API calls are inlined directly via `api.getCampaign()`, etc., calling `/campaigns`, `/campaigns/{campaignId}`, `/campaigns/{campaignId}/status`, `/campaigns/{campaignId}/exceptions/{exceptionId}/status`, `/campaigns/{campaignId}/notes`, `/campaigns/{campaignId}/notify-groups`, `/campaigns/{campaignId}/watchlist`, and bulk-add endpoints for assets/CVEs/software.

`CampaignDetailPage.tsx` is large (2000+ lines) — lifecycle stage UI, KPI tiles, severity/team accountability breakdowns, insight UI (generative assistance hard off for deployed pilot; deterministic paths retained), advisory fetch, and add-assets/add-CVE modals. Routed at `/vuln-repo/campaigns` and `/vuln-repo/campaigns/:id`.

### ai-security (`src/features/ai-security/`)

Files: `types.ts`, `categories.ts`, `assessment.ts`, `AiDependencyGraph.tsx`, `graph-layout.ts`, `AiBaselineSection.tsx`, `AiInventoryOverviewStrip.tsx`, `ProviderLogo.tsx`, `useAssessmentUpdates.ts`, `test-support.ts`

Backs the AI Security / AI Grid posture-management surface (14 pages under `src/pages/Ai*.tsx` + `PlatformAiPolicyStudio.tsx`), entitlement-gated on `ai.security` (see [Entitlements](#entitlements-distinct-from-roles) above). Mirrors the backend `com.prototype.vulnwatch.aisecurity` module's two generations (legacy "AI Security" catalog + governed "AI Grid" pipeline) but the frontend does not distinguish them structurally — everything is under this one feature directory.

**Types** (`types.ts`), grouped by concern:
- Inventory/summary: `AiSecurityArtifact`, `AiArtifactSummary`, `AiSecuritySummary`, `AiSeverityGrid`/`Row`, `AiSecurityPage<T>`
- Graph/relationships: `AiSecurityRelationship`, `AiSecurityGraph`
- Findings: `AiSecurityFinding`, `AiTopRiskArtifact`
- Policies (tenant-scoped): `AiSecurityPolicy`, `PolicyScope`/`PolicyScopeMode`/`PolicyScopeCondition`, `PolicyException`, `PolicyParameterValue`, `PolicyConfiguration`
- Runs/connectors: `AiSecurityRun`, `AiSecurityScope`, `AiSecurityConnectorConfig` (AWS), `AiSecurityAzureConnector`/`AiSecurityAzureFoundryConfig`/`AiSecurityAzureCredentialProfile` (Azure)
- AI Grid reporting/governance: `AiGridSystem`, `AiGridCoverage`, `AiFrameworkDefinition`, `AiFrameworkCoverage`, `AiRuntimeTelemetryReadiness`, `AiGridPolicyAssessmentStateSummary`, `AiGridPolicy`/`AiGridPolicySelection`/`AiGridPolicyDistribution`, `AiGridPolicyReleaseReadiness`, `AiGridPolicyTenantReconciliation`, `AiGridPolicyCandidate`, `AiGridRunMetrics`
- Exposure intelligence: `AiGridExposureSummary`/`Page`/`Detail`, `AiExposurePriority` (priority breakdown now carries `activityPoints` alongside severity/confidence/publicExposure/criticality/recency), `AiExposureIntelligenceOverview`, `AiActionQueueItem`, `AiAssetPosture`
- Runtime metadata: `AiAgentExecution`, `AiAgentExecutionPage`, `AiAgentExecutionEvent`
- Activity evidence: `AiActivityEvidence` (`factKey`, raw `valueJson`, `state`, `evidenceReference`, `observedAt`/`validFrom`/`validUntil`, `confidence`, `producerId`, `expired`)

**Activity evidence.** `api.getAiActivityEvidence(artifactId)` (`GET /ai-security/artifacts/{id}/activity-evidence`) and the `AiActivityEvidence` type remain, but `AiAssetDetailPage` no longer renders an Activity evidence panel, runtime-activity toggle, or "View executions" button (asserted absent in `AiAssetDetailPage.test.tsx`). If it is reintroduced, absence of evidence must not be worded as "Not used".

**Tenant policy reporting (`AiPoliciesPage`).** Reads tenant-visible static policies, global framework definitions/tenant coverage, and latest static assessment-state totals. Runtime policies, readiness, findings, activity summaries, and graph overlays are excluded. Legacy execution bookmarks redirect to inventory. See [business-logic-guide.md](business-logic-guide.md#ai-security--ai-grid-pipeline) (runtime scope doc archived).

**Platform policy distribution (`PlatformAiPolicyStudio`).** This page runs without tenant context and uses only global/platform APIs: catalog, shipping status, rollout queue, and `/ai-frameworks` for labels/control filters. The framework endpoint is intentionally platform-reference scoped. Do not add `/ai-framework-coverage`, `/ai-runtime-telemetry-readiness`, or `/ai-assessment-states/latest` calls to this page.

The same page's **Agent definition** panel is alias-aware: served versions are derived from `HAS_COMPONENT` edges to `AWS_BEDROCK_AGENT_ALIAS` components followed by their `SERVES_VERSION` edges, unioned with any legacy `ACTIVE_VERSION` edge. The field is labelled **"Served versions"** (plural) because a Bedrock agent can have several aliases routing to several versions — there is no single active version.

**`AiDependencyGraph.tsx`** — React Flow-based artifact relationship graph with click-to-inspect node popups (posture, PII, criticality); layout math is pure in `graph-layout.ts` (dagre-based, no JSX, independently unit-tested). `test-support.ts` mocks jsdom's `getBoundingClientRect` since React Flow needs real layout dimensions in tests.

**`categories.ts`** — cross-provider native-kind grouping (Agents/Models/Guardrails/Identity) used by the inventory pages to present AWS Bedrock and Azure AI resources under one taxonomy.

**API surface:** unlike most other features, calls are **not** namespaced under one consistent base path — a mix of `/ai-security/...` (artifacts, findings, policies, runs), `/ai-coverage/...`, `/ai-overview`, `/connectors/ai-security/...` (AWS/Azure connector config), and `/platform/ai-grid/...` (governance). Worth knowing before extending this feature: pick the base path that matches the existing sibling endpoint rather than assuming one canonical prefix.

### widgets (`src/features/widgets/`)

Files: `FplWidgets.tsx`

`DonutChart` — SVG donut with hover effect and center total label.
`HBarChart` — horizontal bar chart with active row highlight.
`WidgetCard` — wrapper with title and active highlight state.

---

## 5. Shared Components

All files in `src/components/`. Each must stay under ~300 lines. Larger components belong in `src/features/<feature>/`.

### DataTable (`src/components/DataTable.tsx`)

Uses `@tanstack/react-table`. Full column resizing, reordering (drag-and-drop), and show/hide controls.

Props:
- `storageKey: string` — localStorage namespace
- `columns: DataTableColumn[]` — column definitions with `id`, `label`, `header`, `initialSize`
- `rows: DataTableRow[]`
- `minColumnWidth?: number` (default 96)
- `showColumnControls?: boolean` (default true)

LocalStorage persistence:
- `{storageKey}` — column widths
- `{storageKey}:order` — column order
- `{storageKey}:hidden` — hidden column IDs

Internal hook: `useContainerWidth()` — ResizeObserver-based container measurement for proportional width rebalancing when columns are shown/hidden.

### StatCard (`src/components/StatCard.tsx`)

Metric display card. Props: `title`, `value`, `tone` (`neutral | warn | critical`), `caption`, `description`. Renders a `MetricInfoIcon` when `description` is provided.

### CveRiskScorePanel (`src/components/CveRiskScorePanel.tsx`)

SVG-based risk score trend chart. Period selector: 14d / 30d / 90d. Two variants: standard and `mini={true}`. Shows S.AI scoring journey events as dots + cards along the timeline. Plots a CVSS baseline dashed line for comparison. Mini mode shows a tooltip with reasoning trace on hover.

### FilterBuilder (`src/components/FilterBuilder.tsx`)

Dropdown filter selector with category tabs and free-text search. Closes on outside click or Escape.

Props: `categories: FilterBuilderCategory[]`, `fields: FilterBuilderField[]`, `activeKeys: string[]`, `onAddFilter: (key: string) => void`

Each `FilterBuilderField` has: `key`, `label`, `categoryKey`, `description`, `typeLabel`.

### ConfirmDialog (`src/components/ConfirmDialog.tsx`)

Native `<dialog>` element with `showModal()` / `close()`. Closes on backdrop click or Escape via `onCancel` prop.

Props: `isOpen`, `title`, `message`, `confirmLabel?` (default `'Confirm'`), `cancelLabel?` (default `'Cancel'`), `onConfirm`, `onCancel`

### SegmentedControl (`src/components/SegmentedControl.tsx`)

Generic segmented button group. Fully typed with `T extends string`.

Props: `options: Array<{value: T, label: string, activeClass?: string}>`, `value: T`, `onChange: (value: T) => void`, `ariaLabel?`

### MultiGroupBy (`src/components/MultiGroupBy.tsx`)

Two-level group-by selector (primary + multi-select secondary). Closes on outside click or Escape.

Props: `options: MultiGroupByOption[]`, `value: string[]`, `onChange: (next: string[]) => void`, `label?`, `placeholder?`, `maxInlineSelections?`, `allowEmptyPrimary?`, `emptyPrimaryLabel?`, `showSelectorsByDefault?`

### VulnRepoCveAssessmentWorkbench (`src/components/VulnRepoCveAssessmentWorkbench.tsx`)

The main CVE investigation panel rendered inside `VulnRepoOrgCvePage` when a CVE row is selected. 4-step workflow. Integrates `CveRiskScorePanel`, `CVEInvestigationSummary`, `ConfirmDialog`, `SegmentedControl`. Calls multiple `cveWorkbenchApi` methods and `api` methods. Derives `DerivedAssetRow` objects from matched software via `buildAssetRowsFromMatchedSoftware` from `src/features/cve-workbench/asset-report.ts`.

### CVEInvestigationSummary (`src/components/CVEInvestigationSummary.tsx`)

Displays a saved AI investigation summary. Props include `InvestigationSummaryInput`.

### EolBadge (`src/components/EolBadge.tsx`)

Small badge rendered in tables when a component is EOL or near-EOL.

### EolDetailDrawer (`src/components/EolDetailDrawer.tsx`)

Slide-in drawer with full EOL release detail for a selected package.

### EolMappingReviewPanel (`src/components/EolMappingReviewPanel.tsx`)

Panel for reviewing and resolving unresolved EOL slug mappings.

### EolSourcePanel (`src/components/EolSourcePanel.tsx`)

Configuration panel for the endoflife.date connector in the Connect page.

### InfoTooltip (`src/components/InfoTooltip.tsx`)

Simple hover tooltip for inline help text.

### InventoryQualityWorkspace (`src/components/InventoryQualityWorkspace.tsx`)

Panel for reviewing inventory data quality issues (missing versions, unmapped software, alias reviews, discovery review flags).

### MetricInfoIcon (`src/components/MetricInfoIcon.tsx`)

Small info icon with tooltip; used by `StatCard` when `description` is provided.

---

## 6. API Layer

All backend calls go through the single `api` export object in `src/api/client.ts`. There is no axios; all requests use native `fetch`.

### Auth header injection

```
applyAuthHeaders(headers):
  if getStoredAuthToken() -> Authorization: Bearer <token>
  else if development STATIC_AUTH_TOKEN -> Authorization: Bearer <token>
  else -> development-only API/creator/tenant/user headers (empty in production)
```

### Base URL

`VITE_API_BASE` overrides the backend URL. Without an override, development uses `/api` through the Vite proxy to `http://localhost:8080`; production uses `https://api.scoutgrid.io/api` so a missing deployment variable cannot send API requests into the SPA fallback.

### Token helpers

```typescript
getStoredAuthToken(): string | null        // reads localStorage 'vulnwatch.authToken'
setStoredAuthToken(token: string): void    // writes to localStorage
clearStoredAuthToken(): void               // removes from localStorage
```

### Core request helpers

- `request<T>(path, options?)` — authenticated fetch; throws on non-OK response
- `publicRequest<T>(path, options?)` — unauthenticated fetch

### Platform action confirmation

`shouldConfirmPlatformAction()` checks `ActorContext.sensitiveActionConfirmationRequired`. `currentPlatformTenantContext()` returns the active tenant name when `actingAsPlatformOwner`.

### Key API methods (grouped by domain)

**Findings:**
- `listFindings(params)` -> `FindingPage`
- `getFinding(id)` -> `Finding`
- `updateFindingWorkflow(id, payload)` -> `Finding`
- `bulkUpdateFindingWorkflow(payload)` -> `FindingBulkWorkflowResponse`
- `bulkDeleteFindings(findingIds)`
- `listFindingFilters()` -> filter option lists

**CVE / Vulnerability Repo:**
- `getVulnRepoDashboard()` -> `VulnRepoDashboard`
- `getPlatformVulnRepoDashboard()` -> `VulnRepoDashboard` (platform scope)
- CVE detail and AI solution calls live on `cveWorkbenchApi` (`getCveDetail`, `getSavedAiSolution`, `generateAiSolution`), not the main `api` object
- `getCveInventoryMap(limit)` -> CVE-inventory map data

**Inventory:**
- `listAssets(params)` -> asset list
- `getHostAssetDetail(assetId, options?)` -> `HostAssetDetail`
- `listInventoryComponents(params)` -> `InventoryComponentPage`
- `listInventoryComponentFilters()` -> `InventoryComponentFilterValues`

**Software Identities:**
- `listSoftwareIdentities(params)` -> paginated list
- `getSoftwareIdentityDetail(id)` -> `SoftwareIdentityDetail`
- `getSoftwareIdentityMetadata(id)` -> `SoftwareIdentityMetadata`
- `getSoftwareIdentityFunnel()` -> `SoftwareIdentityFunnel`
- `getVulnRepoSoftwareAssets(softwareIdentityId)` -> `VulnRepoSoftwareAssetsDetail`

**Dashboard:**
- `getDashboard()` -> `Dashboard`

**Operations:**
- `getOperationalDashboard()` -> `OperationalDashboard`
- Platform Health is composed in `useOperationsViewQuery` from `getOperationalApiReadPath()`, `getSloStatus()`, `getOperationalMetricCatalog()`, `getOperationalPerformanceScorecard()`

**EOL:**
- `getEolSummary()` -> `EolSummary`
- `getEolComponentStatuses(params)` -> paginated component statuses
- `listEolProducts()` -> `EolProductCatalog[]`
- `listEolProductReleases(slug)` -> `EolRelease[]`
- `listEolUnresolvedMappings(params)` -> paginated unresolved mappings
- `listEolMappingSuggestions(normalizedKey)` -> `EolSlugSuggestion[]`
- `getEolPackageStatuses(params)` -> paginated `PackageEolStatus`
- `getEolPackageAssets(params)` -> paginated assets for a package

**Configurations:**
- `getRiskPolicy()` -> `RiskPolicy`
- `updateRiskPolicy(payload)` -> `RiskPolicy`
- `listOwnershipRules()` -> `OwnershipRuleResponse[]`
- `createOwnershipRule(payload)`, `updateOwnershipRule(id, payload)`, `deleteOwnershipRule(id)`
- `listSuppressionRules()` -> `SuppressionRule[]`
- `createSuppressionRule(payload)`, `updateSuppressionRule(id, payload)`, `deleteSuppressionRule(id)`

**Connectors:**
- `listSyncRuns(params)` -> `SyncRun[]`
- Per-connector triggers returning `SyncTriggerResponse`: `triggerServiceNowCmdbSync()`, `triggerSccmCmdbSync()`, `triggerAwsDiscoverySync()`, `triggerAzureDiscoverySync()`
- `getServiceNowCmdbConfig()`, `saveServiceNowCmdbConfig(payload)`
- `getSccmCmdbConfig()`, `saveSccmCmdbConfig(payload)`
- `getAwsDiscoveryConfig()`, `saveAwsDiscoveryConfig(payload)`
- `listAwsDiscoveryTargets()`, `createAwsDiscoveryTarget(payload)`, `deleteAwsDiscoveryTarget(id)`
- `listGithubSbomSources()`, `createGithubSbomSource(payload)`, `deleteGithubSbomSource(id)`
- `getVulnerabilitySourceFilterConfig(sourceSystem)`, `saveVulnerabilitySourceFilterConfig(sourceSystem, payload)`
- `getVexAssertionRepairSummary()`

**AI Security / AI Grid** (base paths mixed — see the `ai-security` feature section above; method names below verified against `src/api/client.ts`):
- Inventory: `getAiSecuritySummary()`, `listAiSecurityArtifacts(...)`, `listAiArtifactSummaries(...)`, `listAiKnowledgeDataInventory(...)`, `listAiMcpInventory(...)`, `getAiSecurityArtifact(artifactId)`, `getAiSecurityGraph(rootArtifactId?, depth?)`, `getAiSeverityGrid()`, `getAiTopRiskArtifacts(limit?)`
- Findings: `listAiSecurityFindings(...)`, `getAiSecurityFinding(findingId)`, `reviewAiSecurityFinding(findingId, disposition, reason?)`
- Policies (tenant): `listAiGridPolicies()`, `getLatestAiGridAssessmentStates()`, `getAiGridPolicyDetail(policyId)`, `updateAiGridPolicySelection(policyId, selection)`, `executeAiGridPolicies(policyIds)`, `getAiGridPolicyConfiguration(policyId)`, `updateAiGridPolicyScope(policyId, mode, conditionLogic, conditions)`, `addAiGridPolicyException(...)`, `removeAiGridPolicyException(policyId, artifactId)`, `updateAiGridPolicyParameters(policyId, parameters)`, `explainAiGridPolicy(policyId)`
- Runs: `listAiSecurityRuns(provider?)`, `listAiSecurityRunScopes(runId)`
- Runtime metadata: `listAiAgentExecutions(filters)`, `getAiAgentExecutionTimeline(executionId)`
- AWS connector: `getAiSecurityConnector()`, `saveAiSecurityConnector(payload)`, `testAiSecurityConnector()`, `runAiSecurityConnector()`
- Azure connector: `listAiSecurityAzureConnectors()`, `getAiSecurityAzureRequirements()`, `saveAiSecurityAzureConnector(payload)`, `runAiSecurityAzureConnector(connectorId)`, `runAiSecurityAzureTarget(targetId)`; Foundry single-form flow `testAiSecurityAzureFoundryConfig()`/`runAiSecurityAzureFoundryConfig()`; credential profiles `listAiSecurityAzureCredentials()`, `createAiSecurityAzureCredential(payload)`, `testAiSecurityAzureCredential(profileId, subscriptionId)`, `rotateAiSecurityAzureCredential(profileId, payload)`, `revokeAiSecurityAzureCredential(profileId)`
- Coverage/readiness: `getAiGridCoverage()`, `getAiGridCoverageDimensions()`, `getAiFrameworks()`, `getAiFrameworkCoverage(framework, version, coverageEpochId?)`, `getAiRuntimeTelemetryReadiness()`, `getLatestAiGridAssessmentStates()`
- Exposure intelligence: `getAiExposureIntelligenceOverview()`, `listAiExposurePriorities()`, `listAiActionQueue()`, `getAiAssetPosture(artifactId)`, `listAiGridExposures(cursor?, limit?)`, `getAiGridExposure(exposureId)`, `dispositionAiGridExposure(exposureId, disposition, reason)`, `getAiGridRunMetrics(runId)`, `confirmAiGridArtifactOwner(artifactId, ownerName, reason?)`
- Platform governance: `listPlatformAiGridPolicies()`, policy-ID `approvePlatformAiGridPolicy()`, `publishPlatformAiGridPolicy(policyId, targetTenantIds)`, `deprecatePlatformAiGridPolicy()`, `revokePlatformAiGridReleaseBinding()`, policy detail/readiness, shipping status, rollout queue, and `getPlatformAiGridPolicyCandidates()`. `getAiFrameworks()` is shared global reference data; framework coverage itself is tenant-scoped.

**Auth / Admin:**
- `getAuthContext()` -> `AuthContext` (`GET /me`; the session uses `authApi.getActorContext` -> `ActorContext`)
- `login(email, password)` -> `AuthTokenResponse`
- `selectTenantContext(tenantId)` -> `AuthTokenResponse`
- `clearTenantContext()` -> `AuthTokenResponse`
- `listTenants()` -> `Tenant[]`
- `listPlatformUsers()` -> `PlatformUser[]`
- `listServiceAccounts()` -> `ServiceAccount[]`
- `createServiceAccount(payload)` -> `ServiceAccount`
- `listAuditEvents(params)` -> `AuditEvent[]`
- `listTenantMembers()` -> `TenantMember[]`
- `addTenantMember(payload)`, `updateTenantMember(id, payload)`, `deleteTenantMember(id)`
- `listTenantSupportGrants()`, `createTenantSupportGrant(payload)`, `revokeTenantSupportGrant(id)`
- `listInvitedSupportGrants()`, `acceptSupportGrant(id)`
- `listInventoryConnectorHealth()` -> `InventoryConnectorHealth[]`

---

## 7. State Management

There is no Redux or Zustand. All remote data is managed by `@tanstack/react-query`. Local/ephemeral state is `React.useState`. Persisted UI state (column prefs, theme, filters) goes to `localStorage`.

### React Query setup

`createQueryClient()` in `src/lib/queryClient.ts`:
- `retry: 1`
- `staleTime: 10_000` (10 seconds, overridable per query)
- `refetchOnWindowFocus: false`

The client is instantiated once in `src/main.tsx` and provided via `QueryClientProvider`.

### Query key conventions

| Domain | Key prefix |
|---|---|
| Auth context | `['auth-context', rawToken]` |
| Findings list | `['findings', params]` |
| Finding filters | `['finding-filters']` |
| Dashboard summary | `['dashboard-summary']` |
| Vuln repo dashboard | `['vuln-repo-dashboard', scope]` |
| CVE detail | `['cve-detail', cveId]` |
| Inventory components | `['inventory-components', params]` |
| Host asset detail | `['host-asset-detail', assetId, sourceSystem]` |
| Software identities | `['software-identities', params]` |
| Software identity detail | `['software-identity-detail', id]` |
| EOL summary | `['eol-summary']` |
| EOL package statuses | `['eol-package-statuses', params]` |
| EOL package assets | `['eol-package-assets', params]` |
| Sync runs | `['sync-runs', params]` |
| GitHub SBOM sources | `['github-sbom-sources']` |

### Polling intervals (`src/lib/polling.ts`)

| Constant | Value | Used by |
|---|---|---|
| `DASHBOARD_REFRESH_INTERVAL_MS` | 14 400 000 ms (4 h) | dashboard, vuln-repo dashboard, EOL, and operations quality queries |
| `OPERATIONS_REFRESH_INTERVAL_MS` | 15 000 ms | `useOperationsViewQuery` |
| `ORG_CVE_STATUS_REFRESH_INTERVAL_MS` | 10 000 ms | `useOrgSpecificCveAutomationStatusQuery` (conditional) |
| `RUN_QUEUE_REFRESH_INTERVAL_MS` | 3 000 ms | `useSyncRunsQuery`, `useIngestionJobsQuery` (conditional on active runs/jobs), and several connector/AI inventory pages |

### localStorage keys

| Key | Purpose |
|---|---|
| `vulnwatch.authToken` | JWT Bearer token |
| `scoutai-theme` | `'dark'` or `'light'` — applied as `data-theme` on `<html>` |
| `findings-col-vis-v2` | FindingsPage column visibility |
| `{storageKey}` | DataTable column widths (per table) |
| `{storageKey}:order` | DataTable column order |
| `{storageKey}:hidden` | DataTable hidden columns |

### Inventory URL state

Inventory views persist their filter and grouping state as URL search parameters (not localStorage) via the helpers in `src/features/inventory/searchState.ts`. This means inventory filter state survives page refresh and is shareable via URL.

---

## 8. Custom Hooks

### `useDebouncedValue<T>(value, delayMs?)` (`src/hooks/useDebouncedValue.ts`)

Debounces a value with a configurable delay (default 300 ms). Special behavior: empty strings clear immediately without waiting for the delay. Used for search inputs to avoid excess API calls.

### `useActorQuery()` (`src/features/auth/queries.tsx`)

Calls `GET /api/me`. Returns `UseQueryResult<ActorContext>`. Query key includes the raw token so it auto-invalidates on login/logout. `staleTime: 60 seconds`.

### `useActor()` (`src/features/auth/context.ts`)

Reads the `ActorContext` from React context. Returns `null` when no actor is loaded (it does not throw).

### `useFindingsQuery(params)` (`src/features/findings/queries.ts`)

Server-side paginated findings. Uses `keepPreviousData` to avoid flash on page change.

### `useOrgSpecificCveAutomationStatusQuery()` (`src/features/cve-workbench/queries.ts`)

Polls at `ORG_CVE_STATUS_REFRESH_INTERVAL_MS` only when `pendingEventCount > 0`. Returns to non-polling when the pending count reaches zero.

### `useOperationsViewQuery(selectedView)` (`src/features/operations/queries.ts`)

Loads both Pipeline and Platform Health sections in parallel using `Promise.all`. Refetches every 15 seconds.

### `useSyncRunsQuery(params)` (`src/features/connect/queries.ts`)

Smart polling: checks `run.status` for RUNNING/STARTED/QUEUED; polls at 3 s when any run is active, stops when all runs complete. Does not poll in background (`refetchIntervalInBackground: false`).

### `useInventoryData(args)` (`src/features/inventory/useInventoryData.ts`)

Composes `useInventoryComponentsQuery` and `useInventoryComponentFiltersQuery`, normalizes filter option values, exposes `refreshInventory()` to force a refetch.

### `useContainerWidth()` (internal to `DataTable.tsx`)

`ResizeObserver`-based hook that measures the table container's width. Used by DataTable to proportionally redistribute column widths when columns are shown or hidden.

---

## 9. Type System

Types are **feature-colocated**, not centralized. `src/types/index.ts` re-exports everything but is only a convenience barrel — the source of truth is always the file in the feature directory. When editing a type, edit the feature file.

### Type file locations

| Type(s) | Source file |
|---|---|
| `ActorContext`, `AllowedTenant` | `src/features/auth/types.ts` |
| `Finding`, `FindingPage`, `FindingFilterValues`, `FindingBulkWorkflowRequest`, `FindingTimeline`, `VulnerabilityDetail` | `src/features/findings/types.ts` |
| `OrgSpecificCveExposureRecord`, `CveDetail`, `CveMatchedSoftware`, `CveInvestigation`, `CveApplicabilityAssessment`, `FixRecord` | `src/features/cve-workbench/types.ts` |
| `ApplicabilityDecision`, `ImpactDecision`, `SoftwareGroup`, `FindingDisplayRow` | `src/features/cve-workbench/assessment-helpers.ts` |
| `RiskPolicy`, `SuppressionRule`, `SuppressionRuleRequest`, `OwnershipRuleResponse`, `OwnershipRuleRequest` | `src/features/configurations/types.ts` |
| `InventoryViewKey`, `InventoryScopedAssetType`, `InventoryComponentFilterKey`, `HostReviewCategory` | `src/features/inventory/types.ts` |
| `Asset`, `HostAssetDetail`, `HostAssetSummary`, `InventoryComponentRecord`, `InventoryComponentPage`, `InventoryComponentFilterValues` | `src/features/inventory/api-types.ts` |
| `SyncRun`, `ServiceNowCmdbConfig`, `SccmCmdbConfig`, `AwsDiscoveryConfig`, `GithubSbomSource`, `VulnerabilitySourceFilterConfig` | `src/features/connect/types.ts` |
| `OperationalDashboard`, `OperationalQualityIssue`, `SloStatus` | `src/features/operations/types.ts` |
| `Dashboard`, `TopFindingMetric` | `src/features/dashboard/types.ts` |
| `VulnRepoDashboard`, `VulnRepoDashboardSummaryCards`, `VulnRepoDashboardResolutionStatus`, `VulnRepoDashboardCriticalUnresolvedItem`, `VulnRepoDashboardTopAffectedSoftwareItem`, `VulnRepoDashboardImpactedAssetItem` | `src/features/vuln-repo-dashboard/types.ts` |
| `SoftwareIdentitySummary`, `SoftwareIdentityDetail`, `SoftwareIdentityFunnel`, `VulnRepoSoftwareAssetsDetail` | `src/features/software-identities/types.ts` |
| `EolSummary`, `ComponentEolStatus`, `EolProductCatalog`, `PackageEolStatus` | `src/features/eol/types.ts` |
| `Tenant`, `TenantMember`, `PlatformUser`, `ServiceAccount`, `AuditEvent`, `TenantSupportGrant` | `src/features/admin/types.ts` |
| `AiSecurityArtifact`, `AiSecurityFinding`, `AiSecurityPolicy`, `AiGridSystem`, `AiGridCoverage`, `AiGridExposureDetail`, and all other AI Security/Grid types | `src/features/ai-security/types.ts` |
| `OwnershipSummary` | `src/types/ownership.ts` |
| `PolicyWeights` | `src/lib/riskScoring.ts` |
| `DataTableColumn`, `DataTableRow` | `src/components/DataTable.tsx` |
| `MultiGroupByOption` | `src/components/MultiGroupBy.tsx` |
| `FilterBuilderCategory`, `FilterBuilderField` | `src/components/FilterBuilder.tsx` |
| `AppTab`, `OperationsRouteView`, `VulnerabilityIntelRouteView`, `ConnectRouteView`, `AdminRouteView`, `PlatformRouteView` | `src/app/routes.ts` |

### S.AI scoring types (`src/lib/riskScoring.ts`)

`PolicyWeights` mirrors the 6 `triage*` fields on the frontend `RiskPolicy` type (the backend entity has none):
- `triageExploitabilityWeight: number`
- `triageBlastRadiusWeight: number`
- `triageEolRiskWeight: number`
- `triageSlaBreachWeight: number`
- `triageMissingOwnerBoost: number`
- `triagePatchGapBoost: number`

`CveRiskScoreResult` — output of `computeCveRiskScore`: `score` (0–10), `label`, `color`, `topReasons`, and a `journey` array of `CveScoreEvent` (`stage`, cumulative `score`, `delta`, `reason`, `isNote`). `computeOrgImpact(item, saiScore, externalFacingCount)` returns `'NONE' | 'LOW' | 'MEDIUM' | 'HIGH'`; `riskScoreLabel` and `riskScoreColor` map a score to its label/color.

`FindingPriorityScoreResult` — output of `computeFindingPriorityScore`: `score` (0–10), `label`, `color`, `topReasons`.

---

## 10. Styling

All styles are plain CSS with custom properties. No CSS-in-JS, no Tailwind.

### Theme system

Two themes: `light` (default) and `dark`. Applied as `data-theme="dark"` on `<html>`. Persisted in `localStorage` under `scoutai-theme`. Theme state is managed in `App.tsx`.

### CSS custom properties (defined in `src/styles/base.css`)

| Variable | Purpose |
|---|---|
| `--bg` | Page background |
| `--panel` | Card/panel background |
| `--panel-muted` | Slightly muted panel |
| `--text` | Body text |
| `--title` | Heading text |
| `--muted` | Secondary/caption text |
| `--border` | Default border |
| `--border-strong` | Emphasized border |
| `--accent` | Brand/action color |
| `--critical` | Critical severity color |
| `--high` | High severity color |
| `--medium` | Medium severity color |
| `--low` | Low severity color |
| `--space-1` through `--space-6` | Spacing scale |
| `--control-sm` | Small control height |

### Fonts

- **Space Grotesk** — display/heading text
- **IBM Plex Sans** — body text

### CSS file organization

| File | Contents |
|---|---|
| `base.css` | CSS custom properties for both themes, font imports, reset |
| `shared.css` | Global layout classes (`page-grid`, `panel`, `panel-header`), buttons, pills, badges, filter dropdowns, SBOM wizard, segmented controls |
| `cve-workbench.css` | CVE Assessment Workbench panel and workflow styles |
| `connect.css` | Connector filter bar, connector card grid, wizard step styles |
| `eol.css` | EOL page — at-risk table, catalog styles |
| `vuln-repo.css` | Vuln repo pages — inline bars, status pills |
| `user-management.css` | User management page — role matrix table, member rows |
| `exposure-dashboard.css` | Executive dashboard — `exec-kpi-*`, `exec-pipeline-*`, `exec-cve-*`, `exec-rem-*`, `exec-asset-*`, `exec-software-*`, `exec-insight-*` classes |
| `finding-detail.css` | Finding detail page styles |
| `findings-list.css` | Findings list page styles |

### CSS class naming patterns

| Pattern | Usage |
|---|---|
| `severity-pill severity-{critical,high,medium,low}` | Severity badges |
| `status-pill status-{open,resolved,suppressed,in-progress,unknown,auto_closed}` | Status badges |
| `panel` | Card container |
| `panel-header` | Card header row |
| `panel-caption` | Subdued helper text |
| `btn`, `btn-primary`, `btn-secondary`, `btn-link` | Button variants |
| `segmented-control`, `segmented-control-btn--active` | Segmented button groups |
| `filter-pill`, `filter-pill-chevron` | Filter UI |
| `exec-kpi`, `exec-kpi--critical`, `exec-kpi--warn` | KPI cards on exposure dashboard |
| `impact-impacted`, `impact-fixed`, `impact-no-patch`, `impact-not-impacted`, `impact-unknown` | VEX impact state badges |

---

## 11. Development Notes

### Starting the app

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173 (strictly)
```

Backend must be configured with an explicit environment/runtime role and supported JWT mode; see [backend startup](../README.md#backend). Development proxies `/api` to port 8080 unless `VITE_API_BASE` overrides it.

### Environment variables

Set public inputs in `.env.local` (no frontend `.env.example` is committed). Provider secrets belong only on the backend. Production builds reject nonempty `VITE_API_KEY`, `VITE_CREATOR_KEY`, `VITE_AUTH_TOKEN`, `VITE_USER_ID` and `VITE_TENANT_ID`; these are dev-only, and the bundle guard also checks for leakage.

| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_BASE` | `/api` in development; `https://api.scoutgrid.io/api` in production | Backend API base URL |
| `VITE_TURNSTILE_SITE_KEY` | Cloudflare test key in development | Public Turnstile site key used by the demo-request CAPTCHA |
| `VITE_API_KEY` | `change-me-in-prod` | `X-API-Key` header (local dev fallback) |
| `VITE_CREATOR_KEY` | `local-creator` | `X-Creator-Key` for PLATFORM_OWNER endpoints (local dev) |
| `VITE_AUTH_TOKEN` | (empty) | Development-only bearer fallback after stored token |
| `VITE_SENTRY_DSN` | (empty) | Sentry DSN — leave empty to disable |
| `VITE_ENABLE_TEST_PERSONAS` | `false` | Enables impersonation persona switcher in dev |

### S.AI Risk Scoring

`computeCveRiskScore` and `computeFindingPriorityScore` in `src/lib/riskScoring.ts` are **pure TypeScript** — no React imports, no API calls. They compute scores entirely from data already returned by the API. Scores are not stored in the database; they recalculate on every render.

Call sites fetch the risk policy via `useRiskPolicyQuery()` and pass `policyQuery.data` as the optional `policy` argument. `DEFAULT_POLICY` (all weights 1.0) is used when no policy is available.

**`computeCveRiskScore` stages:** CVE Published (CVSS + EPSS) -> In CISA KEV -> Org Exposure (blast radius) -> EOL Risk -> No Patch -> Applicability Decision -> Findings Created.

**`computeFindingPriorityScore` signals:** exploitability (KEV/EPSS weight), SLA breach proximity, missing owner boost, EOL component risk, severity boost, VEX confirmed affected.

### React StrictMode

The app uses `React.StrictMode` (see `src/main.tsx`). Effects run twice in development. All side effects must be idempotent.

### Two distinct CVE list pages

These are different pages backed by different API endpoints — do not confuse them:

- `/vuln-repo/org-cves` (`VulnRepoOrgCvePage`) — **Unified Vulnerability Records.** Queries `org_cve_records` via `useOrgSpecificCvesQuery`. Only shows CVEs correlated to org inventory. Primary analyst triage and investigation workflow. Every CVE here has a CPE match.

- `/vuln-repo/vulnerabilities` (`VulnRepoVulnerabilitiesPage`) — **Vulnerability Intelligence.** Queries `vulnerability_intel_summary` via `useVulnRepoVulnerabilitiesQuery`. Shows ALL ingested CVEs from NVD/GHSA/KEV regardless of inventory match. CVEs with `matchedSoftwareCount = 0` are expected here.

### Adding a new connector

1. Add the connector ID to the `ConnectorId` union in `ConnectPage.tsx`.
2. Add to the `CONNECTORS` array with `id`, `name`, `summary`, `icon`.
3. Add to the appropriate category list — `INVENTORY_CONNECTOR_IDS` or `BOM_CONNECTOR_IDS` in `ConnectPage.tsx` (AI connectors are in `INVENTORY_CONNECTOR_IDS` and also listed in `AI_CONNECTOR_IDS` for entitlement gating) (there is no rendered "Vulnerability Intelligence" connector-card category anymore — see below).
4. Add a `case` in `ConnectorDetailContent` that renders the connector's config component.

Note: `endoflife-date`, `euvd-feed`, and `jvn-feed` are declared in the `ConnectorId` union and `CONNECTORS` array (with `ConnectorDetailContent` cases) but are not in either of the two connector-card category lists above, so they currently render no clickable card anywhere in the UI — likely a gap worth a follow-up ticket.

### Configurations page sections

7 sections in sidebar order: SLA & Remediation -> S.AI Prioritization (AI badge) -> Workflow Automation -> Ownership -> Findings Score -> Suppression Rules -> Auto-Finding Rules. All except Ownership persist to a single `RiskPolicy` record via `PUT /api/risk-policy`. Call `applyTriageDefaults()` on API responses to fill missing triage fields for older backends that predate the 6 triage weight fields.

Vulnerability Sources (the per-tenant feed filter rule editor, `VulnerabilitySourcesSection`) is no longer a Configurations tab — it now renders inside a collapsible "Vulnerability Intelligence" accordion on the Connect page (`/connect/sources`, gated by `canManageSourceFilters(actor)`).

### Test infrastructure

Page tests live next to their page as `<Page>.test.tsx`. Use `renderWithProviders` from `src/test/test-utils.tsx`:

```typescript
import { renderWithProviders } from '../test/test-utils';

renderWithProviders(<MyPage />, {
  route: '/findings',            // optional initial route
  initialEntries: [{ pathname: '/findings', state: { foo: 'bar' } }],
  queryClient: customClient,     // optional
});
```

Mock API methods with `vi.spyOn(api, 'methodName').mockResolvedValue(...)`. Use `api` from `src/api/client.ts`. The `cveWorkbenchApi` is a separate object and must be mocked separately. Call `localStorage.clear()` in `afterEach` for pages that persist column preferences.

Test `QueryClient` uses `retry: false` so failed queries resolve immediately without retries.

Available test fixtures in `src/test/fixtures.ts`:
- `buildFinding(overrides?)` — builds a complete `Finding` with realistic defaults
- `defaultRiskPolicy(overrides?)` — all 12+ `RiskPolicy` fields with sensible defaults
- `defaultFindingFilterValues(overrides?)` — `FindingFilterValues`
- `pageOf<T>(items, size?)` — wraps items in a paginated envelope
- `findingPageOf(items, size?)` — typed version for `FindingPage`

### Platform owner flow

`ActorContext.platformScope = true` means the user is a platform owner who has not selected a tenant. In this state, all tenant-scoped routes (`/exposure`, `/findings`, `/vuln-repo`, `/inventory`, etc.) redirect to `/platform/tenants`. After authorized LOCAL-mode `api.selectTenantContext(tenantId)`, `actingAsPlatformOwner = true`. The backend requires current membership or support access; a tenant ID or platform-owner claim alone does not authorize entry.

### Exposure Dashboard layout

`ExposureDashboardPage` fetches from four queries in parallel: `useExposureSummaryQuery()`, `useVulnRepoDashboardQuery()`, `useEolSummaryQuery()`, `useGridExposureQuery()`. It renders these rows:
1. 6 KPI cards: Critical Findings, Open Findings, Impacted CVEs, CISA KEV Exposure, Needs Attention, EOL Software
1b. Grid Exposure widget (rendered only when grid exposure rows exist)
2. CVE Exposure Pipeline (funnel with Tracked/Applicable/Impacted/Remediation) + Remediation Progress (status bars + Security Score)
3. Critical CVEs Requiring Action list + Where Attention Is Required (insight chips)
4. Most Exposed Software list + Critical Exposed Assets list

The insight chips are generated client-side from the fetched data and link directly to filtered views on other pages.

### FindingsPage details

`FindingsPage` has 5 widget cards (severity donut, status bars, top assets, SLA/due date, KPI indicators), 19 configurable columns persisted to `findings-col-vis-v2` in localStorage, server-side filters (severity, status, creationSource, vulnerabilityId, packageName) and client-side filters (findingId, asset, owner, supportGroup, assignedTo, incidentId, risk, dueDate band). Bulk actions available: Resolve, Defer, False Positive, Duplicate, Create ServiceNow Incident, Re-open, Delete. `computeFindingPriorityScore()` is called per row for the S.AI Priority column.

### OperationalDashboardPage view keys

Two nav items shown: `pipeline` and `platform-health`. The `quality` view key redirects to `/inventory` with quality-tab search params (`inventoryTabs=quality-normalization|quality-correlation|quality-eol|quality-vex`) instead of rendering inside Operations — Correlation/Normalization/EOL/VEX quality analytics now live under Inventory. `PipelinePayload` itself only carries `{ ingestion, freshness }` now; the older `getOperationalNormalizationQuality`/`getOperationalCorrelationEffectiveness`/`getOperationalNoiseLifecycle` API methods have no call sites left in `src/`.

### Never-touch list (from project CLAUDE.md)

- Applied Flyway migrations (V*.sql) — add a new one, never edit an applied one
- Security config in backend
- Tenant scoping logic
- Deploy infra (Dockerfile, workflows)
- Golden contract fixture hashes

### Things rejected on sight (from project CLAUDE.md)

- New `any` TypeScript types without a comment explaining why
- `console.log` left in shipped code
- New `src/components/` files larger than ~300 lines
- Lowering coverage thresholds
- `// TODO` without owner or linked issue


## Declared AI-BOM dependency evidence

`AiBomDeclaredResourceDetailPage` shows current ordered dependency paths, unresolved gaps/remediation, retained uncertain support, and a separate retired-history view. Evidence pages use the additive detail `correlation` field and the paginated `/bom/declared-resources/{resourceId}/correlation` API. Legacy associations awaiting path backfill are explicitly qualified. Active support does not imply an OPEN finding, proven deployment, or exploitability; finding status remains visible separately.

Loading, failed requests, empty results, gaps, pagination, reactivation history, and retired support have distinct states and tests. Empty findings/evidence do not assert absence of risk. Upload success states that ingestion completed and that software assessment/finding creation and later AI-resource linking run asynchronously. No queue-derived assessment COMPLETE claim is rendered. See the archived release evidence (`Other Docs/Archive/ai-bom-correlation-release-evidence.md`) for browser screenshots and test results.
