# CLAUDE.md

> **Current prerequisite contract (October 21, 2026):** [implementation closure](<../Working Knowledge/AWS/AWS_APPLICATION_PREREQUISITES_IMPLEMENTATION_CLOSURE.md>) and [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>). Generic Azure, local archive operations, tenant OSV, runtime evidence and destructive tenant purge remain contained; Fix Intelligence and the patch connectors are re-enabled (tenant V9) but not yet release-qualified; deployed pilot generative assistance remains off. The unsupported Patch Management mock forms and credential-logging handlers have been retired; see [review handoff](<../Working Knowledge/AWS/AWS_APPLICATION_PREREQUISITES_REVIEW_HANDOFF.md>). Documentation completion is not release qualification.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> The root `../CLAUDE.md` contains full project conventions, route table, feature descriptions, and the never-touch list. This file adds frontend-specific runtime detail.

## UI 2.0: required reading for new screens

Follow [the UI development standard](<../Working Knowledge/New UI 2.0/ui-development-standard.md>) for every new or substantially changed screen. It defines the architecture, reusable React components and CSS primitives, required states, accessibility, responsive checks and the approval process for changing a shared pattern. [UI 2 styles and rollback](<../Working Knowledge/New UI 2.0/ui2-styles-and-rollback.md>) defines the exact import order, route boundary and browser commands.

Use the existing `AppShell` inside `src/App.tsx`; compose route pages from feature modules and shared components. UI 2.0 is always active on app/auth routes; `/demo` routes have the intentional public presentation. No `VITE_UI_VERSION`, `uiVersion.ts`, legacy stylesheet imports or `legacy-bridge.css` remain. Styles load eagerly once from `main.tsx` through `styles/index.css`; do not add page-local CSS imports.

Extend shared components/tokens and matching family styles. Do not create a second component library, shell, theme store or per-screen design. A departure from the standard needs explicit user approval during development after explaining alternatives, pros/cons and the affected-screen convergence plan; record it and update the shared standard. Routine screens following the standard proceed normally.

## Commands

```bash
npm run dev           # dev server on port 5173 (strictly)
npm run build         # tsc -b --force && vite build && node scripts/verify-production-bundle.mjs
npm run lint          # eslint .
npm run typecheck     # tsc -b --noEmit (no output files)
npm run test:unit     # vitest run (all tests, no watch)
npm run test:coverage # vitest run --coverage (enforces line/branch thresholds)

# Run a single test file
npx vitest run src/pages/FindingsPage.test.tsx
```

Quality gates in order: `lint` → `typecheck` → `build` → `test:coverage`. Browser CI builds and checks the UI 2 artifact and runs fixture journeys. The scheduled and on-demand workflow runs the route and accessibility sweep at four widths in both themes, plus screenshot comparison. Run `npm run e2e:build` before browser commands. Visual/affected/update commands require the pinned Playwright container. See [browser gates](<../Working Knowledge/New UI 2.0/ui2-styles-and-rollback.md#browser-gates>); `e2e:live` requires approved disposable accounts/data and is separate from default CI.

## Environment variables

Public browser configuration uses `VITE_` variables in an ignored `.env.local`; no frontend `.env.example` is committed. Never place provider/server secrets in frontend inputs. Production builds reject nonempty static auth inputs (`VITE_API_KEY`, `VITE_CREATOR_KEY`, `VITE_AUTH_TOKEN`, `VITE_USER_ID`, `VITE_TENANT_ID`) before bundling and scan the bundle afterward.

| Variable | Purpose | Default / notes |
|---|---|---|
| `VITE_API_BASE` | Backend API base URL | unset: same-origin `/api` (Vite proxy to localhost:8080 in development). Required for Vercel production builds and must be `/api` or an HTTPS origin in the `vercel.json` CSP `connect-src` (`scripts/production-api-policy.mjs`) |
| `VITE_API_KEY` | `X-API-Key` header value | `change-me-in-prod` |
| `VITE_CREATOR_KEY` | `X-Creator-Key` for PLATFORM_OWNER endpoints | `local-creator` |
| `VITE_AUTH_TOKEN` | Development-only bearer fallback after stored token | (empty) |
| `VITE_SENTRY_DSN` | Sentry error reporting | (empty = disabled) |
| `VITE_ENABLE_TEST_PERSONAS` | Enable impersonation switcher | `false` |

## Auth model in the browser

Authentication state flows through a single read path:

1. `getStoredAuthToken()` reads only `vulnwatch.authToken` from `localStorage`; it returns an empty string if absent. `applyAuthHeaders()` separately falls back to development-only `VITE_AUTH_TOKEN`. A stored token wins.
2. `api/client.ts` attaches this as `Authorization: Bearer <token>` on every request. When no token is present it falls back to `X-API-Key` / `X-Creator-Key` headers (local dev only).
3. `useActorQuery()` calls `GET /api/me` and returns an `ActorContext`. The query key is `[...AUTH_CONTEXT_QUERY_ROOT, rawStoredTokenOrAnonymous]`, with a 60-second stale time. The current code still uses the raw stored token; do not describe it as an opaque epoch or sessionStorage design. Logout clears the shared query cache. Keep tokens out of logs, telemetry and review evidence.
4. `AuthSessionBoundary` in `App.tsx` wraps all authenticated routes. If the query fails or returns no data it redirects to `/login`.
5. The loaded `ActorContext` is published via `ActorContextState` (React context). Read it with `useActor()` from `src/features/auth/context.ts`.

Role checks **must** go through the helper functions in `src/features/auth/roles.ts` (`hasRole`, `canAccessPlatformConsole`, etc.). Do not check `actor.roles` directly — the helpers normalize `ROLE_` prefixes and handle `platformScope` edge cases.

**Entitlements are a separate mechanism from roles**: `src/features/auth/entitlements.ts`'s `canUseEntitlement(actor, key)` checks a per-tenant, plan-based feature flag (currently `ai.security`, gating the entire AI Security / AI Grid feature surface) and fails closed. Roles answer "can this user do X"; entitlements answer "does this tenant's plan include feature X at all". Both can gate the same route.

Backend decisions use current stored authority; decoded browser claims and UI checks never grant access. Tenant membership accepts only the four customer roles; selecting a tenant requires a current membership/support reference.

`TenantEntitlementService` uses one effective resolver for backend enforcement and the `/me` snapshot. Corrected precedence is an active tenant override, then plan value, then disabled default; expired overrides fall through. LEGACY and SHADOW retain legacy allow behavior; ENFORCE applies corrected decisions only to explicit tenant UUIDs or `slug:<tenant-slug>` cohort entries. Outside that cohort behavior remains SHADOW; null/platform snapshots are empty. Wildcards and invalid modes/cohorts are rejected. Deployed pilot startup requires ENFORCE and a named cohort (committed default `slug:scoutgrid-internal-pilot`); effective deployed settings still need qualification. Roles, lifecycle, provider availability and independent containment remain additional checks: an entitlement never enables generic Azure, runtime evidence or pilot generative assistance.

`ActorContext.platformScope = true` means the user is a platform owner who has not yet entered a tenant. In this state, tenant-scoped routes redirect to `/platform/tenants`. After authorized tenant selection, `actingAsPlatformOwner = true`; selection is not an unrestricted owner bypass.

AI Grid follows that boundary explicitly. Platform policy pages use global APIs; `/policies` reads tenant static policies, framework coverage, and assessment-state totals. Runtime telemetry, activity summaries, execution timelines, graph overlays, and runtime findings are deferred. No customer page calls their APIs. Legacy `/inventory/ai/executions` bookmarks redirect to `/inventory/ai` without loading runtime data.

## Source layout

```
src/
  api/
    client.ts          # Single api object — all backend calls, auth header injection,
                       # getStoredAuthToken / setStoredAuthToken / clearStoredAuthToken
  app/
    PresentationBoundary.tsx # Update route presentation before paint on router navigation
    routes.ts          # All typed path helpers (pathForTab, pathForVulnRepoView, …)
                       # and legacy query-param → path-based redirect logic
  features/            # Feature-colocated modules; types live here, not in src/types/
    auth/              # ActorContext type, context, role helpers, queries
    findings/          # Finding type, queries, filters
    cve-workbench/     # Largest feature — CVE Assessment Workbench types and helpers
    configurations/    # RiskPolicy (6 triage weight fields, frontend-only — not on the backend entity), OwnershipRule, SuppressionRule
    ownership/         # Ownership & Directory hub (Configurations → Ownership, ?view=), its panels/dialogs,
                       # queries, permissions (visibility only), resolvedOwnership helpers for inventory/findings
    inventory/         # Asset, HostAssetDetail, InventoryComponentPage
    connect/           # Connector configs, sync run types
    operations/        # OperationalDashboard, SLO, quality types
    dashboard/         # Dashboard, ImpactedCve types
    vuln-repo-dashboard/
    software-identities/
    eol/
    admin/             # Tenant, PlatformUser, ServiceAccount, AuditEvent, TenantSchemaStatusItem
    campaigns/         # Remediation campaign types + CampaignDetailPage; API calls inlined (no queries.ts)
    ai-security/       # AI Security/AI Grid types, dependency graph (React Flow), category
                       # helpers; entitlement-gated ('ai.security') — see root CLAUDE.md
    widgets/           # Shared chart/widget components
  hooks/
    useDebouncedValue.ts  # Generic debounce hook
  lib/
    riskScoring.ts     # Pure TS: computeCveRiskScore, computeFindingPriorityScore, computeOrgImpact
    presentationBoundary.ts # App/auth UI 2 outside /demo; restore saved theme
    queryClient.ts     # createQueryClient factory (shared between app and tests)
    time.ts            # timeAgo, formatTimestamp
    polling.ts         # Refresh-interval constants for run-queue and status polling
    performanceMonitoring.tsx  # Client performance telemetry
  pages/               # One file per route; lazy-loaded via React.lazy in App.tsx
  components/          # Shared presentational components (≤ 300 lines each)
  styles/              # One eager index.css: scoped public*.css, then ui2/index.css
                       # ui2/: tokens, app-base, shell, primitives, family base/presentation (including Fix Intelligence), tables
  types/               # Re-exports only — source of truth is always in the feature directory
  test/
    setup.ts           # @testing-library/jest-dom/vitest import
    test-utils.tsx     # renderWithProviders (QueryClientProvider + MemoryRouter)
    fixtures.ts        # buildFinding, defaultRiskPolicy, defaultFindingFilterValues, pageOf
```

`src/types/index.ts` re-exports feature types but the **source of truth** is always the feature directory file. Edit the feature file, not the re-export.

## Ownership feature

`src/features/ownership/` renders the Ownership & Directory hub inside `ConfigurationsPage` (`ownership` section). The sub-view lives in the `view` search parameter (`overview` default, `teams`, `people`, `groups`, `imports`, `review`, `legacy`). `permissions.ts` mirrors the backend `OwnershipAuthorization` matrix for visibility only; the server still decides. People and Groups appear only for roles that can view the directory, and Imports only for `TENANT_ADMIN`. The legacy rule editor is passed in as `legacyRules` and shown as "Legacy rules" while inventory ownership still reports `LEGACY_PENDING_MIGRATION`.

Use `resolvedOwnership.ts` to read the canonical ownership envelope on assets and findings. Show the resolved team only when `authorityState` is `CANONICAL`; otherwise keep today's owner display (findings show "Pending migration"). Findings owner-team and ownership-status filters are offered only when `useOwnershipCoverageQuery('FINDINGS')` reports `CANONICAL`, and they filter by stable team ID. Ownership API calls go through `api/client.ts`. Tests: `OwnershipDirectoryHub.test.tsx`, `resolvedOwnership.test.ts`, and the Findings, Inventory, HostAssetDetail and Configurations page tests.

## cve-workbench feature internals

`src/features/cve-workbench/` has its own `api.ts` (separate from `src/api/client.ts`) for CVE-workbench-specific endpoints. The feature is also the largest pure-logic surface:

| File | Purpose |
|---|---|
| `types.ts` | `OrgSpecificCveExposureRecord`, `CveDetail`, `CveMatchedSoftware`, `VendorIntelligence`, etc. |
| `queries.ts` | React Query hooks for org CVEs, CVE detail, vendor intel |
| `api.ts` | CVE-workbench API calls (`cveWorkbenchApi` object) — mock this in tests, not `api` from client.ts |
| `formatting.ts` | `formatDate`, `formatLabel`, `severityClassName`, `statusClassName`, `softwareLabel` |
| `eol-helpers.ts` | `eosDisplay` (returns ReactElement), `eolRiskSummary` |
| `view-helpers.ts` | `formatAssetType`, `formatEpssPercent`, `epssTrendMeta` |
| `vendor-helpers.ts` | CPE parsing, correlation scoring, false-positive status, advisory labels |
| `source-helpers.ts` | Builds view models from `CveDetail` — affected products, reference links, source record views |
| `assessment-helpers.ts` | `buildSoftwareGroups` — groups `CveMatchedSoftware[]` by package into `SoftwareGroup[]` |
| `investigation-context.ts` | `assetInventoryFieldMatches` — pure string matcher used by source-helpers and workflow |
| `workflow.ts` | Assessment workflow state machine helpers |
| `view-models.ts` | Composite view-model builders combining multiple helper outputs |

## Page test scaffolding

Tests live next to the page as `<Page>.test.tsx`. Use `renderWithProviders` from `src/test/test-utils.tsx` — it wraps in `QueryClientProvider` and `MemoryRouter`.

```tsx
import { screen } from '@testing-library/react';
import { afterEach, describe, it, vi } from 'vitest';
import { api } from '../api/client';
import { buildFinding, defaultRiskPolicy, findingPageOf } from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { FindingsPage } from './FindingsPage';

describe('FindingsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders rows for findings returned by the API', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(findingPageOf([buildFinding()]));
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    renderWithProviders(<FindingsPage />);
    expect(await screen.findByText('F-001')).toBeInTheDocument();
  });
});
```

- Mock only the API methods the page actually calls.
- Use `vi.spyOn(api, 'method').mockResolvedValue(...)` / `mockRejectedValue(...)`.
- For cve-workbench pages, mock `cveWorkbenchApi` from `../features/cve-workbench/api` in addition to `api`.
- Pass `{ initialEntries: [{ pathname, state }] }` when the page reads `useLocation().state`.
- Pass `{ initialEntries: [{ pathname: '/path/:id', search: '?key=value' }] }` for search-param pages.
- Wrap route-param pages in `<Routes><Route path="/path/:id" element={<Page />} /></Routes>` so `useParams` resolves.
- Call `localStorage.clear()` in `afterEach` for pages that persist filter/column preferences.

## Pure-logic test files

Helper modules that return no JSX should use `.ts` test files (not `.tsx`). Functions that return React elements can be tested by inspecting `.props` directly — no rendering required:

```ts
// eol-helpers.test.ts (pure .ts — no JSX)
import React from 'react';
const el = eosDisplay('2024-01-01') as React.ReactElement;
expect(el.props.className).toContain('eol-badge--eol');
```

## React Query v5 — behavior that affects tests

`@tanstack/react-query` v5 changed `isLoading`:

| Condition | `isPending` | `isLoading` | `isFetching` |
|---|---|---|---|
| Disabled query (`enabled: false`), no data | `true` | **`false`** | `false` |
| Fetching for the first time | `true` | `true` | `true` |

Pages that use `isPending` in a loading guard will show a spinner forever in tests when a dependent query is disabled. **Fix:** provide non-empty data so the page's `hasData` flag becomes `true`, bypassing the loading branch. Pages that use `isLoading` work normally with disabled queries.

The test `QueryClient` uses `retry: false` so failed queries settle immediately without network retries.

For `AiPoliciesPage` tests, mock the policy catalog, global framework registry/framework coverage, and latest assessment-state summaries. Production framework fixtures use `OWASP_GENAI_LLM_TOP_10` version `2026`.

## Coverage thresholds

Thresholds are enforced by `vitest.config.ts` and **only move up, never down**. After adding a new batch of tests, run `npm run test:coverage`, read the summary line, and ratchet the floor in `vitest.config.ts` to match the new measured value.

## Key constraints

- Components in `src/components/` must stay under ~300 lines. New substantial components go under `src/features/<feature>/`.
- `src/lib/riskScoring.ts` is pure TypeScript — no React imports, no API calls.
- The app uses React StrictMode (see `src/main.tsx`) — effects run twice in development, so side effects should be idempotent.
- Theme (`dark` / `light`) is persisted in `localStorage` under `scoutai-theme` and applied as `data-theme` on `<html>`. `AppShell` defaults to dark; the presentation boundary restores a valid saved preference on public/auth direct loads. Public canvases retain their explicit local palette.
- **Use the shared API layer** (`api/client.ts` or the established CVE adapter), not raw authenticated `fetch()` or inline credentials. Production builds reject static auth inputs and scan the output bundle. A new endpoint belongs behind the shared base/auth/error handling.
