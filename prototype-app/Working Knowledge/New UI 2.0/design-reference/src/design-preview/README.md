# Design reference — UI modernisation

A runnable, standalone reference for restyling the whole app. It is separate from the
production frontend and makes no API or provider requests. All mutation results are
local simulations with deterministic sample data.

```bash
cd "prototype-app/Working Knowledge/New UI 2.0/design-reference"
npm ci --legacy-peer-deps
npm run dev
open http://127.0.0.1:5174/design-preview.html#/reference

npm run typecheck
npm test
npm run build
```

The standalone build emits `dist/design-preview.html` and its assets. Serve the
`dist` directory over HTTP to review the built version. No production app imports
this project.

## Production handoff — behavior authority

Read [behavior parity and implementation readiness](../../../BEHAVIOR_PARITY_AND_IMPLEMENTATION.md)
before migrating this design. The live frontend controllers, hooks, filters, DTOs
and route helpers remain authoritative. This mock is not a drop-in production app.

The CVE reference now separates applicability from computed impact and analyst
disposition, permits partial assessment saves, and covers investigation, finding
configuration, fixes and notification drafts. AI Findings has its own routes and
domain filters with the same shared presentation as vulnerability findings.

## Enriched review routes — 24 October 2026

Start at the **Review hub**. Its cards link all enriched examples, and the topbar
Review hub button is available throughout the app.

| Mock route | Covers |
|---|---|
| `#/findings/ai` | AI policy findings, provider/status/subscription scope, action queue and row navigation |
| `#/findings/ai/vulnerabilities` | AI-resource-scoped software vulnerabilities |
| `#/reference` | Review hub and original pattern links |
| `#/vuln-repo/org-cves/CVE-2026-31337` | Overview, investigation, separate applicability/impact, impacted assets/configuration, fixes, notification drafts, retained edits |
| `#/inventory/ai/support-agent` | AI asset context, policies, static evidence, selectable relationship graph, dense/empty graph, provenance drawer |
| `#/platform/ai-policies` | Platform policy catalog |
| `#/platform/ai-policies/tool-access` | Dev/test cohort → evidence approval → publication; selected/all-active scope; failed rollout and retry |
| `#/inventory/overview` | Long identifiers, expandable versions, missing/zero values, right-edge filter, software/EOL drawer |
| `#/reference/scenarios` | Role matrix, entitlement, lifecycle, refresh, partial-error, failed-save and baseline/enhancement fixtures |

Reference controls expose the same role and scenario settings without leaving a
page. A tenant role changes navigation and mutation affordances; this is a local
UI simulation, never a substitute for real backend authorization. Platform routes
select the Platform Owner fixture; tenant domain routes select Tenant scope.

Useful review sequences:

- Workbench: review step 2, decide Legacy reporting, confirm applicability, create findings.
- Policy: deploy to dev/test, enter an approval note, approve, choose publication scope, publish.
- Failure: choose **Save failure**, edit and submit; inputs/decisions remain available for retry.
- Partial rollout: choose **Partial data failure** before publishing, then retry the failed tenant job.
- Keyboard: open a modal/drawer; test Tab, Shift+Tab, Escape, and focus restoration.
- Dense layout: expand an inventory version, scroll to Lifecycle, open its filter, and inspect a drawer.

The connector catalog omits retired Patch Management forms. Contained SCCM and
generic Azure entries show an unavailable/read-only screen; they expose no sync
or credential form. Existing provider configuration examples remain mock patterns;
the production migration must preserve each real connector's actual fields/logic.

| Route | Demonstrates | Live counterpart |
|---|---|---|
| `#/exposure` | Dashboard pattern | `ExposureDashboardPage` |
| `#/findings` | List pattern (widgets, GROUP BY, header filters, actions, queues, dialogs, paging) | `FindingsPage` |
| `#/findings/F-10420` | Record-detail pattern | `FindingDetailPage` (+ Host/Software/AI asset/Campaign detail) |
| `#/connect`, `#/connect/aws-discovery`, `#/connect/run-history` | Catalog + config form + run queue | `ConnectPage`, `*ConnectorPage`, `IntegrationRunQueuePage` |
| `#/configurations/<section>` | Settings pattern (sliders, rule builder, Save row) | `ConfigurationsPage` |
| `#/platform/tenants` | Console pattern (secondary rail, inline create form, lifecycle table) | `PlatformConsolePage` → `TenantLifecyclePanel` |
| `#/login` | Public/auth pages | `DemoPublicPages` → `LoginPage` |
| `#/components` | Every primitive and state, incl. React Flow graph | — |
| `#/x/<app path>` | Any other nav destination → which pattern to use | — |

"Reference controls" (bottom-left, dashed) switches tenant/platform scope and loading
skeletons. It is mock-only chrome and has no product equivalent.

## The hard constraint: zero functional change

Phase 2 restyles; it does not redesign behaviour. Every rule below exists because the
live app's tests (265 `getByRole`, 553 `getByText`, 52 `getByLabelText` queries) or users
depend on it.

1. **Keep every visible string.** Headings, button labels, captions, placeholders, empty-state
   copy, notice text. `App.tsx` `pageTitle` text (e.g. "Exposure Dashboard") stays.
2. **Keep roles and accessible names.** `aria-label`, `title`, `role="status"` vs `role="alert"`,
   `role="tab"`/`aria-selected`, `aria-pressed`, `aria-expanded`. Icon-only buttons keep their label.
3. **No new clicks.** Anything visible on first render today stays visible on first render
   (e.g. the inline create-tenant form, per-row tenant buttons, Findings Resolve/More which are
   always rendered and only *disabled* without a selection). Don't move controls into
   menus, drawers, dialogs or collapsed sections.
4. **Same elements.** A `<button>` stays a button, a `<Link>` stays a link, native `<select>`,
   `<input type="range|date|datetime-local|file|password">`, `<details>` and `window.confirm`
   stay native. Restyle them; don't replace them with custom widgets.
5. **Same navigation targets.** Click handlers keep their `navigate(...)` destinations,
   query params and `state`. Row click on Findings toggles selection (it does not open the row).
6. **Same conditional rendering.** Status-dependent actions (FindingDetail OPEN vs not,
   tenant PROVISIONING_FAILED/ACTIVE/SUSPENDED), role and entitlement gates are untouched.
7. **Class names tests read stay.** Add new classes alongside them; don't remove these:
   `fpl-widget--active`, `fd3-tab--active`, `ai-severity-grid--compact`, `active`,
   `.fd3-modal` (+ `.btn-primary`/`.btn-danger` inside it), `.grid-exposure-table tbody tr`,
   `.grid-exposure-cell--high .grid-exposure-cell-btn`, `.fpl-hbar-row`, `.react-flow__pane`.
8. **No invented data.** Don't add trend deltas, sparklines or insights the page has no API
   data for. `StatTile.spark` is only for series the page already loads.
9. **Theme contract.** `data-theme` on `<html>`, `scoutai-theme` in `localStorage`, default `dark`.

### Optional additions (need explicit approval; off by default)

These exist in the reference but are **new behaviour**, so they're not part of the
zero-change pass: ⌘K command palette, sidebar collapse to icon rail (⌘\\), sticky
first columns and column resize on Findings (DataTable already resizes), toasts
(never as a replacement for an inline notice).

Command search and desktop sidebar collapse are disabled in the baseline. Enable
**Optional UI enhancements** in Reference controls or States & permissions to review
them. Toast demonstrations remain part of the component reference, not approval to
replace inline production notices. Narrow layouts retain the Menu control.

## Migration path (recommended order)

1. **Token bridge — one PR, no markup changes.** Append `@import`s for `tokens.css` then
   `legacy-bridge.css` at the end of `src/styles/index.css` (after `base.css`; move both files
   under `src/styles/` first). Every
   legacy variable (`--border` ×701, `--accent` ×574, `--muted` ×527, `--panel*`, radii,
   fonts, shadows) re-points to the new tokens, so the whole app picks up the palette,
   type and elevation at once. Remove the gradients (`--bg-gradient`, `--shell-glow`).
   Verify every page in both themes.
2. **Shell.** Restyle `App.tsx` sidebar/topbar markup classes (`.sidebar`, `.nav-btn`,
   `.nav-sub-btn`, `.nav-expand-toggle`, `.topbar`, `.tenant-context-pill`,
   `.settings-menu*`, `.test-persona-*`) to the `dp-` shell look. Grouping headings and
   icons are presentational; labels, order and the label-navigates / caret-toggles split
   stay exactly as `renderExpandableNavButton` does today.
3. **Shared primitives.** `.btn*`, `.panel*`, `.notice*`, `.status-pill`/`.severity-pill`,
   form controls, `.fd3-modal`, `DataTable.css`, `StatCard`, `InfoTooltip`, `ConfirmDialog`.
4. **Page families**, one PR each, in pattern order: dashboards → lists → details →
   catalog → settings → console → public pages. Each PR: existing tests green unchanged,
   screenshots light + dark, no test edited except to add coverage.

## Component mapping

| Reference | Replaces (legacy) |
|---|---|
| `StatTile` | `.exec-kpi`, `.fpl-kpi-card`, `StatCard` |
| `Card` | `.panel` + `.panel-header` + `.panel-caption` |
| `PageHeader` | `.topbar-copy` eyebrow/h1, `.config-section-head` |
| `Badge` / `SeverityBadge` / `StatusBadge` | `.severity-pill`, `.status-pill`, `.risk-score-badge` |
| `Alert` | `.notice`, `.notice.success`, `.notice.error` |
| `FreshnessStatus` | `PageFreshnessStatus` visuals |
| `Field`, `TextInput`, `PasswordInput`, `Select`, `Textarea` | `.fpl-form-*`, `.field-hint`, raw inputs |
| `Checkbox`, `RadioCards`, `Switch`, `Slider`, `FileDropzone` | `.checkbox-row`, raw radios, range inputs, upload inputs |
| `Tabs` | `.fd3-tab-bar`, `.connect-filter-bar`, pill sub-navs |
| `Segmented` | `SegmentedControl` |
| `Accordion` / `Collapsible` | `<details>` blocks, "show more" toggles |
| `Modal` / `ConfirmDialog` | `.fd3-modal`, `.modal`, `ConfirmDialog` |
| `Drawer` | `EolDetailDrawer`, `SoftwareIdentityDetailDrawer` shells |
| `Menu` + `Popover` | `.fpl-more-*`, `.fpl-colvis-*`, `.fpl-col-filter-*`, `.settings-menu` |
| `Tooltip` | `InfoTooltip`, `MetricInfoIcon` |
| `PropertyList` | `.fd3-kv-table` / `KVRow` |
| `Timeline`, `Stepper`, `CodeBlock` | timeline lists, wizard steps, `<pre>/<code>` blocks |
| `.dp-table*`, `.dp-toolbar`, `.dp-filter-chip`, `.dp-pagination` | `DataTable.css`, `.fpl-table*`, `.fpl-chip*`, `.fpl-pagination` |
| `.dp-widget*`, `.dp-hbar*`, `.dp-group-*` | `FplWidgets`, `.fpl-group-*` |
| `.dp-heatmap` / `.dp-heat` | `.grid-exposure-*` |
| `.dp-connector-card`, `.dp-status-dot` | `connect.css` connector cards + health dot |
| `.dp-graph-node`, `.dp-graph` | `AiDependencyGraph` node/edge/canvas styles |

## Files

```
design-preview.html            entry (frontend/)
src/design-preview/
  DesignPreviewApp.tsx         shell + hash router
  nav.ts                       nav IA mirroring App.tsx (labels, order, real paths, pattern per leaf)
  data.ts                      deterministic mock data shaped like the real DTOs
  previewContext.ts            mock-only reference controls
  components/                  primitives, forms, feedback, overlays, disclosure, CommandPalette
  pages/                       one file per pattern
  styles/tokens.css            design tokens (light/dark + scales)
  styles/legacy-bridge.css     legacy var → token map for phase 2 step 1
  styles/components.css        all component/page styles
  DesignPreviewApp.test.tsx    pins the behaviours above
```
