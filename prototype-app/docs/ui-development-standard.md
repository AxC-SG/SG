# UI development standard

Effective October 28, 2026. This is the required starting point for every new screen and every substantial screen change. It applies to tenant, platform, login, setup and invitation experiences. UI 2.0 is the only application presentation; new development must extend it consistently.

## Architecture and ownership

```text
main.tsx
  styles/index.css                    one eager application stylesheet entry
  QueryClientProvider + BrowserRouter
    PresentationBoundary              data-ui and saved theme before paint
    App.tsx                           public/auth routes, session gates, AppShell
      pages/<Screen>Page.tsx          route composition and orchestration
        features/<feature>/           domain components, types, queries, helpers
        components/                   existing cross-feature React components
        api/client.ts                 shared HTTP/auth/error handling
        features/cve-workbench/api.ts specialized CVE API using shared auth/base
```

`AppShell` currently lives inside `src/App.tsx`; there is no separate shell package. Reuse its sidebar, top bar, workspace context, navigation and theme control. Do not create a second shell for a feature. Pages are lazy-loaded, but application styles load eagerly so direct links and navigation have the same cascade.

Keep domain types in `src/features/<feature>/`; `src/types/index.ts` is a re-export surface. Keep substantial domain components in their feature folder. Small reusable cross-feature components belong in `src/components/` (new additions should stay under about 300 lines; existing larger files are not templates to copy). Pure calculations belong in feature helpers or `src/lib/`; they should not fetch data or import React unless they render elements.

TanStack Query owns remote state. Reuse the feature's query hooks, keys, polling constants, invalidation and existing previous-data behavior. Local state owns temporary selections and drafts; URL state owns only the filters/navigation defined by that feature's contract. Persist successful writes through the API and verify them after reload. Do not claim local drafts are server-persisted or turn page-local filters into tenant-wide searches without an explicit behavior change.

## Reuse what exists

The current design system combines React components and shared CSS classes. It does **not** expose a generic React `Button`, `Input`, `PageHeader` or `Badge` library; the one modal is `components/Dialog.tsx`. Use native semantic elements with the shared classes instead of importing mock/reference components or inventing a parallel library.

| Need | Existing implementation | Usage rule |
|---|---|---|
| Shell, tenant/platform navigation, theme | `src/App.tsx` (`AppShell`), `src/app/SidebarNav.tsx`, `src/app/AccountMenu.tsx` and `src/app/routes.ts` | Register lazy routes and typed path helpers; extend the existing navigation and access gates. Navigation (Option B) uses non-clickable group headings, real route links with `aria-current` and sibling disclosure buttons; `navDestinationForPath` selects exactly one destination per route. Groups left empty by role/entitlement filtering are omitted |
| Route title (H1) | `src/app/pageHeaderState.ts` (`usePageHeader`), `src/app/PageHeader.tsx` (`PageHeaderProvider`) | The shell renders the only authenticated H1 and `main`; `routeTitleForPath` is the fallback. A page that knows a better title (record name, CVE ID) calls `usePageHeader({ title, actions? })`, passing `null` until the record is known. Registration is pathname-keyed and applied in a layout effect, so the previous record's title never appears on the next route. Feature pages and panels use `h2` and below; do not add another `h1` or `main` |
| Dense tabular data | `components/DataTable.tsx`, `DataTableColumnChooser.tsx`, `dataTablePreferences.ts` | Give each table a stable, unique `storageKey` and mark identity/action columns `priority: 'essential'` (always shown), secondary ones `'optional'` (hidden below 768px unless the user chose otherwise); set `minWidth` where 96px is not readable. Columns never shrink below their minimum: the labelled region scrolls instead. Preferences are written only by user actions (`:preferences:v2` overrides, `:order`, widths); the legacy `:hidden` snapshot is imported, not written. The chooser offers checkboxes, Use default, Move left/right and Reset columns; resize handles take Arrow keys in 8px steps. Feature owns paging, filters, selection and actions |
| Dialogs and confirmation | `components/Dialog.tsx`, `components/ConfirmDialog.tsx` | One native modal: name it with `title` or `labelledBy`, keep the feature's panel class as `className`. It focuses an autofocused field or the first control, keeps Tab inside, closes on Escape/backdrop and returns focus to the opener. Pass `busy` during a non-cancellable write: dismissal is blocked and the dialog says why; disable the feature's own close buttons too. Keep input mounted on a recoverable failure. Do not stack a second modal for discard prompts; replace the content in place |
| Exclusive local view choice | `components/SegmentedControl.tsx` | Uses `aria-pressed`; route navigation still uses route links/helpers |
| Filter discovery and grouping | `components/FilterBuilder.tsx`, `MultiGroupBy.tsx` | Reuse where their interaction model fits; retain feature-specific request and grouping semantics |
| Metric and freshness feedback | `components/StatCard.tsx`, `PageFreshnessStatus.tsx` | Reuse existing tones, captions, last-update and refresh/delay treatment |
| Section data states | `components/AsyncSection.tsx` | Presentation-only. The feature passes `state` (`pending`, `ready`, `empty`, `filtered-empty`, `error`, `unavailable`), its own retry/clear actions and truthful copy; `refreshError`/`staleMessage` keep cached data visible. One AsyncSection per independent dependency, so a secondary failure never hides a populated sibling |
| Metric availability | `components/MetricValue.tsx` | The feature passes `availability` separately from `value`: valid zero renders `0`, unavailable renders `—` with an accessible reason, pending renders a placeholder. Never map missing data to zero to feed it |
| Inline help | `components/InfoTooltip.tsx`, `MetricInfoIcon.tsx` | Keep labels and essential instructions visible; verify help remains available by keyboard |
| Route failure | `components/RouteErrorBoundary.tsx` | Follow the existing route wrapper pattern; query errors still need feature-level messages and retry |
| Shared charts | `features/widgets/FplWidgets.tsx` (`DonutChart`, `HBarChart`, `ChartLegend`, `WidgetCard`) | Preserve metric scope and textual meaning; use the same semantic colors. Interactive bars and legend entries are real buttons with `aria-pressed`; a donut carries a text summary and pairs with a `ChartLegend` as its keyboard equivalent. An active `WidgetCard` announces "filter applied" and, given `onReset`, shows a labelled Clear |
| Queue controls | `components/QueueControls.tsx` (`ActiveFilterChips`, `ResultScope`, `Pager`) | Presentation-only. Chips name each removal and offer Clear filters; `ResultScope` states the shown range, the reported total (never invented: pass `null`), filter scope and page/all-page selection; `Pager` is a labelled navigation that uses `hasNext` when no page count is reported |
| Domain displays | `EolBadge`, EOL panels/drawer, `CveRiskScorePanel`, CVE workbench and AI graph components | Reuse within their supported domain; do not replace real workflows with simplified decorative cards |
| Buttons and forms | `.btn` + `.btn-primary`, `.btn-secondary`, `.btn-ghost`, `.btn-sm`; native labelled inputs/selects/textareas | Shared appearance comes from `ui2/primitives.css`; keep focus, validation and disabled states |
| Panels, states and badges | `.panel`, `.panel-header`, `.panel-caption`, `.notice` with tone modifiers, `.empty-state`, `.severity-pill`, `.status-pill` | Reuse existing vocabulary and meaning; do not invent another success/severity palette |

Inspect the selected component's props and a real consumer before using it; the inventory above is not a guarantee that every existing component already meets every accessibility requirement. Extend a shared component when a real reusable gap exists. Keep one-off domain logic local and avoid premature abstractions.

## Screen composition

Start from the closest implemented screen in the same family: Findings/AI Findings for queues and detail; Inventory for inventory/detail/relationships; CVE workbench for investigation; Governance for tenant/platform policy/admin; Connect for providers and configuration; Experience for dashboards, campaigns, operations and auth entry.

Use the shell's page heading/context and existing family header treatment. Within the page, keep a clear hierarchy: summary/freshness where relevant, primary action, filters/tabs, main table/detail/form, then secondary evidence/actions. Use the same button priority, label style, spacing scale, table density, badge meaning and feedback placement as sibling screens. Show tenant/platform scope explicitly where actions depend on it.

Consistency concerns presentation and interaction conventions. Keep genuine domain distinctions: vulnerability finding rows support selection while AI finding rows navigate; CVE applicability and analyst impact are separate; role and entitlement gates are independent. Do not force unrelated workflows into a shared state machine to make them look alike.

Every data screen must cover the states that apply: initial loading, populated, empty, filtered-no-results, refresh with existing data, delayed/stale data, failed load with retry, unavailable/contained capability, permission/entitlement restrictions, and saving/success/failure. Preserve drafts and selections on recoverable errors. Disable duplicate submission and only show success after the mutation succeeds. Destructive actions use the existing confirmation pattern. Never substitute fake counts, sample inventory or a successful-looking mock action for unavailable backend behavior.

## Styles, tokens and boundaries

The exact import order and ownership are in [UI 2 styles and rollback](ui2-styles-and-rollback.md). Do not import application CSS from pages or components or add a second entry point. Add family rules to the existing family sheet and shared behavior to the appropriate shared sheet. A genuinely new family can add a sheet through `ui2/index.css` after its ownership and regression coverage are established.

- Application rules must be scoped under `html[data-ui='2']`; shared defaults use `:where(html[data-ui='2'])` where zero added specificity is required. Prefer a family/page root for new page-specific selectors. Do not add global `.active`, `button`, `table` or `.panel` overrides.
- Use `--dp-*` tokens for new app colors, fonts, spacing, radius, shadows, sizes and motion where a token exists. Keep semantic critical/high/medium/low and success/warning meanings. Add any needed shared token in `ui2/tokens.css` for both themes; do not recreate retired aliases such as `--panel` or `--muted` in app CSS.
- The spacing names are literal values: `--dp-space-5` is 20px, `--dp-space-6` is 24px, `--dp-space-8` is 32px. Do not translate old numbered spacing tokens mechanically. A necessary domain geometry (graph coordinates, measured widths) can remain computed; static presentation belongs in CSS.
- Use the existing `data-theme` on `<html>` and `scoutai-theme` storage key. The mounted app defaults to dark when no valid preference exists. Do not create per-screen theme stores or hard-coded dark/light variants. The current app font stack is declared by `--dp-font`/`--dp-mono`; do not add external font/CDN dependencies.
- `/demo` and its descendants intentionally use public styles. Login, setup and invitation routes use UI 2.0 even though some markup uses public class names. `presentationBoundary.ts` and `PresentationBoundary` own that boundary on direct loads, links and Back/Forward; components must not toggle `data-ui` themselves. Public content/canvases can intentionally remain light inside a stored dark theme; preserve their explicit local palette.
- Keep full identifiers available through wrapping, detail or copy affordances; avoid document-wide horizontal overflow. Confine necessary wide tables/tab strips to their scroll containers. Keep active underlines and focus indicators inside those containers.
- Use semantic buttons and links, labelled fields, visible keyboard focus, accessible errors and status announcements, readable contrast, Escape/close behavior and focus return for overlays. Honor reduced motion. Check both themes, narrow screens and real browser zoom. Do not copy known accessibility defects into new screens.

## Adding a screen

1. Identify the family, closest sibling, actor/entitlement requirements, real API contract and required states. Document any shared-pattern gap before introducing a new pattern.
2. Add feature types/hooks/helpers and route composition. Use `api/client.ts` or the established CVE API; preserve centralized base URL, auth headers and errors. Do not add raw authenticated `fetch()` calls, browser secrets, duplicate actor stores or client-side authority bypasses.
3. Register the lazy route in `App.tsx`, path helpers in `app/routes.ts`, and the existing shell navigation when appropriate. Apply session/platform/tenant/role/entitlement wrappers consistently. Frontend visibility never grants backend access.
4. Compose the existing components/classes and family root. Keep APIs, enum values, pagination, return links, router state and mutation semantics explicit and domain-owned.
5. Add or update page/interaction tests using `src/test/test-utils.tsx`, plus error and access cases relevant to the feature. Update `e2e/routes.mjs`, `affected-routes.json`, fixtures and journeys when the route or behavior changes. Unexpected API requests must fail; fixtures cannot silently hide new calls.
6. Run `npm run lint`, `npm run typecheck`, `npm run build`, and `npm run test:coverage` from `frontend/`. Keep the configured coverage floors and assertions. Then run `npm run e2e:build` and relevant journeys. Presentation changes require visual/affected-route and axe checks in the pinned Playwright image; shared changes require broad family/public-boundary coverage. Run live journeys with approved disposable accounts/data for changed server workflows and verify persistence after reload.
7. Review dark/light, 390px and 1280px, keyboard and direct/link/Back/Forward behavior. Use the four-width sweep (390/768/1280/1440) for shared layouts and the final integrated candidate. Update the docs and include screenshots and test scope/limitations in the review.

See [the browser gate details](ui2-styles-and-rollback.md#browser-gates) for commands, baseline review and environment requirements. Passing fixture tests does not prove authenticated backend persistence or release readiness.

## Changing the standard requires approval

Routine screens that use these patterns can proceed under the development request. A departure that changes the shared shell/navigation, token system, component library, interaction conventions, CSS architecture, theme behavior or public/app boundary requires explicit user approval during that development, before implementing the departure.

Present a concrete proposal that includes:

1. The user problem and why the current shared pattern is insufficient.
2. The proposed change and an option that keeps the current standard.
3. Pros and cons: usability, accessibility, performance, implementation/maintenance cost and compatibility.
4. Every affected family, screen and shared component, plus a plan to update them together so the app has no split experience.
5. A preview/example, verification and rollback plan, and any temporary exception's owner, scope and removal condition.

Record the user's decision and its scope in the feature design/PR, with a link or exact decision text. Approval applies only to the described change; it does not authorize future unrelated exceptions. After approval, update this standard and shared components/docs as part of the same coherent change. Without approval, use the current standard. Do not ship a permanent per-screen fork or a second design system; a temporary exception must be explicitly approved with its convergence plan.

## UI improvement proposal status

The [UI improvement package](<../Working Knowledge/New UI 2.0/UI 2.0 improvements/README.md>) contains UI-only feedback, a ranked adoption plan and a separate non-UI ledger. Its [shared UI proposal](<../Working Knowledge/New UI 2.0/UI 2.0 improvements/SHARED_UI_PROPOSAL.md>) specifies candidate header/query-state/dialog/metric/table contracts, icons, exact visual values and mobile presentation. These are proposed additions, not existing component APIs or implemented rules. Continue using the current inventory above until the accepted contract is implemented and documented with its scoped decision and verification. No read-only mobile restriction, policy entitlement expansion or non-UI architecture change is adopted by that proposal.
