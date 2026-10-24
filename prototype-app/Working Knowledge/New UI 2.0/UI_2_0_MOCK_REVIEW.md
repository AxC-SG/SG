> **Updated handoff:** The October 24 behavior audit and corrections are documented in [BEHAVIOR_PARITY_AND_IMPLEMENTATION.md](BEHAVIOR_PARITY_AND_IMPLEMENTATION.md). That contract supersedes earlier 1:1 mock claims. The current reference includes AI Findings and corrected CVE decisions; the live application remains the behavior authority.

# UI 2.0 mock review

Reviewed 24 October 2026. Scope: the standalone `design-reference` project, compared with the current frontend's representative Platform and Tenant workflows. This is a design and implementation-readiness review, not a full functional or security audit. No mock or application source was changed.

## Recommendation

Approve the visual direction. Begin a limited token/shell pilot after resolving the shared-component issues below. Enrich the reference before using it as the specification for a whole-application restyle.

The missing work is mostly **domain compositions and realistic state combinations**, rather than more generic buttons, cards, or dialogs. Do not mock every route. Add the few screens that exercise the parts a normal list/detail example cannot represent.

## What is already strong

- A coherent system: Inter, monospace identifiers, neutral surfaces, restrained indigo, semantic severity colors, and explicit light/dark tokens.
- Eight representative page files: overview, findings, finding detail, connectors, configurations, tenant management, login, and the component library.
- Useful coverage of dense tables: filtering, removable chips, grouping, queues, selection, bulk actions, column visibility, resizing, and pagination.
- Broad primitive coverage: native form controls, validation examples, secret reveal, file input/dropzone, progress, loading, empty/error states, dialogs, drawers, popovers, tooltips, tabs, disclosure, properties, timelines, and steps.
- A React Flow example and CVE risk-phase example already exist. They should be extended in context, not rebuilt as separate generic components.
- The migration guidance explicitly protects existing labels, navigation targets, roles, conditional actions, and first-render visibility. Retain that discipline.

## Corrections before implementation handoff

### 1. Align the mock with the current supported product scope

`src/design-preview/data.ts:150` still models SCCM as unconfigured, generic Azure Discovery as an ordinary failed connector, and a Patch Management section containing SCCM Patch, BigFix, and Tanium. `pages/ConnectPage.tsx` opens a generic configuration screen for these entries.

The current application's scope explicitly contains generic Azure/SCCM operations and has retired unsupported Patch Management forms. A `mockOnly` warning does not make those screens a valid zero-functional-change migration reference.

**Action:** reconcile the connector catalog, availability states, and per-connector form patterns with the current frontend. Preserve unavailable/read-only treatments and avoid resurrecting retired flows. Also distinguish Platform feed management from Tenant inventory connectors.

### 2. Correct popover placement inside wide tables

**Observed in the browser:** opening Findings → Filter Severity near the right edge produces a popover whose labels extend outside the visible table area and are clipped. This combines `Popover`'s absolute positioning with the table/card overflow containers.

Relevant files: `components/primitives.tsx:180`, `styles/components.css:652`, and `pages/FindingsPage.tsx:355`.

**Action:** define viewport/container collision handling and scrolling behavior for filters, column menus, and tooltips. An existing compatible overlay solution or a portal can address placement; preserve the current trigger and click semantics. Validate the last visible column, both scroll extremes, and short tables.

### 3. Finish keyboard and form accessibility contracts

**Observed:** after opening Component Library → Modal, two Shift+Tab presses from Assigned To move focus to the background “Hover for tooltip” button while the modal remains open.

- `components/overlays.tsx:22` moves initial focus and handles Escape, but does not contain focus or make the background inert.
- `components/primitives.tsx:147` leaves a closed drawer mounted behind `aria-hidden`; its controls are not removed from keyboard navigation. Its dialog also needs an accessible name and focus handling.
- `components/forms.tsx:9` displays field errors and required markers but does not associate hints/errors with controls or communicate invalid/required state. These need explicit call-site props or a field API that supplies the appropriate attributes.
- The switch primitive changes a checkbox's role to `switch`; it cannot simultaneously preserve existing `getByRole('checkbox')` queries. Keep the role required by each existing call site.
- Tabs and menus need their keyboard behavior specified and checked, not just role attributes.

**Action:** add reusable acceptance examples for Tab/Shift+Tab, Escape, focus restoration, closed-overlay focus exclusion, arrow-key navigation where appropriate, and field error announcement. Reuse the live behavior where the restyle contract requires it; separately identify any behavior changes.

### 4. Improve secondary-text contrast and dense-layout behavior

Captions, hints, timestamps, and navigation section labels frequently use `--dp-text-3` at small sizes. They are visually faint in both themes (`styles/tokens.css:21` and `:52`). Reserve very low-emphasis text for nonessential decoration; use a stronger secondary token for information users must read.

**Observed:** at a 390px viewport, Findings Score retains a six-column row. The first three selects are about 43px wide and their selected values are unreadable (`styles/components.css:784`). Define a stacked, labeled rule-row variant for narrow screens.

At a 1280px desktop viewport, Findings' five widgets form two rows, pushing much of the table below the initial view. The Platform console also spends substantial width on two navigation rails. Validate a denser presentation without hiding current first-render controls or introducing additional clicks.

### 5. Separate the baseline restyle from optional product changes

The README describes command search, sidebar collapse, and toasts as optional additions, off by default. The current shell renders command search/collapse and registers their shortcuts unconditionally (`DesignPreviewApp.tsx:83`, `:198`, `:208`).

**Action:** provide a baseline preview with optional changes disabled, plus a separate opt-in preview. The handoff should make it unambiguous which UI belongs in the behavior-preserving restyle. Do not migrate the demo's simplified mutation/validation handlers into the application.

## Recommended enrichment

| Priority | Add or extend | Components and states it must demonstrate | Why the present reference is insufficient |
|---|---|---|---|
| Before domain migration | **CVE assessment workbench** | Investigation steps/canvas; applicability table; expandable VEX/evidence; bulk and individual decisions; finding-generation configuration; decision summary; pending/failed/saved states; existing navigation guard | A risk-phase illustration and a normal Finding Detail do not cover the investigation → applicability → create-findings workflow. |
| Before domain migration | **AI asset detail with relationships and evidence** | Overview/policies/findings/relationships tabs; graph node selection and navigation; long node names; disconnected and dense graphs; empty/loading/error graph states; deployment unverified/stale/no evidence; provenance and timestamps | The five-node component demo proves node styling, not how the graph, evidence, policies, and asset metadata work together. Keep runtime evidence outside the current product scope. |
| Before Platform policy migration | **Platform policy distribution/detail** | Policy metadata and lifecycle; framework mappings; native multi-tenant selection; selected tenants versus all active tenants; dev/test, approval and publish controls; shipping blockers; rollout progress and failed jobs | Tenant lifecycle administration does not exercise policy governance or cohort distribution. |
| Before shared-component sign-off | **An interactive state/scenario board** | Read-only auditor, inventory admin, tenant admin and Platform owner; AI entitlement unavailable; tenant provisioning/blocked/expired states; session verification failure; retained data during refresh; section-level failure; validation and save failure; existing pending and partial-result feedback | Current persona preview changes the displayed label, not authorization-dependent rendering. A global loading toggle and isolated alert examples do not demonstrate composed application states. Use fixtures, without adding new product flows. |
| Before broad rollout | **Dense inventory/detail and drawer fixture** | Long ARNs/CPEs/package names; null values and zeroes; many columns; expandable relationships; selected rows; software/EOL evidence; real drawer contents; last-column filters; narrow and zoomed layouts | Findings demonstrates a flat list. A generic EOL drawer with placeholder content does not settle inventory hierarchy, lifecycle evidence, or content overflow. |

Useful follow-up coverage, without needing a whole new page for each:

- Extend the existing connector form with stored/masked secrets, preserved versus replaced values, connection failure, save failure, and contained/unavailable states.
- Extend file input into a supported BOM or bulk-invitation example: chosen file, parsing/validation errors, per-item results, pending work, and completion. Retain native file controls and existing behavior.
- Include at least one actual native multi-select example; the production policy workflow already uses one. Do not replace it with a new searchable picker during a zero-change pass.
- Add a campaign-detail composition when that family is scheduled: current lifecycle actions, blocked state, exceptions, notify groups, and watchlist. It can reuse the established detail primitives.
- Add invitation/setup/expired-session examples before public/auth migration. A login form alone does not specify these first-use states.
- Extend Platform feed management with feed-specific settings, run failures, review/release states, and ownership/scope distinctions before those routes migrate.

## Minimum practical next iteration

1. Fix scope drift, popover clipping, overlay focus, supporting-text contrast, and narrow rule rows.
2. Add three composed screens: CVE workbench, AI asset detail, and Platform policy detail/distribution.
3. Expand reference controls into a fixture board for permissions, entitlement, lifecycle, loading/refresh, failure, and dense data. Add an inventory/EOL drawer fixture there.
4. Produce light and dark captures for the baseline at desktop and narrow widths, including one open overlay and one failed operation. Add keyboard checks and a zoomed-layout check.
5. Validate a limited token/shell pilot on actual legacy routes before applying the design across all pages. The token bridge does not cover hardcoded colors or prove layout compatibility.

## Verification performed

- Installed locked dependencies with scripts disabled. The offline attempt could not complete because a required package was absent from cache; the normal locked install succeeded.
- Ran the standalone mock at `http://127.0.0.1:5174/design-preview.html` and inspected representative dashboard, Findings/filter, Platform console, component/graph, modal, and rule-builder states. Inspected desktop, 768px, and 390px layouts.
- `npm run typecheck`: **passed**.
- Default `npm test` on this host's Node **26.12.1**: failed because the environment exposed an unusable global `localStorage`, followed by cascading test failures.
- `NODE_OPTIONS=--no-experimental-webstorage npm test`: **14/14 passed**. Declare a tested Node environment or make the test harness robust to this environment difference; do not describe the default command as verified green here.
- `npm run build`: **failed** with `Could not resolve entry module "index.html"`. The standalone project has `design-preview.html`, while `vite.config.ts` does not set a build input. Configure that entry or provide `index.html` for the standalone build. The README's frontend-relative setup/build description also needs updating for this copied project.
- These checks validate the mock in isolation. They do **not** establish API behavior, authorization, functional parity, accessibility completeness, or full-application visual regression safety.

The intended gate is: **approved design direction + completed shared-component contracts + representative domain/state coverage**, followed by incremental migration. More decorative components would add little value at this stage.
