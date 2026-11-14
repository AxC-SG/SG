# Shared UI elements proposal

Status: revised implementation specification; user selected separate Intelligence and six peer Workbench tabs. Shared implementation and verification remain pending; no application changes are made by this document. Updated October 28, 2026.

This is the proposal format required by the [standing standard](../ui-development-standard.md#changing-the-standard-requires-approval). It covers visible UI elements and their interactions. Global route-registry architecture, data-router migration, metric definitions and backend changes belong in the [non-UI ledger](NON_UI_IMPROVEMENTS_LEDGER.md). The Workbench has a narrowly specified tab/task query adapter; a generic URL-state framework is not introduced.

## Problem and proposed scope

The shell, page headings, table controls, dialogs, metric presentation and async sections use inconsistent markup/behavior. Users encounter cramped columns, unclear state, duplicated headings and inconsistent keyboard operation. The proposal extends the existing shell, classes and installed icons; it does not introduce another design system.

| UI contract | Concrete proposal | Required caller responsibility |
|---|---|---|
| AsyncSection / QueryState | One presentation contract for initial loading, populated, empty, filtered-empty, error + retry, refresh with data, and stale data with warning. Handle unavailable/permission states explicitly. | Feature supplies actual state, scope, retry and truthful empty copy. Independent widgets keep independent states; a parent does not hide partial failures. |
| PageHeader / RecordHeader | One route title, breadcrumb/back target, optional stable ID, labelled state/severity/freshness, primary action and secondary actions. One page H1 and one main landmark. | Feature supplies title and supported actions; shell owns workspace context. Avoid adding an H1 to every nested panel. |
| Dialog | Named native modal/dialog behavior: title, optional description, initial focus, focus containment, Escape/cancel, return focus and pending state. Adapt ConfirmDialog and custom overlays. | Feature owns whether cancellation is safe, validation and mutation outcome. A busy dialog must explain why close is unavailable when applicable. |
| MetricValue | Valid zero renders `0`; unknown/unavailable renders `—` with accessible explanation; pending renders a consistent placeholder. | Feature supplies availability separately from numeric value. MetricValue cannot infer that missing data means zero or validate the metric population. |
| DataTable | Honor minimum column widths; internal horizontal scroll. Add essential/default/optional display priority, stable row links, column chooser and keyboard reorder/resize alternatives. | Feature selects meaningful defaults and preserves supported selection/paging. Essential identity/action columns cannot all disappear. |
| Chart interaction | Textual values and legends remain available. Interactive bars/segments have a real button/link equivalent, visible focus and a clear active-filter/reset state. | Feature owns domain interpretation and supported filters. Decorative SVG remains noninteractive. |

These are proposed small reusable contracts, not imports that already exist. Implement only after checking existing components and representative consumers. A review/static-analysis rule should flag fallbacks that convert unavailable query data into success; do not prohibit all `?? 0`/`?? []` expressions. A fallback after validated successful data can be legitimate.

## Exact candidate visual specification

These are the selected values for the reference implementation, replacing the earlier ranges. They are proposed values, not claims about current CSS. Reuse existing tokens where present; any new token must be implemented in both themes after the scoped decision.

| Element | Width-driven layout / density | Coarse-pointer target overlay |
|---|---|---|
| Content gutter | 24px at ≥960px; 12px below 960px | Unchanged by pointer |
| Panel padding / panel gap | 16px / 16px | Unchanged |
| Route title | 22px, weight 600, line-height 28px | Unchanged |
| Section heading | 16px, weight 600, line-height 24px | Unchanged |
| Body / table body | 13px/20px; 14px/20px below 640px | Unchanged |
| Supporting copy | 12px/18px; essential instructions never 11px | Unchanged |
| Table density | Compact 36px minimum row pitch; comfortable 44px. Narrow fine-pointer layouts retain chosen density. | Interactive rows minimum 44px pitch |
| Primary / child navigation | 40px / 36px minimum row pitch | 44px target height |
| Standard control | 36px height | 44px target height |
| Navigation / KPI icon | 18px / 16px, consistent stroke | Same glyph inside larger target |
| Heat cell / row pitch | 32px / 40px with intentional scroll where needed | Interactive row pitch 44px |
| Radius | 8px controls; 12px panels | Unchanged |

### Breakpoints and input capabilities

Use the named project convention **640 / 768 / 960 / 1200px** for new/adopted layouts: 640 phone content, 768 table defaults, 960 sidebar/drawer, 1200 wide dashboard. Use mobile-first min-width rules so exact boundary behavior is unambiguous. Width 640–1199px intentionally has three Exposure KPI columns and a stacked grid/progress pair; ≥1200px has six KPIs and the pair side by side; <640px has two KPIs.

1200px already exists in current Exposure, Inventory and CVE styles. The correction is incremental consolidation, not claiming every threshold is newly introduced. When a page adopts U01–U06, migrate its owned responsive rules to this set and remove its superseded thresholds. Do not rewrite unrelated shared-family rules in that slice. Any temporarily retained off-set threshold is recorded with owner, affected selector/page and removal in that family's adoption item. Add an allowed-breakpoint check for new/adopted rules; existing untouched rules are an explicit diminishing exception inventory. Use shared documented breakpoint values with CSS literals in media queries; ordinary runtime CSS variables are not the breakpoint mechanism. No new CSS preprocessor is required.

Touch targets use **`@media (any-pointer: coarse)`**, covering touch tablets and mixed-input devices, independently from width. A narrow mouse window does not automatically get touch rows; a wide touch tablet does. Increase the hit area, not the icon or font. Do not allow overlapping hit boxes; enlarge interactive table/heatmap rows when necessary. A 44px comfortable density remains an explicit fine-pointer option rather than a synonym for a small viewport.

Page header anatomy: breadcrumb/context on the first line, title + identity + primary action on the next, then supporting freshness/scope. Compact shell top bar remains 52px minimum with workspace, theme and account controls. Long tenant names wrap/truncate with full accessible text; actions wrap into a labelled group without covering the title.

Severity colors retain the existing critical/high/medium/low semantics. Status retains explicit text labels and existing success/warning/error meaning. Unordered chart categories use a separate proposed palette:

| Category token | Light | Dark |
|---|---|---|
| `--dp-chart-1` | `#5b5bd6` | `#8b8cf8` |
| `--dp-chart-2` | `#2563eb` | `#60a5fa` |
| `--dp-chart-3` | `#0f766e` | `#2dd4bf` |
| `--dp-chart-4` | `#a21caf` | `#e879f9` |
| `--dp-chart-5` | `#475569` | `#94a3b8` |

These categorical colors do not replace severity or lifecycle status colors. Reference charts use tabular numbers and labels rather than relying on hue. Measure normal-size text against its actual composited background at ≥4.5:1 and meaningful graphical/control boundaries at ≥3:1 as project acceptance thresholds. Check light/dark panels, hover/selected states and adjoining series. Do not require every unrelated palette pair to have a numerical ratio; for adjacent distinctions that do not meet the threshold, add an adequate outline, spacing, pattern or direct label rather than silently accepting ambiguous color-only encoding. Record measured colors/ratios and any necessary palette adjustment in the slice evidence.

## Navigation options

**Decision recorded:** the user selected “Separate Intelligence (Recommended)” and “Six peer tabs (Recommended)” during implementation planning. Option B is the selected navigation; Option A below is retained as the considered alternative. The single-child Intelligence group is intentional. Workbench and repository detail/list routes highlight Vulnerability Repository; Campaign routes highlight Campaigns under Remediation. No speculative future Intelligence items are added.

The six original requests remain fixed: appropriate icons, Remediation and Assets headings, standalone Exposure, standalone Policies outside Assets, compact Exposure grid and improved widget placement.

| Option | Tenant navigation | Trade-off |
|---|---|---|
| A — retain reference grouping | Exposure; Remediation → Findings (expandable Vulnerability/AI Findings), Vulnerability Repository, Campaigns; Assets → Inventory, AI Inventory; standalone Policies; bottom utilities. | Closest to the supplied reference and smallest structural departure. Repository mixes intelligence with remediation, and Findings has an extra level. |
| B — selected | Exposure; Remediation → Vulnerability Findings, AI Findings, Campaigns; Intelligence → Vulnerability Repository; Assets → Inventory, AI Inventory; standalone Policies; bottom utilities. | Flatter Findings access and clearer repository purpose. Adds a heading and differs from the reference grouping; this trade-off was selected by the user. |

Non-clickable group headings organize destinations; route links navigate; sibling disclosure buttons expand a destination's children. Do not nest interactive controls. Omit empty groups after role/entitlement filtering. Platform navigation retains its own structure.

Policies keeps the existing AI policy scope and `ai.security` gate. Tenants without that entitlement continue not to see it. Expanding to general policies or changing access is outside this proposal (N11). Supporting copy can say “AI security controls” without undoing the requested standalone Policies label.

## Mobile support proposal

Define which tasks are practical on each viewport; do not silently remove supported actions.

| Tier | Proposed experience |
|---|---|
| Full phone priority | Search, filter, triage, record review, basic ownership/status actions and supported notification-draft preview/export; readable results ahead of secondary charts. |
| Responsive with alternate presentation | Matrices and graphs retain data via internal scrolling and an equivalent list/table. Complex configuration remains operable and receives a desktop-recommended notice if necessary. |
| Optional scope reduction | Read-only phone configuration or removal of write actions is **not selected**. It needs an explicit capability decision recorded under N11. |

Do not interpret “desktop recommended” as disabled. Verify controls, keyboard access and zoom even for two-dimensional content.

## Options, costs and consistency rollout

Alternative preserving the current pattern: fix labels, individual markup and spacing in each page using existing classes/components. This minimizes new abstractions but repeats state/dialog/header logic and leaves more opportunity for drift.

Recommended option: extend current reusable controls and add only small contracts proven in Findings list/detail. Benefits: predictable state/keyboard behavior, readable tables and fewer repeated defects. Costs: shared-consumer migration, responsive/visual regression coverage and feature-specific adapters. Maintain feature-specific selection, assessment and entitlement semantics. No replacement table library, styling system or state manager is proposed.

Affected UI: tenant/platform shell, Findings and AI Findings, all DataTable consumers, CVE workbench, inventory/BOM and AI details, campaigns, policy/governance, connectors/settings/admin, and auth/public dialogs or headers where applicable. Public marketing retains its own shell and palette; adopt accessible behavior without copying the tenant sidebar.

Preview reference:

```text
Workspace / Findings
Findings                         [primary supported action]
Scope • data freshness
[compact summary, collapsible]
[search] [filters] [active chips / Clear]
[selection + bulk actions, only where supported]
[readable essential columns ............ internal scroll]
[result count]                       [Previous] [Next]
```

Record reference: breadcrumb/back → human name + stable ID + state → primary next action → overview facts → feature tabs/evidence. Empty/error examples must appear beside the populated reference before acceptance.

## Verification, rollback and decision record

Implement the reference slice first; inspect 1440, 1280, 768 and 390px, both themes, keyboard, 200% zoom, long names, pending/failed/stale sources and dialogs. Verify default and restored column preferences and all visible role/entitlement combinations. The workbench then exercises the same controls in a more complex journey before family rollout. The [UI plan](UI_IMPLEMENTATION_PLAN.md) owns acceptance and evidence recording.

Use reversible component/shell and family-adoption commits. If a shared change regresses an untouched family, revert the relevant slice or repair the shared contract; do not maintain an indefinite page-specific fork. Frontend implementation owner owns any temporary adapter, limited to the active family and removed before that family's acceptance. Record any exception's owner/scope/removal condition explicitly. No production rollback or deployment occurs under this documentation work.

| Decision | Current status |
|---|---|
| UI-only feedback + separate non-UI ledger | User requested; applied to this documentation revision |
| Original six Exposure/shell requests | User-requested design direction retained |
| Navigation Option B | User selected Separate Intelligence. Implemented in Stage 2a (October 29, 2026) with standalone Fix Intelligence, per the user's Stage 2a task: `app/SidebarNav.tsx`, `navDestinationForPath`, lucide icons, link destinations and sibling disclosures. Integrated, not verified (screenshot comparison deferred) |
| Workbench six peer tabs | User selected six peer tabs; parent drafts, inactive-panel unmount and tab/task URLs specified in the plan |
| AsyncSection and MetricValue (U01, Stage 1a) | User approved October 29, 2026 (reason: one state contract to stop false healthy/empty UI; alternative per-page markup rejected; rollback: revert the component commit, no page adopts it before Stage 1b). Implemented in `components/AsyncSection.tsx` and `components/MetricValue.tsx` with `.async-section-notice`, `.metric-value` and `.ui2-sr-only` in `ui2/primitives.css`; recorded in the UI development standard. Page adoption pending Stage 1b |
| Shell-owned route header (PageHeader contract) and U03 shell values | Implemented in Stage 2a as directed by the user's Stage 2a task (single shell H1, pathname-keyed pre-paint registration, accessible drawer and account menu; 40/36px rows, 18px icons, 22px title, 24px gutter at ≥960px, 44px coarse-pointer targets, 36px icon controls). Recorded in the UI development standard. Retained exception: the drawer still switches at `max-width: 960px` in `app-base.css` (960px exactly is drawer, not the ≥960 sidebar convention); owner shell frontend, removal when the `app-base.css` 960 block is migrated to min-width rules |
| Remaining shared control/table contracts (DataTable, Dialog, Chart interaction, queue controls) | Implemented in Stage 2b (October 29, 2026) as directed by the user's instruction to execute the plan: `components/Dialog.tsx` (ConfirmDialog and the six campaign overlays adopted), DataTable preference v2/essential-optional priority/minimum widths with internal scroll/accessible chooser/keyboard reorder and resize, `ChartLegend` and button bars with `aria-pressed` and text summaries, `QueueControls.tsx`. Recorded in the UI development standard. Integrated, not verified (screenshot comparison deferred); page adoption beyond the listed consumers follows the family stages |
| Mobile read-only restriction | Not selected; retain supported capabilities |
| New chart tokens | Candidate specification only; contextual contrast evidence pending |

Record the user's implementation decision and exact scope here before implementing a departure. Update the canonical standard together with the accepted shared implementation; do not represent a proposed component as an available API.

## Table preference compatibility specification

Existing DataTable writes visibility on mount, so presence of `:hidden` is not evidence of user interaction. Keep existing `storageKey`, `:order` and `:hidden` keys readable. Add `${storageKey}:preferences:v2` containing `version: 2`, `visibilityOverrides` per column and provenance `user` or `legacy-snapshot`. Write new overrides only when the user toggles a column; viewport/default computation must not write preferences.

If v2 is absent and a legacy visibility snapshot exists, import the known columns conservatively as legacy overrides: preserve both visible and hidden choices instead of guessing which were intentional. New columns without overrides receive current defaults. If no stored preference exists, essential/default columns start visible; optional columns follow `defaultHidden` and narrow defaults. Below 768px, optional columns without an override are hidden. Explicit overrides win over responsive defaults. Essential identity/action columns are always shown, with a disabled chooser checkbox and explanation; a legacy request to hide one is retained in provenance but cannot remove the required identity/action from the rendered table.

A user toggle updates only that column's override. Returning a column to a responsive/default state removes its override through a labelled “Use default” action. Keep existing order/width preferences, clamp old undersized widths for rendering and never persist viewport-generated widths. **Reset columns clears widths, order, hidden snapshot and v2 overrides**, then recomputes current defaults. It does not clear search, filters, selection, theme or other feature settings.

The chooser is a labelled popover with real checkboxes and Escape/focus return, not a menu role wrapped around non-menu children. Provide labelled keyboard Move left/right actions and focusable resizing with 8px arrow steps and the declared minimum. Preserve existing mouse/touch controls.

## Modal confirmation and header migration specification

There is one native modal. A dirty form's discard prompt **replaces that modal's content in place** with Stay/Discard and Save only if supported. Keep the form draft mounted in its owner; do not open a second confirmation dialog. Stay restores the form and previous field focus. A page-level guard opens the same confirmation shell only when no form modal is open. Pending non-cancellable writes block dismissal with a visible busy explanation.

The shell is the sole authenticated route-header/H1 owner; pages register content, not another H1. Until adopted, a page receives the existing route fallback title. Remove duplicate feature headings and nested main landmarks atomically with the shared header slice. Header registration is route-keyed and applied before paint; stale registrations cannot render another record's title. Loading and route-error states use the same owner. Public/auth pages retain one main and one H1 in their separate shell. Extend the sweep to assert one visible H1/main for adopted routes, capture legacy failures separately and prohibit new duplicates. Final adoption requires the assertion across every supported route. Add transition/loading tests, since a settled sweep alone will not catch title flashes.

## Navigation rollback and evidence scope

Implement the regrouping in a reversible shell slice; no feature-flag framework is added. If active-state/access/navigation regressions appear, revert the shell slice and its paired expected snapshots/tests together, leaving independent state fixes intact; rerun representative navigation/access checks. Restore the immediately preceding verified shell artifact only through the existing release process if already deployed. Do not add an unqualified runtime rollback toggle.

Affected evidence includes AppShell navigation/access tests, active-route and route-helper tests, route sweep's disclosure/link locators, all six family journeys' sidebar expectations, current authenticated light/dark desktop/mobile baselines and header/structure assertions. New links/disclosures require updating the sweep's current button-centric assumptions. Public/auth screenshots change only for actual shared-boundary or header effects, not automatically. Snapshot refresh and review follow the bounded per-slice procedure in the UI plan.
