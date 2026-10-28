# Application-wide UI elements and interaction review

Updated October 28, 2026 after feedback. The filename is retained for existing references. Scope is now **UI elements and interactions only**: navigation, hierarchy, layout, icons, controls, labels, responsive presentation, accessibility and visible feedback. Architecture, API/data definitions, persistence, scalability and instrumentation have moved to the [non-UI ledger](NON_UI_IMPROVEMENTS_LEDGER.md).

## Overall assessment

Scout has substantial workflow depth and a shared visual foundation. The UI needs clearer page hierarchy and consistent controls: readable tables, recognizable navigation, understandable progress, accurate labels, useful error/empty states, and an obvious next action. Improve those shared elements first, then apply them to each page while retaining domain-specific interactions.

Read the [ranked UI plan](UI_IMPLEMENTATION_PLAN.md) for execution order, the [shared UI proposal](SHARED_UI_PROPOSAL.md) for exact candidate values and choices, the [page register](application-page-review-register-2026-10-28.md) for coverage, the [Exposure review](exposure-shell-review-2026-10-28.md) for the supplied dashboard reference, and the [Workbench journey](CVE_WORKBENCH_UI_JOURNEY.md) for step transitions. The register is an adoption checklist; it is not a separate P1 ticket for every repeated shared-control defect.

## Evidence and limits

The initial review mapped 58 page/feature-page modules through structural indexing and targeted source inspection, all 35 saved light desktop compositions, 12 representative saved mobile and six dark compositions, plus the supplied references. This is not an exhaustive line-by-line review or a current live walkthrough. Contact sheets support composition findings, not precise current contrast or hit-target measurements. Saved screenshots predate some theme fixes.

**C** = source-confirmed UI observation; **V** = saved fixture visual evidence; **R** = proposed design; **Q** = current interaction qualification required. Source was selectively rechecked at `eedc8a08` plus the existing uncommitted checkout. Browser/visual/axe and live persistence evidence remains pending. The documentation revision changes no application code.

P0 identifies a broken visible path or misleading UI state. P1 identifies interaction/accessibility work. P2 identifies layout/polish. Exact rank, qualitative reach, effort, owner and acceptance belong to the UI plan. The earlier A01–A18 findings are preserved through the traceability table in the separate ledger rather than mixed into UI feedback.

## UI findings

| UI element | Feedback and improvement | Root / adoption |
|---|---|---|
| Shell navigation | Missing icons and headings make the flat list difficult to scan. Restore Remediation/Assets, standalone Exposure and standalone Policies. Use sibling navigation/disclosure controls and correct active/expanded state. Compare the repository grouping alternatives without treating an optional change as already selected. C/V/R | U03 |
| Page and record headers | Title, breadcrumb, ID, status, freshness and actions vary across families; some nested content repeats H1/main. Use one clear route header and a consistent record identity/next-action pattern. C/V/R | U03 |
| Loading, errors and empty states | Pending/failed sections can look empty or healthy. Use explicit unavailable/retry, valid zero, true empty, filtered-empty, stale-with-data and partial-section feedback. Do not hide useful populated sections because a secondary request failed. C/R | U01 |
| Metric cards | Add appropriate icon + label, readable value and short explanatory caption. Use unavailable presentation separately from zero and label risk, severity, finding and CVE populations precisely. Underlying definitions are N03, not a cosmetic task. C/V/R | U01/U11 |
| Tables and column controls | Minimum-readable columns and intentional internal scrolling are preferable to squeezed words. Essential/default/optional display priorities, usable column chooser and keyboard alternatives need a shared treatment. Preserve each page's supported selection model. C/V/R | U02 |
| Queue controls | Search, filters, active chips, clear, result count, selection count and paging should appear in a predictable place. State whether a number covers all matching records or the current page. Show filtered-no-results recovery. C/V/R | U06 |
| Dialogs and overlays | Use a named dialog, logical initial focus, containment, Escape/cancel, focus return and understandable busy/error state. Keep feature-specific cancellation behavior. C/R | U04 |
| Charts and row actions | Pointer-only actions need native link/button equivalents, contextual names and visible focus. Chart values/meaning must remain available without hover or color. C/R | U05 |
| Detail-entry and Back UI | Finding direct entry needs an understandable loading/error/missing/denied view and usable return path. EOL actions must not visibly loop. Supported record/destination contracts are separately N01/N02. C/V/Q | U07/U08 |
| Forms and action feedback | Consistent labels/help, validation, dirty/cancel cues, retained input and explicit action outcome. Do not show success merely because a dialog closed or a refetch started. Underlying write/readback behavior is N04/N12. C/R | U01/U06 + family adoption |
| Narrow layouts | Large chart stacks delay the working queue; matrices and dense lists need readable scroll/list alternatives. Prioritize identity, search, triage and next action. Do not silently disable existing phone actions. V/R/Q | U02/U09–U16 |
| Workbench progress | Six reference destinations are currently spread across tabs, numbered steps and a canvas. Clarify current location, partial/saved/draft work and Save versus Continue. Notify Groups currently exports drafts, not email. C/V/R/Q | U10 |
| Color, icons and type | Use the installed icon library, exact reference type/spacing/density values and a categorical chart palette distinct from severity meaning. Keep full accessible text for truncated identifiers. C/V/R | U03/U05/U11 |

## Visual and navigation decisions

The [proposal](SHARED_UI_PROPOSAL.md) specifies 24px desktop/12px phone gutters, 16px panel padding/gaps, 22px route titles, 16px section headings, 13px desktop/14px phone body text, 36px compact/44px comfortable rows and consistent 18px navigation icons. These replace preliminary ranges; they are proposed reference values and require current contextual validation.

The user selected Option B: flat Vulnerability/AI Findings under Remediation and a separate Intelligence group containing Vulnerability Repository. Six peer Workbench tabs were also selected. Option A remains only the considered alternative. Both retain the six original user requests. Policies remains the existing AI policy capability and entitlement; broader policy scope is not implied by the label.

Phone support prioritizes search, triage and review. Matrices/graphs have equivalent reading/scrolling paths; complex forms remain operable unless a separate capability decision is made. Public marketing keeps its own palette/shell while reusing accessible interaction behavior.

## Evidence before closure

The retained axe baseline has 939 repeated route/theme/viewport/node records across 35 route names, not 939 unique current defects. Source independently confirms several shared markup/control issues; reproduce them against the new candidate. Run the current sweep, affected visual/axe and relevant journeys, then inspect keyboard, zoom, dialogs and workbench transitions. Passing a historical comparison does not certify zero accessibility defects.

Findings list/detail is the reference slice. The full CVE Workbench journey follows before broader family adoption, with parent-owned drafts, inactive panels unmounted, tab/task URLs and N07a-backed route/Back guards. Width and coarse-pointer target sizing are independent; use the updated bounded test matrix and per-slice snapshot approval procedure. Each page closes only after its own controls, states, content lengths and access combinations are verified. Scope decisions, precise work order, local acceptance measurement and rollback are in the linked plan/proposal. No production analytics, backend redesign or deployment is included in this UI review.
