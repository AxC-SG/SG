# UI implementation plan and adoption ledger

Updated October 28, 2026. Scope: visible elements, navigation behavior, layout, labels, feedback, keyboard accessibility and responsive presentation. Non-UI implementation work is independently ranked in the [non-UI ledger](NON_UI_IMPROVEMENTS_LEDGER.md). No application changes or test passes are recorded by this documentation revision.

## Locked decisions and scope

The user selected **Separate Intelligence** and **six peer Workbench tabs** during planning. Remediation contains Vulnerability Findings, AI Findings and Campaigns; Intelligence contains Vulnerability Repository; Assets contains Inventory and AI Inventory; Exposure and Policies are standalone. The Workbench highlights Vulnerability Repository. A single-item Intelligence group is deliberate; do not invent future links. Policies retains `ai.security`.

Use parent-owned Workbench drafts with inactive panels unmounted; validated `tab`/`task` query parameters; full exit protection through the separately tracked N07a router prerequisite; and in-place discard confirmation inside an existing dialog. Width and input capability are independent. The detailed contracts below supersede earlier ambiguous descriptions. These are plan decisions, not completed application changes.

Backend/metric/identifier/persistence work stays in the non-UI ledger. The finding API already accepts UUIDs, whereas some UI links use display IDs; N01 owns that compatibility gap. No API changes, general policy entitlement, runtime evidence, fifth matrix row, real email delivery or new feature-flag/telemetry system is included here.

## Priority, status and ownership

The staged sequence below is the execution authority. Stable U IDs in the ownership table preserve cross-document traceability; table row order is not a second schedule. P0 = user-facing broken path or misleading state; P1 = interaction/accessibility defect; P2 = layout/polish. These are delivery priorities, not security ratings. Reach is qualitative; it is not a measured user count. Effort S/M/L is an initial implementation-size estimate, excluding backend dependencies and qualification, not a schedule commitment. Owner denotes responsibility to assign, not an invented named assignee.

Track a shared fix once under U01–U06, then each consumer as an adoption check. A component landing does not resolve a page automatically. Every page progresses through **not started → integrated → verified** with evidence; recommendations are not tickets until current reproduction/scope is recorded.

| Tracking item | Priority / reach / effort | Concrete UI deliverable | Dependencies | Owner / status |
|---|---|---|---|---|
| <a id="U07"></a>U07 | P0 · finding entry points · M | Finding detail has loading, unavailable/denied/missing states, usable Back, and a successful direct-entry view. | N01 for authoritative lookup; does not depend on restyling | Findings frontend / candidate, source confirmed |
| <a id="U08"></a>U08 | P0 · Exposure EOL actions · S | EOL action leads to a meaningful supported lifecycle view or explains unavailability; no self-loop. | N02 destination contract | Exposure frontend / candidate, source confirmed |
| <a id="U01"></a>U01 | P0 · multiple data screens · M | Explicit loading/error/retry/filtered-empty/stale UI and unavailable metric display, starting with Exposure, AI action queue and declared resources. | Existing query states; N03/N12 only where source semantics are missing | UI platform + consuming feature / proposed |
| <a id="U02"></a>U02 | P1 · all table consumers · M | Readable minimum widths, essential/default/optional columns, internal scroll and keyboard column controls. | Shared proposal; explicit-override and legacy preference rules below | UI platform / proposed |
| <a id="U03"></a>U03 | P1 · every authenticated page · M | Grouped shell/icons, standalone Exposure/Policies, sibling disclosures, consistent page/record header, one H1/main. | Selected Intelligence grouping; shared proposal; N07a only for complete exit guards | Shell frontend + UI designer / proposed |
| <a id="U04"></a>U04 | P1 · dialogs/menus · M | Named modal, initial/return focus, containment, Escape, cancellation and busy feedback; consolidate ConfirmDialog and campaign overlays. | Shared proposal; preserve feature-specific cancel behavior | UI platform / proposed |
| <a id="U05"></a>U05 | P1 · charts and rows · M | Real links/buttons for actions, textual chart values, focus/active-filter/reset behavior. | U02/U03 where relevant; no new business actions | Feature frontend / proposed |
| <a id="U06"></a>U06 | P1 · queue/detail controls · M | Consistent active filter chips, result/page/selection labels, paging controls and Back/dirty-state presentation. | Scoped tab/task adapter; N07a for route/Back guards; N05 for missing server paging | Feature frontend / proposed |
| <a id="U09"></a>U09 | P1 · reference slice · M | Findings list/detail demonstrate U01–U06 with populated, empty, error, denied and narrow views. | U07 and accepted shared proposal; integrate roots incrementally | Findings frontend + designer / not started |
| <a id="U10"></a>U10 | P1 · analyst core journey · L | Workbench's six visible destinations and runbook transitions, saved/draft cues, eligibility, action results and notification-draft export. | U09 reference; U01/U04/U06; N07a exit-guard prerequisite; N01/N03/N04/N12 where needed | CVE frontend + designer / review specified, not verified |
| <a id="U11"></a>U11 | P2 layout; P0 labels/states · M | Exposure KPI icons, exact labels, compact grid/remediation pair, action panels next, consistent headers; current numeric score with explanation; no ring in this scope. | U01–U03; N03 semantics and N10 only for optional AI row | Exposure frontend + designer / not started |
| <a id="U12"></a>U12 | P1 · inventory/BOM/AI · L | Apply headers, readable lists, coverage/empty/error feedback, relationship alternative and record actions. | U09/U10 acceptance; N05 scale work independently owned | Inventory frontend / not started |
| <a id="U13"></a>U13 | P1 · campaigns · M | Wizard/selection/summary, lifecycle action hierarchy, readable progress, notification preview/result and common dialogs. | U04/U06; N04/N12 for authoritative outcomes | Campaign frontend / not started |
| <a id="U14"></a>U14 | P1 · policy/config UI · L | Scope/parameter/exception forms, dirty/save cues, rule summaries and readable lifecycle/tenant cohort controls. | U01/U03/U04/U06; N03/N04/N11 for domain decisions | Governance frontend / not started |
| <a id="U15"></a>U15 | P1 · connectors/admin/platform · L | Consistent catalog/detail forms, validation, status/result feedback, run details, invite and account dialogs. | Shared roots; N04/N12 where API outcome is incomplete | Connect/admin frontend / not started |
| <a id="U16"></a>U16 | P1 auth; P2 marketing · M | Labelled login/setup/invite/request states and actionable recovery; readable public pages and CTA hierarchy. | Reuse behavior without tenant-shell duplication; N11 capability decisions | Auth/public frontend / not started |

Stage 1a introduces AsyncSection and MetricValue before Stage 1b adopts them, avoiding throwaway page implementations. U07/U08 repairs remain independent of the wider visual redesign once their contracts are available. Do not delay a currently reproducible production defect for a whole-app refresh; an exceptional emergency patch is explicitly re-adopted under U01 rather than treated as the long-term reference.

## Detailed sequence and effort

Effort bands are initial focused **person-days including implementation and slice verification**, not calendar promises or measured estimates. They exclude non-UI dependency work, deployment and time waiting for decisions/environments. Frontend lead re-estimates after Stage 0, preserving the order and scope. A developer owns code and automated evidence; a designer reviews composition; QA owns cross-flow/manual verification. No named assignee or delivery date is invented.

| Stage | Work and owner | Initial effort | Exit / dependencies |
|---|---|---|---|
| 0 | Current evidence and completed-work reconciliation; frontend lead + QA | 1–2 days | Current routes/states reproduced, active tooling inputs confirmed, historical-only findings removed from active work. |
| 1a | U01 AsyncSection + MetricValue, scoped styles and behavioral tests; UI frontend | 2–3 days | Loading, ready, empty, filtered-empty, unavailable/error/retry and cached-refresh-failure contract works before page adoption. |
| 1b | Adopt U01 in Exposure, AI action queue and declared resources; truthful mutation feedback; U07/U08 UI states | 2–4 days | No false healthy/empty UI. Successful finding/EOL paths separately depend on N01/N02; visible fallback is not recorded as successful resolution. |
| 2a | U03 shell, exact visual defaults, single header owner and selected navigation; frontend + designer | 3–5 days | Allowed links reachable, correct active destination, accessible drawer/account menu and stable header across current routes. |
| 2b | U02/U04/U05/U06 table, dialog, chart and queue controls; UI frontend | 5–8 days | Preference compatibility, keyboard controls, one-modal confirmation and active-filter/result-scope behavior verified. |
| 3 | U09 Findings list/detail reference; feature frontend + designer/QA | 3–5 days | Reference states, custom selection/queues, direct-entry UI and narrow layout accepted before family propagation. |
| 4 | U10 Workbench UI and J01–J18; CVE frontend + designer/QA | 8–12 days | Six tabs, parent drafts, URL history, all exit guards and exact draft export verified. N07a must land before complete guard acceptance. |
| 5 | U11 Exposure page layout; Exposure frontend + designer | 3–5 days | Compact grid/progress pair, intentional KPI/tablet layout, actionable lower panels and precise state/label presentation. |
| 6a | U12 infrastructure/software/BOM/AI inventory adoption | 5–8 days | Readable tables/details/coverage and graph list alternative; backend scale changes remain N05. |
| 6b | U13 campaigns adoption | 3–5 days | Wizard, lifecycle actions, selection/progress and notification UI verified. |
| 6c | U14 policies + seven configuration sections | 5–8 days | Dirty/save/validation, rule/scope controls and lifecycle UI verified without domain changes. |
| 6d | U15 connectors, administration and platform | 6–10 days | Catalog/detail/run/status feedback, management controls and dialogs verified. |
| 6e | U16 public/auth residual work only | 0.5–3 days | Do not redo recent theme/header fixes; close reproduced residual gaps and prove no regression. |

### Stage 0 — current inputs, not retired migration evidence

Use current `frontend/e2e/` fixtures, routes, journeys, visual/axe baselines, package scripts and `.github/workflows/`. Source inspection confirmed that candidate build/sweep does not require deleted `BEHAVIOR_BASELINE_2026-10-24.json`, `VERIFICATION_RESULTS_2026-10-24.md` or removed intermediate checkpoint reports. Archive integrity checking is separate and uses retained archives/manifests; do not delete those or reintroduce obsolete reports.

Record existing public/auth fixes from commits `2f5abf42`, `6bb3376e`, `26c3bc26`, `1faab124` and `eedc8a08` as **implemented historically; current regression qualification pending**. Reproduce remaining gaps before adding work. Implementation already present is not scheduled again, and historical evidence is not a new candidate pass.

### Stages 1–3 — shared reference contracts

AsyncSection is presentation-only with explicit state and feature-provided retry/empty copy. MetricValue receives availability independently from value; valid zero stays zero. Keep populated sections visible when another dependency fails. Do not globally prohibit all `?? 0` or `?? []` expressions.

Header ownership is atomic: the shell renders one shared H1 using route-scoped header data; feature pages register title/actions without rendering another H1. Unadopted routes retain the shell fallback. Remove duplicate feature H1s in the same shell slice, including nested InventoryShell/Copilot landmarks. Match registrations to pathname/record identity and clear mismatched registrations immediately; use a pre-paint layout registration so navigation cannot briefly reuse the previous record title. Auth/public routes continue to own a single header/main in their own shell. Suspense/error states use the same route header owner.

Findings list keeps its existing selection/saved-queue semantics; do not mechanically replace the bespoke table if that would drop behavior. Adopt the same readable widths, keyboard links, control hierarchy and state conventions. Finding detail uses contextual loading/missing/denied/error presentation until supported identifier lookup is resolved under N01.

### Stage 4 — Workbench state, location and exit behavior

Use the six user-selected peer tabs: Overview, Investigation, Applicability, Impacted Assets, Fixes and Notify Groups. Keep one CVE header; highlight Vulnerability Repository under Intelligence. Investigation contains the existing five task IDs/labels, including Summary Report for the internal `installed-patch-info` ID.

Lift editable form state into one **CVE-keyed parent-owned draft model** before switching navigation. It holds investigation criteria/results/notes/tasks, applicability/impact/rationale, finding configuration, editable fix guidance and notification composition/selection. Track per-section baseline/dirty state. Panels receive controlled values/callbacks and **unmount when inactive**. Query/cache state stays in existing feature queries, not in the draft reducer. Gate panel fetches/effects by active tab/task; allow only existing shared summary/pending-job polling to remain active. Responses for a different CVE or an obsolete request must not overwrite current drafts; handle underlying cancellation lifecycle under N06 if an existing helper cannot supply it.

An initial response seeds an unedited section once. Refetches may refresh read-only facts but do not overwrite dirty fields. Clear only the relevant dirty section after the existing authoritative save succeeds. A multi-operation partial failure remains dirty with explicit feedback; do not redesign transaction/retry semantics here. State survives unmount/remount and tab switches; navigating to another CVE first goes through the guard, then creates that record's independent draft model. No cross-session draft persistence is added.

The scoped UI adapter accepts `tab=overview|investigation|applicability|assets|fixes|notify` and `task=review-asset-inventory|find-false-positive|end-of-life-analysis|solutions|installed-patch-info`. Missing/invalid tab resolves to Overview; missing/invalid task in Investigation resolves to the first task. Remove task when leaving Investigation. Preserve unrelated parameters. Use history **push** for deliberate tab/task changes and **replace** for canonicalizing invalid/default parameters. Browser Back restores the previous valid view. Links and refresh restore location, never unsaved draft contents.

Dirty tab/task changes, record changes, sidebar/row links and browser Back/Forward use the same guarded transition. Stay retains the current view/draft; Save is offered only for sections with an existing save operation and continues only after success; Discard resets affected fields to the known baseline and then proceeds. Notification drafts expose Stay/Discard, not a fake server Save. A notification export never claims server persistence or delivery. Use a single pending navigation target while confirmation is open. For multiple dirty sections, enumerate them and save only through supported operations; a failed section blocks the transition.

`beforeunload` is attached only while dirty for reload/close/external document exits; it uses the browser's native confirmation and cannot promise custom text or asynchronous Save. Internal navigation uses router blocking after **N07a**. Do not claim complete exit protection while N07a is open. No history monkey-patching, private router context hacks or manual popstate reversal.

### Stage 5 — Exposure page layout

At width **1200px and above**, show six KPIs and a 7:5 Grid Exposure/Remediation pair. At **640–1199px**, show three KPI columns and stack that pair; this intentionally includes tablet portrait. Below **640px**, show two KPI columns. Keep cards at 112px minimum height and let captions wrap. Below the pair place critical CVEs/attention, then software/assets, then the funnel. Keep one attention list rather than adding a duplicate strip.

Keep four supported grid domains. Retain the current score as text with explanation; no ring or formula change. A coherent 100% remediation chart depends on N03; use labelled existing rows with an accurate scope/unavailable explanation until that contract is resolved. Do not invent totals, trends or a new AI row.

## Acceptance and no-double-counting rule

| Shared item | Required reference acceptance | Consumer closure rule |
|---|---|---|
| U01 | Pending, first-load error, retry, valid zero, successful empty, filtered-empty, cached data + refresh failure, and independent secondary failure. | Page references the same root; verifies its actual empty copy, retry action and partial dependencies. Never “resolved by component” without integration evidence. |
| U02 | Long identifiers and maximum default columns at 1280/390px; readable minimum widths; intentional scroll; keyboard chooser/reorder/resize; restore preferences. | Each table's essential columns, selection/paging and storage key remain correct. |
| U03 | Tenant/platform, AI entitlement on/off, expanded nav, direct record entry, long tenant names, menu keyboard and phone drawer. | One route title/main, correct active destination and reachable allowed actions. |
| U04 | Named dialog, focus entry/trap/return, Escape/backdrop, validation, pending save, server failure and repeated open/close. | Each feature specifies safe close/cancel and retains input on recoverable failure. |
| U05 | Every visible action works by keyboard; chart meaning available without hover/color; real row links support new tab. | Verify the destination/filter meaning and preserve domain selection conventions. |
| U06 | Clear filters, result scope, all/page selection, next/previous, no-results recovery, Back and dirty-save/discard. | Only supported state persistence is asserted; feature URL contract belongs to N07. |

The [page register](application-page-review-register-2026-10-28.md) maps every module/subview to these roots and a family adoption item. Create root tasks and adoption subtasks, not a fresh shared-control defect for each page. New UI findings discovered during qualification attach to the relevant root or get a new explicit item.

## Current evidence gate

Source recheck on October 28 (documentation only; no new runs): `HEAD eedc8a08` plus the existing uncommitted checkout. Confirmed finding router-state dependency, EOL redirect, table width shrinking, dialog naming gap, inconsistent query/action feedback and workbench draft-only notification behavior. This is not an immutable tested artifact. At implementation, record the exact candidate commit, relevant working-tree diff or content hashes, fixture version and environment.

Fresh browser evidence remains **pending**. The UI implementation owner must:

1. Build current fixture artifacts with `npm run e2e:build` from `prototype-app/frontend`.
2. At baseline and final shared release candidate, run `npm run e2e:sweep -- --widths 390,768,1280,1440`; it includes route checks in both themes and representative axe audit/comparison. Per-slice testing uses the bounded matrix below, not a full route × role × state Cartesian product.
3. Run affected visual checks and relevant family journeys in the repository's required pinned Playwright environment; inspect changed images. Add successful finding-detail and setup fixtures instead of accepting fallback-only pictures.
4. Reproduce each candidate UI defect and record route, role/entitlement, state, viewport/theme, expected/actual and evidence path. Reclassify already-fixed items, including recent public/auth fixes; do not create tickets from stale screenshots alone.
5. Add keyboard, zoom and workbench transition checks missing from the representative sweep. Any live write/persistence verification belongs to separately identified disposable test data and the non-UI dependencies.

Use the [canonical browser instructions](../../../docs/ui2-styles-and-rollback.md#browser-gates). Do not fake the Playwright image environment, loosen assertions/tolerances, or update baselines just to remove failures. A pass against known axe/journey baselines is a regression comparison, not zero defects. If an environment check cannot run, record the missing prerequisite and leave that evidence pending.

## Bounded verification matrix

Do not multiply 58 modules by every width, theme, state and role. State truth is tested once per shared contract, then verified through representative feature integration. Extend existing fixtures/journeys rather than duplicating all assertions. All checks below are future acceptance, not passes recorded by this update.

| Tier | Automated minimum | Manual minimum / trigger |
|---|---|---|
| Shared component | Unit/RTL tests for every supported state and action; chooser preference migration/reset, dialog focus/cancel/busy and chart keyboard behavior. | One keyboard/screen-reader check per shared contract at reference acceptance. |
| Ordinary family slice | Existing affected visual + axe routes at 1280/390px, both themes; related family journey; one representative empty/filter-empty/error/stale/failed-mutation case per relevant feature. | Designer reviews changed route images; QA runs one 390px and one desktop critical task, 200% zoom and the changed dialogs. |
| Findings and Workbench reference | Populated reference routes/tabs at 1440/1280/768/390px, both themes. Critical state/transition suite at 1280 light and 390 dark, rather than every state at all eight combinations. J01–J18 cover workbench behavior. | Keyboard/focus and screen-reader names; zoom and long-content review. Repeat at another width/theme only for a layout- or contrast-dependent failure. |
| Access/navigation | One default-width functional assertion for tenant admin, analyst, inventory admin, read-only auditor and platform scope; AI on/off; route/active group and enforced redirects. | Keyboard drawer/account check on reference slice. Do not snapshot every role in every state. |
| Global shell/token/router slice | Current representative authenticated visual/axe route set in both themes at 1280/390; all-route smoke for links, errors, overflow and header structure. | Review all changed shared-shell images; targeted role/drawer/history/public-boundary checks. |
| Baseline/final candidate | Full route sweep 390/768/1280/1440 in both themes, existing six family journeys and quality/build/coverage checks; final one-visible-H1/main on all supported routes. | Residual blockers explicitly recorded; final cross-family tasks and accepted accessibility evidence. |

At each changed breakpoint, add reference-page smoke at **639/640, 767/768, 959/960 and 1199/1200px** for the affected layout only. These are layout assertions, not a new full screenshot matrix. Add wide coarse-pointer tablet and narrow fine-pointer desktop cases to distinguish targets from density. Tests capture both effective media-query match and target dimensions.

Introduce header assertions on adopted routes immediately; retain baseline-only diagnostics for untouched failures until migration, with no new duplicate headings permitted. At final adoption require exactly one visible route H1 and main across the supported route set. Add explicit lazy-loading, record-to-record and route-transition tests to catch title flashes that a settled sweep misses.

### Concrete visual acceptance

- Essential KPI captions and button/field labels wrap without ellipsis or clipping at 390px. Titles/actions do not overlap at 390/768px. Identifiers may truncate only when full text is accessible and copyable.
- Table cells meet declared minimum widths; numeric heat cells meet the selected dimensions; document width does not overflow from a table/graph. Its labelled internal region scrolls by keyboard/touch.
- Coarse-pointer controls have at least 44px target dimensions where specified; no overlapping click regions. Fine-pointer compact rows stay at the chosen compact density regardless of narrow width.
- Normal-size text achieves ≥4.5:1 against the actual composited background; meaningful graphical/control boundaries achieve ≥3:1. Check dark/light, selected and hover states. For touching chart categories, use adequate separation/outline/pattern/direct labels when color-only distinction is insufficient; record the chosen solution, not an unqualified assertion that five colors are accessible.
- Exposure positions and column counts match Stage 5 at exact boundary widths; lower short cards have no artificial fixed-height empty area.
- Current tab, selected filter, enabled/disabled action and task state have programmatically available names/state and visible focus; none depend solely on color or hover.

### Snapshot change and approval procedure

1. Build and compare the current slice against existing baselines in the required pinned environment; retain before/after/diff artifacts. Record the slice commit/diff and selected route list.
2. The feature developer explains every changed layout/control/state. The designated UI reviewer checks the affected images; QA checks functional/keyboard expectations. Record actual reviewer identity/date/result at review time, not an invented approval now.
3. Refresh **only the expected visual snapshots for the slice**, using the visual spec's existing E2E_ROUTES/E2E_WIDTHS filters and Playwright's targeted update-snapshots after the image prerequisite check. Preserve a human-approved route/diff manifest. A shell/token change legitimately refreshes all affected authenticated routes together; it does not automatically refresh unrelated public pages.
4. Do not use blanket `e2e:update` for a layout-only slice: the current command also rewrites journey and axe baselines. Update those independently only for reviewed behavior/known-finding changes, retaining all assertions and thresholds.
5. Rerun comparisons and attach results plus reviewer record. Unexpected image or behavior changes are fixed or explicitly explained before acceptance. Baseline refresh never closes a non-UI dependency.

### Navigation-specific regression and rollback

Update AppShell/access/active-route tests, typed route-helper expectations, sidebar disclosure/link locators in route sweep, and any of the six family journeys using navigation labels. Refresh the current authenticated shell/header light/dark desktop/mobile baselines as one reviewed slice. Assert that all Workbench tabs, CVE/assets/software/intelligence detail routes select Vulnerability Repository, while campaign routes select Campaigns.

Do not add a feature-flag system. Keep the shell and router changes as separately reversible slices. If navigation/access/active state regresses, revert the responsible slice and its paired tests/snapshots, retain independent state fixes, then rerun the access/navigation/public-boundary smoke set. Deployment/production artifact rollback remains the existing release process and is not executed by this plan.

## Measurement plan

These are local acceptance measurements, not promises of production analytics. No new tracking is installed by this plan.

| Outcome | Method / owner | Acceptance |
|---|---|---|
| Reach a detail without router state | Fixture navigation + fresh context/new tab/direct URL / feature QA | All supported detail-entry scenarios resolve or show a correct denied/missing/error state. |
| Avoid false clean/zero UI | Rejected/pending/partial response fixtures / feature frontend | No unavailable dependency is represented as a successful empty/healthy result. |
| Reach supported records | Fixture dataset over page-size boundary, next/previous and filters / feature QA | Every permitted result reachable; count/scope labels accurate. |
| Read and operate the UI | Screenshot inspection, keyboard, zoom, long-content scenarios / UI QA | Essential identity/actions remain readable/reachable; no accidental document overflow. |
| Time to first meaningful action | Moderated repeatable task with the same fixture dataset before/after / designer | Record baseline and post-change observations and errors before setting a numeric target. Do not infer improvement from fewer pixels. |
| Preserve context and drafts | Back/tab/refresh and save/failure scenarios / feature QA | Verified state matches the declared feature contract; local draft is never labelled server-saved. |

Record results under each item: candidate, scenario, evidence, result, owner and date. Performance instrumentation, payload/request budgets and production telemetry are N05/N09, not additions hidden inside UI acceptance.

## Execution boundaries

Do the Findings reference before broad adoption, then the complete Workbench journey before treating shared patterns as proven for complex workflows. Follow the selected contracts and bounded matrix above; do not fall back to leaving panels mounted or treating any legacy visibility map as a new user toggle. Apply accepted exact visual values consistently; standard changes land with the implementation decision and real reference evidence. Roll out reversible family slices. No non-UI ledger item is automatically authorized for implementation by a UI item depending on it.
