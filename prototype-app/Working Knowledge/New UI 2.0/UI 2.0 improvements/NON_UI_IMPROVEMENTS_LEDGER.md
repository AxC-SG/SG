# Non-UI improvements ledger

Updated October 28, 2026. This ledger separates architecture, API/data/domain correctness, persistence, scalability and instrumentation from the UI-elements feedback, as requested. It preserves the non-UI findings from the earlier reviews without treating them as UI implementation tasks.

Status of all implementation items: **candidate / not implemented under this task**. Source observations were rechecked selectively; a current browser/backend reproduction and scope agreement are required before closure or ticketing. P0/P1/P2 are delivery priorities, not security severity. Owner is the role to assign; effort S/M/L is indicative and excludes qualification. Cross-links identify dependencies, not duplicate tasks.

## Ranked independent backlog

| Rank / ID | Priority / effort | Non-UI improvement and source evidence | Dependency / acceptance / owner |
|---|---|---|---|
| 1 · <a id="N01"></a>N01 | P0 / M | Authoritative finding lookup by supported stable ID. FindingDetailPage seeds from `location.state` and does not fetch using the URL ID; affected links include AI-BOM evidence. | U07 owns visible states/Back. Existing `api.getFinding` and backend GET accept UUIDs; some routes currently pass display IDs. Resolve that identifier compatibility explicitly without silently rewriting existing links; direct entry/new tab/no-state resolves the same authorized record. Distinguish denied, missing and failed responses. Findings frontend + API owner. |
| 2 · <a id="N02"></a>N02 | P0 / S–M | Supported tenant EOL destination. `EndOfLifeRoute` redirects tenant users to Exposure, while dashboard EOL actions target it. | U08 fixes the visible loop; domain owner chooses existing supported at-risk view or explicit capability boundary. Preserve platform catalog ownership. Product/domain + frontend. |
| 3 · <a id="N03"></a>N03 | P0 / L | Metric definitions and count/drill-down parity: Critical Findings risk threshold versus severity; repository-wide CVE impact buckets labelled critical findings; independently counted suppressed-CVE Accepted Risk can overlap; impacted KEV click lacks matching restriction; “known exploits” includes KEV or high EPSS but click selects KEV. | U11 owns wording/chart presentation. Establish metric contract below, backend semantics and parity evidence before presenting a coherent whole. Domain/backend + feature frontend. |
| 4 · <a id="N04"></a>N04 | P1 / L | Persistence authority and mutation outcomes: configuration merges local scoring fallback into a “saved” result; investigation drafts/cache versus server records; campaign enrichment in browser storage; findings may succeed while ticket creation fails. | UI labels local/server state under U01/U10/U13/U14. Verify authoritative readback after reload/new session, identify partial success and safe retry without repeating completed writes. Feature API + frontend. |
| 5 · <a id="N05"></a>N05 | P1 / L | Bounded data access: per-host detail fan-out, silent dropping of rejected details, whole-page downloads for overview/components and first-100 AI findings without reachable pagination. | U02/U06/U12 own controls. Add supported server list/filter/aggregate contracts where needed; retain identity on detail failure and qualify >100-record/large-tenant cases. Backend + inventory/findings frontend. |
| 6 · <a id="N12"></a>N12 | P1 / M | Backend/action contract consistency: accepted-risk filter vocabulary versus supported finding enum; review/disposition responses and incident partial failures; coverage/freshness source interpretation. | UI feedback can improve immediately using existing responses. Domain outcomes, supported statuses and retry semantics must be explicit and independently tested. Domain/API owner. |
| 7 · <a id="N07"></a>N07 | P1 / M | Typed route metadata and feature URL-state ownership. Titles/groups/access metadata, route helpers, meaningful filters/tab identity and test route lists currently diverge; Applications/BOM selection is local-only. | U03/U06 own visible behavior; N07a below is the separately specified exit-guard prerequisite. Global registry work remains independent. Introduce focused metadata and feature-validated state adapters; preserve aliases, history and access checks. Keep independent test expectations rather than generating the entire oracle from the registry. Frontend architecture owner. |
| 8 · <a id="N06"></a>N06 | P1 / M | Remote-state lifecycle: manual effects versus query hooks, cancellation, query-key inputs, adaptive polling, workspace transitions and locally cached identity/scope. | Preserve existing query-client clearing on workspace entry/exit; test stale response handling and data identity. Do not infer a cross-tenant vulnerability solely from unscoped preference keys. Feature frontend. |
| 9 · <a id="N08"></a>N08 | P2 / L | Cohesive module ownership and CSS maintenance. Large Configurations/Campaign/Platform files mix concerns; Connect imports a domain section from Configurations; large eager family style layers need ownership checks. | Refactor incrementally with feature work, preserve deterministic CSS order/public boundary and API behavior. File length is not a correctness defect. Frontend architecture owner. |
| 10 · <a id="N09"></a>N09 | P2 / M | Performance/observability measurement: request count, bytes, time to usable table, cancellation and optional production task telemetry. | Establish local baselines first; production telemetry needs a separate scope/privacy decision. Record environment, cardinality, method and owner; no fabricated improvement targets. Platform/frontend owner. |
| 11 · <a id="N10"></a>N10 | Deferred / L | AI Assets integration into Exposure matrix. Current AssetType/endpoint cover four infrastructure domains, and tests explicitly omit AI assets. | Separate API/domain source, severity mapping, deduplication, entitlement and AI drill-down contract. U11 must not fabricate a fifth row. Domain/backend + AI frontend. |
| 12 · <a id="N11"></a>N11 | Decision / varies | Optional product-scope changes: general Policies beyond `ai.security`; phone read-only restrictions; new “changed since last visit” data; removal/redefinition of Security Score; real notification delivery; unsupported runtime/pilot features. | No capability expansion/reduction is selected by this documentation task. Record a product decision and separate implementation scope. Product owner + domain owner. |

## N07a — narrow prerequisite for complete navigation guards

Status: **specified dependency; not implemented or authorized as an incidental UI change**. This sub-item is separate from the optional global route-metadata registry. The mounted app uses BrowserRouter. The installed router's useBlocker requires a data router; merely adding that hook to Workbench would fail.

Selected technical approach: move the existing app under `createBrowserRouter` + `RouterProvider` with a root wildcard element containing the existing PresentationBoundary/App composition. Keep existing descendant route definitions, paths, aliases, search parameters, lazy pages, error/auth boundaries and query ownership; no route loaders/actions, API changes or global route registry are introduced. Define the router once outside component renders. Validate absolute/relative link resolution, refresh, nested routes, public/auth transitions and back/forward before consuming useBlocker.

Use supported useBlocker for SPA Push/Replace/Pop transitions and a dirty-only beforeunload handler for document exit. Session expiry and enforced access redirects cannot be vetoed by an unsaved-form prompt; preserve existing authorization behavior. Add a data-router test helper using createMemoryRouter for guard tests; do not globally rewrite unrelated MemoryRouter tests or mask missing router context with private APIs. Roll back the router slice independently if navigation regresses.

Estimated effort: **2–4 focused person-days including guard/router regression tests**, separately from the UI stage estimates. Owner: frontend architecture owner. Acceptance: valid route/history/public/auth behavior plus blocked/cancelled/proceeded Push/Replace/Pop and dirty-only native unload warning. Existing current URLs and workspace query-cache boundaries remain intact. U10 cannot close full exit protection until this dependency is complete. No private history patching or ad hoc popstate undo is an alternate implementation.

## Metric definition contract — N03

Define each metric once with a stable ID, human label, **population**, unit (finding/CVE/component/asset), tenant/platform scope, authoritative source, exclusions/unknown handling, time window/snapshot, and a typed drill-down filter specification or explicit non-drillable status. A numeric render helper does not satisfy this contract.

The KPI and destination use the same declared filter semantics. Do not duplicate backend aggregation logic in the browser. Where codebases cannot share a type directly, use a versioned API/schema contract plus independently maintained boundary tests. Count parity must compare the same population, unit and snapshot. Exact equality across independent polling times or page lengths is not a valid invariant.

Acceptance cases: risk-high/severity-low finding; unknown severity/domain; mixed open/suppressed/resolved; duplicate component associations; distinct CVEs versus finding rows; impacted and non-impacted KEV; EPSS-only signal; paging; independent refresh. Status distributions must be mutually exclusive over a declared denominator before they become a 100% stacked chart. If populations legitimately differ, explain/expose the difference rather than forcing totals to agree.

The reference mock's grid totals are 1,244 versus Open Findings 1,223, and its score 72 conflicts with average risk 6.4 under the current inverse formula (36). Those are illustrative-data inconsistencies, not target production values. Evaluate whether the score is useful before adopting a ring or changing its formula. “Critical” should identify the selected severity population; risk-threshold populations need an explicit risk label.

## Workbench persistence/capability boundaries — N04/N12/N11

Current source distinguishes browser runbook state from server investigation/assessment submissions. `saveAssessment(true)` advances to finding creation only after submit and detail refresh succeed. Applicability and analyst impact are separate maps. The generic dirty guard compares notes/rationale, so decision-only edits and every route-exit path require qualification; do not claim those are protected already.

Finding creation may succeed while ServiceNow ticket creation fails. Track and retry the failed operation without implying that finding creation failed or creating duplicates. Preserve existing creation/reopen/already-open semantics and validate the authoritative result.

NotifyGroupsPanel prepares text drafts and explicitly says email delivery is not connected. No actual email dispatch, delivery tracking or automatic notification on completion is included in UI work. If delivery is wanted, it is a separate capability under N11. Generated fixes, runtime evidence and generative pilot restrictions remain subject to existing capability boundaries.

## Traceability from the original architecture findings

| Original finding | Current ownership |
|---|---|
| A01 / A02 | N01/N02 for contracts; U07/U08 for visible entry/return behavior |
| A03 | N03/N12 for metric/status meaning; U11 for labels/charts |
| A04 | U01 for presentation; N12 for any missing availability contract |
| A05–A08 | UI roots U02–U05; no separate architecture project required |
| A09 / A10 | N05 for bounded/paged data; U06/U12 for reachable controls |
| A11 | N07 for route/state architecture; U06 for visible navigation/context |
| A12 / A13 | N04/N12 for authority/results; U01 and family adoption for feedback |
| A14 / A16 / A17 | UI header/responsive/visual contracts U02/U03/U09; optional capability changes N11 |
| A15 | U14 control design; N11/N12 only for changed rollout authority/semantics |
| A18 | N08 only; removed from UI-elements feedback |

## Evidence and closure ledger

All items remain candidates. Per item record: exact source revision/diff, reproduction, agreed scope, dependency owner, API/schema effect, tests, readback/measurement and closure date. The initial source recheck is `eedc8a08` plus existing local changes; no new immutable candidate, fresh browser run, backend integration run or deployment is certified here.

A UI item can close its presentation acceptance while an unrelated architecture optimization stays open. It cannot claim successful data/persistence/capability behavior while its actual contract dependency remains unresolved. No underlying API/domain change is hidden inside a cosmetic UI task.

Source pointers: [App](../../../frontend/src/App.tsx), [FindingDetailPage](../../../frontend/src/pages/FindingDetailPage.tsx), [ExposureDashboardPage](../../../frontend/src/pages/ExposureDashboardPage.tsx), [DashboardService](../../../backend/src/main/java/com/prototype/vulnwatch/service/DashboardService.java), [VulnRepoDashboardService](../../../backend/src/main/java/com/prototype/vulnwatch/service/VulnRepoDashboardService.java), [FindingQueryService](../../../backend/src/main/java/com/prototype/vulnwatch/service/FindingQueryService.java), [FindingRepository](../../../backend/src/main/java/com/prototype/vulnwatch/repo/FindingRepository.java), [ConfigurationsPage](../../../frontend/src/pages/ConfigurationsPage.tsx), [InventoryPage](../../../frontend/src/pages/InventoryPage.tsx), [InventoryOverviewPage](../../../frontend/src/pages/InventoryOverviewPage.tsx), [BomComponents](../../../frontend/src/features/inventory/BomComponents.tsx), [WorkbenchMain](../../../frontend/src/features/cve-workbench/components/WorkbenchMain.tsx), [InvestigationCanvas](../../../frontend/src/features/cve-workbench/components/InvestigationCanvas.tsx), [NotifyGroupsPanel](../../../frontend/src/features/cve-workbench/components/NotifyGroupsPanel.tsx).
