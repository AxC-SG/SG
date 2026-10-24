# UI 2.0 — behavior parity and implementation readiness

Reviewed October 24, 2026 against the current local application and enriched design reference.

**Decision: ready to start a staged, behavior-preserving implementation. Not ready to replace every production page or deploy the mock wholesale.** The visual direction, major component families, and critical Findings/CVE contracts are now documented and regression-tested. Complete route-level visual acceptance and authenticated end-to-end qualification remain release gates.

## What changed in this pass

- Added an AI Findings composition using the same header, navigation treatment, labelled filter controls, tables, badges, empty states and detail hierarchy as Vulnerability Findings. Policy violations and AI-BOM software vulnerabilities retain their distinct scopes.
- Corrected the CVE mock: applicability and analyst impact are separate; computed impact is separately displayed; partial assessment saves are permitted. Removed the invented all-reviewed gate and the unrelated automatic-generation setting.
- Expanded the CVE reference to overview, investigation, applicability, impacted assets and finding configuration, fixes, and notification drafts. Included creation modes, existing grouped-finding behavior, failure retention, and dirty-rationale navigation.
- Corrected mock finding status/source choices to the live contract (`OPEN`, `RESOLVED`, `SUPPRESSED`, `AUTO_CLOSED`; `MANUAL`, `AUTOMATIC`), added working missing column filters, aligned widget toggle behavior, and used 25-row sample pagination.
- Added live frontend regression tests. Production UI, API handlers, query hooks, filter reducers and routes were not changed by this parity pass. Existing workbench repairs already in the workspace were preserved.

This document supersedes older claims that the standalone mock is a complete 1:1 functional specification. The live application is the authority for behavior. Mock saves, queues, datasets, graphs, counts, and pagination remain simulated.

## Non-negotiable implementation boundary

Restyle and extract presentation around current controllers. Reuse the existing hooks, DTOs, role/entitlement helpers, API methods, path helpers and request/error handlers. Do not port the mock's local arrays or state machines into production.

Keep visible strings and accessible names, first-render actions, navigation targets, query parameters, router state, theme storage (`scoutai-theme`, default dark), entitlement checks, role gates, lifecycle containment, selection semantics and existing test selectors. Preserve `fpl-widget--active`, `fd3-tab--active`, `ai-severity-grid--compact`, `active`, `.fd3-modal` with `.btn-primary`/`.btn-danger`, `.grid-exposure-table tbody tr`, `.grid-exposure-cell--high .grid-exposure-cell-btn`, `.fpl-hbar-row`, and `.react-flow__pane` until their tests are deliberately migrated with equivalent assertions.

Optional command palette, sidebar collapse, resizing, new bulk actions, extra charts, new filter persistence and changed row interactions are separate behavior changes. They are not implicit requirements of the visual refresh.

## Findings contract — preserve exactly

Sources: `frontend/src/pages/FindingsPage.tsx`, `features/findings/hooks.ts`, `queries.ts`, `types.ts`, and `components/FindingsSummaryWidgets.tsx`.

| Area | Current behavior to preserve |
|---|---|
| Initial URL scope | Reads repeated `severity`, `status`, valid `creationSource` (`MANUAL`/`AUTOMATIC`), repeated `assetType`, plus `vulnerabilityId`, `packageName`, `assetName`. Other column state is not automatically URL-persisted. |
| Queue selection | Explicit/default/fallback resolution remains in `useFindingsQueryContext`; queue changes update the `queue` URL parameter using replace. Personal queues keep create/edit/duplicate/default/delete APIs, confirmations, errors and scope merging. |
| Server narrowing | `queueKey`, severity, status, creation source, vulnerability/package/asset name, support group, assignee, due band, asset type, unassigned, incident-linked, group field/value. Keep existing trimming, omissions, enums and API serialization. |
| Local narrowing | Finding ID, owner display name, incident-ID substring and minimum risk run against the fetched page; local matching also checks several server-supplied fields. Do not silently turn these into global searches or claim page-local counts are tenant totals. |
| Column multiselect | Values within one severity/status/source filter accumulate. Independent column filters combine. Removing a chip removes that filter only. Clear-all clears ad-hoc narrowing, not the selected queue. |
| Severity widget | Selecting the same single severity again toggles it off; sets/clears severity, clears status and due band, resets page. Honors incompatible base-queue severity restrictions. |
| Status widget | Same single-value toggle; clears severity and due band, resets page. Honors base-queue status restrictions. |
| Asset widget | Toggles exact asset name, clears due band, resets page. Preserve full identity even when displayed text is truncated. |
| SLA widget | Toggles overdue/due-soon/on-track/no-SLA; respects conflicting base-queue due band. Local bands apply to OPEN rows: overdue before now; soon from now to strictly less than seven days; on-track at least seven days; no-SLA absent due time. |
| Key indicators | Critical Open sets severity+status while preserving other column fields and clears due band. Unassigned clears ad-hoc filters then sets OPEN + `unassignedOnly`. With Incidents clears ad-hoc filters then sets `incidentLinked`. |
| Aggregate scope | Summary, distributions, backlog health and group breakdown queries receive queue scope only. Table drilldowns do not recompute these aggregates over the current page or narrowed result. |
| Grouping | Multi-field grouping uses server group aggregates for the full queue. Clicking a group clears prior ad-hoc filters then applies `groupField`/`groupValue`. The mock's simple grouping control is not a replacement for `MultiGroupBy`. |
| Pagination | 25-row cursor paging, existing next-cursor enablement and previous-page stack. Queue/server-filter changes reset page and cursor history. Retain results while fetching (`keepPreviousData`). Do not replace this with array slicing. |
| Selection | Clicking a vulnerability finding row selects it. Finding ID link opens detail with finding in router state. CVE callback opens the workbench. Both stop row-selection propagation. Preserve current selection lifetime and current-page select-all behavior. |
| Preferences | `findings-col-vis-v2` column preferences; mandatory Finding ID/CVE ID columns; retain order, defaults and all optional columns. No invented sorting API. |
| Actions | Resolve, ServiceNow incident, defer, false-positive, duplicate, assignment, reopen and delete keep role gates, selected targets, validation/payloads, confirmations, success/error behavior and refetching. |

### Existing edge cases that a restyle must not silently reinterpret

- Filter URL values initialize local state; there is no general bidirectional URL synchronization for all filters. Do not promise new browser-back/reload persistence without a separate behavioral change.
- `all-findings` is normalized by removing the queue parameter. With an asynchronously loaded personal default, queue resolution deserves an explicit end-to-end regression before release; a restyle should keep the existing hook intact.
- Finding-ID/minimum-risk filtering is page-local. Not all active local fields have chips or saved-queue equivalents. The current queue-save merge does not serialize every transient field (for example the local risk/finding-ID/incident-ID substring and asset-type ad-hoc filter). Preserve this contract during styling; any functional correction needs a separate focused change and test.
- Selection can outlive currently visible rows. Do not introduce automatic clearing as an incidental effect of a shared table. Validate off-page selection/action behavior in acceptance tests.

## AI Findings contract — consistent presentation, domain-specific behavior

Sources: `frontend/src/pages/AiFindingsPage.tsx`, `AiFindingDetailPage.tsx`, `AiExposuresPage.tsx`, route helpers and AI entitlement wrapper.

| Surface | Current contract |
|---|---|
| Policy Violations | `listAiSecurityFindings(policyId, status, 0, 100, provider, trimmedSubscription, severity, nativeKind)`. Default OPEN. Providers AWS/AZURE/MICROSOFT_COPILOT. States OPEN/RESOLVED/SUPPRESSED_BY_POLICY/All. `policyId`, `severity`, `nativeKind` come from URL. Subscription uses deferred trimmed value. |
| Action queue | Independent `listAiActionQueue` query; show up to ten entries in the current page flow. Do not narrow it with the Findings filter model or invent aggregate counts. Policy and validated-exposure destinations remain distinct. |
| Software Vulnerabilities | `listFindings({findingKind:['VULNERABILITY'], hasAffectedAiResource:true, status:[…] or undefined, size:100})`. Keep both mandatory scope constraints when changing status. |
| Row behavior | AI rows open detail; they do not inherit vulnerability-row selection. Detail URLs retain the existing `returnTo` and vulnerability detail router-state contracts. Exposure links stop propagation. |
| URL vs transient controls | Provider/status/subscription are local state today; the return URL preserves the existing pathname/query only. Do not invent persistence in a visual extraction. |
| Authorization | Keep AI entitlement and existing role checks. Do not add vulnerability bulk workflow actions, SLA fields, ownership mutations or queues without backend and product support. |

The new reference demonstrates the same visual language and visible domain scope. Its AI detail is a composition specimen, and its exposure-path page is explicitly marked unexpanded. Production must retain full existing review, evidence and exposure workflows.

## CVE Assessment Workbench — verified behavioral map

Sources: `WorkbenchMain.tsx`, `CveOverviewTab.tsx`, `ApplicabilityTab.tsx`, `FindingsTab.tsx`, `InvestigationCanvas.tsx`, `NotifyGroupsPanel.tsx`, `assessment-helpers.ts`, `VulnRepoCveAssetsPage.tsx`, feature API/query modules.

| Workflow | Required contract |
|---|---|
| Entry/navigation | Existing Intelligence/organization record routes, CVE ID encoding, back/return context and asset/software drilldowns. The overview Create Findings card navigates to the dedicated `/assets` page; Proceed to Findings opens the workbench's impacted-assets step. Keep both entry paths. |
| Initialization | Reset on a different CVE; detail refreshes for the same CVE must not overwrite in-flight decisions. Preserve persisted assessment, runbook and finding identifiers. |
| Intelligence | Overview/KEV/EPSS/CVSS/vendor sources and equivalence data use current provenance, trust, evidence and missing-value handling. Risk scores remain current calculations. No sample metrics in production. |
| Investigation | Inventory criteria/results and resolved inventory, false-positive review/overrides/evidence, EOL analysis, solutions/fix saving, task states, logs, confidence, agent drafts and confirmation, analyst and lifecycle. Preserve substep dirty warnings and each save/run/retry action. |
| Persistence boundary | `saveRunbook` then `submitCveInvestigation`; only clear saved-note dirty state after success and refresh. Failed initial runbook read blocks saving and exposes retry. Detailed inventory criteria/results continue their existing local draft contract. Do not silently convert them into server-persisted claims. |
| Applicability | `APPLICABLE`, `NOT_APPLICABLE`, `NEEDS_REVIEW`; individual decision and Mark all actions. Removing applicability deletes analyst impact; restoring it initializes UNKNOWN if absent. |
| Impact | Separate analyst `IMPACTED`, `NOT_IMPACTED`, `UNKNOWN`. Computed VEX impact remains server-driven. Never collapse the two into one Affected selector. |
| Result derivation | No applicable software → NOT_AFFECTED; any applicable + analyst impacted → AFFECTED; all applicable not impacted → NOT_AFFECTED; otherwise UNDER_INVESTIGATION. Preserve existing partial-review behavior; do not impose an all-reviewed gate. |
| Assessment request | Existing software detection, detection method, affected component labels, vulnerableVersionPresent, final result, confidence, trimmed rationale, `componentImpactDecisions` and `componentAnalystDispositions`. Save refreshes detail/list; Proceed advances only after save succeeds. |
| VEX disclosure | Component-scoped loading, errors including unavailable persisted evidence, close/reopen retry and successful-read caching. Preserve provider/trust/freshness/document/source details. |
| Finding eligibility | Applicable + exact eligible evidence, or Applicable + analyst Impacted override; explicit Not Impacted excluded. Computed evidence and manual override stay distinguishable. Preserve investigation-confirmed/synthetic inventory rows and false-positive overrides. |
| Finding list | Selection, asset/software/support-group/priority/FP/finding-ID filtering, search, bulk FP mark/unmark, clear selection, finding/asset drilldowns. Keep both main-workbench and dedicated affected-assets controller semantics. |
| Finding configuration | Title, severity with current SLA-driven due-date behavior, due date, tags, notes, lead analyst/assignment group/auto ownership, ServiceNow opt-in state, selected component IDs and decisions. Modes ASSET_CVE and CVE_FIX; ADD_TO_EXISTING/CREATE_NEW only in the current grouped-finding conditions. No automatic creation mode in this panel. |
| Failure/duplicates | Preserve create/reopen/already-open outcomes. Grouped creation failure does not fall back to a different mode. Retain form/selection on failure. Ticket failure does not erase finding success or trigger duplicate creation. |
| Ticketing | Invoke current ServiceNow API only under its existing conditions and setting. Unchecking the option means no external ticket call; the internal JIRA enum value is not evidence of a new Jira integration. Keep current per-asset ownership mapping. |
| Fixes | Current generation/saved analyst-fix behavior, attribution, failure and retry. Pilot generative containment and provider availability remain enforced independently of design. |
| Notifications | Email delivery is not connected. Downloadable per-team drafts are available; download must not mark teams notified or report delivery success. |
| Dirty guard | Preserve actual notes/rationale guard paths plus investigation substep warnings. Do not claim universal protection for every navigation path or silently broaden the guard to all fields. |

The mock covers the composition and main decision paths. It is not a full reproduction of the investigation engine, false-positive criteria editor, solution generation, CVE equivalence, server persistence or external providers. Those existing production components should be restyled in place, with their tests and domain logic retained.

## Shared system to bridge page-family inconsistencies

Create presentation components with controlled slots/callbacks, not a universal feature reducer.

| Shared pattern | Apply to existing page families | Behavior remains owned by |
|---|---|---|
| Page header + freshness | Exposure, Findings/AI Findings, CVE, inventory/EOL, policies, operations, tenant/platform admin | Each route's queries, timestamps and actions |
| List workspace | Vulnerability/AI Findings, Intelligence, assets/software identities, campaigns, users/tenants/audit, connector runs | Domain adapters: columns, row interaction, selection, pagination, scopes |
| Filter controls + chip treatment | Column text/multi/radio filters, provider/status/subscription, inventory facets | Existing filter models and handlers; no new reset/persistence behavior |
| Table frame | Shared header/cell spacing, density, overflow, empty/loading/error treatment | Existing table implementation; preserve selectors, event propagation and keyboard behavior |
| Evidence/detail layout | Vulnerability detail, AI detail/exposures, host/software/declared-resource detail, CVE evidence | Domain tabs, provenance and available actions |
| Form sections | Configurations, connector-specific setup, tenant/user/service-account forms, policy studio | Current schemas/validation/save flows; no generic provider-form substitution |
| Status and state | Severity, lifecycle, SLA, policy result, stale evidence, refresh, no data, partial errors | Existing enums and semantics; color plus text, never color alone |
| Overlays | Confirmation, bulk workflow, side panels, evidence drawers | Caller mutation/dirty state, role checks and current labels |
| Graph container | AI dependencies, declared-resource relationships, exposure/investigation canvases | Existing React Flow data, interaction, attribution and evidence scope |
| Tenant/platform shell | Navigation, account/workspace selection, theme and content gutters | Current route/role/entitlement/lifecycle/auth wrappers |

Suggested shared interfaces: `PageHeader`, `ListWorkspace`, `FilterField`, `FilterChipRow`, `TableFrame`, `EvidencePanel`, `FormSection`, `StatusBadge`, `StatePanel`, and existing-compatible overlay wrappers. A `rowInteraction` adapter can declare selection versus navigation, but must execute the original handler. Keep query state outside all these primitives.

### Route-family coverage and remaining acceptance work

- **Deeply audited:** vulnerability findings, AI findings (both tabs), CVE overview/assessment/main findings/configuration/affected-assets entry and investigation save boundaries.
- **Representative mock coverage:** exposure dashboard, findings/detail, AI findings/detail, CVE, AI asset/relationships, inventory/lifecycle, connector catalog/forms, configurations, platform tenants, platform policy distribution, login, lifecycle/permission/error states and component library.
- **Must inherit the shared patterns and receive route-specific acceptance before release:** AI exposure list/detail, complete AI finding review/detail actions, all AI inventory categories and declared resources, tenant policies/framework coverage, complete platform policy studio, campaigns/detail, operations views, host/software detail, full EOL flows, users/service accounts/audit/schema/entitlements, connector-specific forms and run history, invitations/setup/authorized-workspace/auth states.
- Existing legacy redirects and contained/retired surfaces must stay contained. Do not restore Patch Management configuration, generic Azure/SCCM credentials, runtime execution UI, Fix Intelligence or unsupported operations because an old mock or CSS file contains them.

This is a family-level audit, not a claim that every production route has a finished bespoke mock or visual sign-off.

## Implementation sequence and acceptance gates

1. **Freeze baseline:** capture all active route families in both themes, principal roles and entitlement/lifecycle states. Preserve the current tests and source snapshot. Record API requests and navigation outcomes for the audited flows.
2. **Foundation:** tokens/type/spacing/theme bridge, accessible buttons/fields/badges, compatible overlays, shell. Keep selectors and accessible names. No query or backend changes.
3. **Findings vertical slice:** extract shared presentation and style Vulnerability + AI Findings together. Run existing/new tests unchanged. Verify all filters, queues, widgets, columns, selection, URLs and paging against baseline with a realistic multi-page dataset.
4. **CVE vertical slice:** restyle overview, investigation, applicability, impacted assets, creation panel, fixes and drafts. Keep both affected-assets entry paths. Re-run failed reads/saves, partial decisions, VEX cache/retry, duplicate creation and partial ticket failures.
5. **Remaining families:** list/detail/form/dashboard/graph families above; pair each tenant/platform route with its route tests and screenshot acceptance. Native provider-specific configuration and containment stay intact.
6. **Release qualification:** authenticated browser E2E in staging, real API and disposable database persistence checks, role/entitlement/lifecycle matrix, keyboard and responsive checks, build/lint/coverage gates, visual regression baseline and a tested rollback. Deploy through the existing release process only after qualification.

Use small reversible changes by page family. Do not combine backend workflow changes or filter fixes with the visual migration. Any intentional behavior change should have a before/after contract and separate tests.

## Verification evidence and limits

See `VERIFICATION_RESULTS_2026-10-24.md` for the fresh results and commands from this pass. Earlier full-stack workbench evidence is in `../../../output/CVE_WORKBENCH_VERIFICATION_2026-10-24.md` (repository-root `output/` is the authoritative location).

The fresh in-app browser attempt to `http://localhost:5173/vuln-repo/vulnerabilities` redirected to `/login?next=…`. No authenticated token was injected and no live records were mutated in this pass. Therefore the fresh automated frontend result and source audit do not constitute a fresh authenticated end-to-end or production certification. Earlier PostgreSQL/browser verification is attributed to its existing report, not represented as rerun here.

External ServiceNow delivery, email delivery and real AI provider execution were not exercised in this parity pass. The reference does not contact any backend. No production deployment was performed.
