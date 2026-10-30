# CVE Assessment Workbench — UI journey review

Updated October 28, 2026. UI adoption item: [U10](UI_IMPLEMENTATION_PLAN.md#U10). Scope: visible destinations, controls, hierarchy, feedback and transitions. Data/persistence/eligibility contracts are dependencies in [N01, N03, N04 and N12](NON_UI_IMPROVEMENTS_LEDGER.md), not additional UI tasks.

Evidence: source inspection of WorkbenchMain, CveOverviewTab, ApplicabilityTab, InvestigationCanvas, FindingsTab and NotifyGroupsPanel, the supplied six-tab mock, and retained representative fixture views. No new live journey or persistence pass is claimed. C = source confirmed; R = proposed UI; Q = needs current interactive qualification.

## Present navigation versus proposed navigation

The mock shows **Overview / Investigation / Applicability / Impacted Assets / Fixes / Notify Groups** as peer tabs. The mounted implementation combines Overview/Affected Entities/Fixes tabs, a separately opened investigation canvas and numbered applicability/findings/notification steps. This mismatch makes location and completion harder to understand.

**User-selected U10 navigation:** use six clearly named peer destinations with persistent CVE/workspace context. Use a separate task stepper inside Investigation. Tabs indicate current location; task markers indicate saved work status. Visiting a tab must not imply assessment completion or trigger a write. Supported read-only sections remain inspectable without completing every prior section. Gate write actions by their actual prerequisites and explain the blocker beside the control.

```text
Workspace / Vulnerability Repository / CVE-…           Back to original queue
CVE Assessment Workbench • CVE/name • severity • evidence freshness
[Overview] [Investigation] [Applicability] [Impacted Assets] [Fixes] [Notify Groups]

Current section                                         Primary next action
Saved / Unsaved / Running / Needs review / Unavailable   Supporting explanation
```

Use human-readable labels and a single route H1. Keep raw JSON/evidence copyable under disclosure; it should not dominate the first screen. Persistent completion badges need real saved-state evidence; otherwise show the current session's draft state explicitly.

## Draft, URL and exit contract

The [implementation plan](UI_IMPLEMENTATION_PLAN.md#stage-4--workbench-state-location-and-exit-behavior) is authoritative: one CVE-keyed parent owns editable drafts and dirty/baseline state; inactive panels **unmount**, with panel-specific fetching/effects inactive. Do not implement hidden-but-mounted tabs. Query state stays in the existing cache; read-only refresh does not overwrite edited values. Record changes cannot carry another CVE's draft forward.

Use validated `tab=overview|investigation|applicability|assets|fixes|notify` and Investigation `task` values from the existing five task IDs. Explicit changes push history; invalid/default normalization replaces; unrelated parameters remain intact. Refresh/share restores location, not unsaved content. Removing task outside Investigation avoids stale task state.

Dirty transitions include tab/task, links/sidebar, another record, browser Back/Forward and reload/close. Use the common Stay/Save-if-supported/Discard flow for SPA navigation, with failed save retaining state. Inside a form modal, confirmation replaces content in that same dialog and Stay restores form focus. For document exit attach dirty-only beforeunload and use the native browser confirmation; no asynchronous Save guarantee. Complete SPA guards depend on [N07a](NON_UI_IMPROVEMENTS_LEDGER.md#n07a--narrow-prerequisite-for-complete-navigation-guards); current BrowserRouter cannot simply consume useBlocker. That router prerequisite is separately scoped and must preserve auth/public/history behavior.

## Stage-by-stage UI review

| Stage | UI elements and recommended behavior | Entry / exit / acceptance |
|---|---|---|
| 1 · Overview | CVE identity, severity versus risk labels, source/date, matched-component/asset counts, EPSS/KEV labels, concise assessment progress and primary “Review investigation”/next supported action. Investigation trail distinguishes collected evidence, correlation and analyst review. Collapse raw JSON by default. | Entry from Findings, repository queue or direct CVE URL. Back label identifies the origin. No assessment is marked complete because intelligence was ingested. Missing data has an unavailable state. |
| 2 · Investigation | Persistent CVE identity, runbook task names, current/previous/next controls, per-task state, notes/log, saved/draft status and explicit Save Investigation. Explain automatic checks when opening a task; avoid surprise writes. | C: opening the canvas replaces step content. Save is disabled until saved runbook loading succeeds. Failed load offers Retry. R: current location and return to overview remain visible; failure retains editable input. |
| 3 · Applicability | Readable software/version rows, independent applicability and impact controls, evidence expansion, bulk-action scope, rationale/confidence and decision summary. “Save Assessment” stays here; “Save & continue to impacted assets” makes the write/transition explicit. | C: current “Proceed to Findings” calls `saveAssessment(true)` and advances only after submit + detail refresh. Do not replace this with unconditional Next. Unknown/unreviewed rows remain visible; partial work is labelled partial. |
| 4 · Impacted Assets | Distinguish matched, assessed and finding-eligible rows. Show selection count, scope, reason an item cannot be selected, ownership/deadline configuration, existing finding links and Create Findings action. Clear filters/selection without losing unrelated assessment drafts. | C: internal step 3 renders finding creation; external affected-assets view also exists. R: use one name/context and explicit link between them. On completion show created/reopened/already-open counts and accessible result links. Ticket partial success has a distinct warning. |
| 5 · Fixes | Human-readable remediation options, applicability to selected software/assets, provider/source and review/generated labels; readable evidence and “Save as Fixes” where supported. A proposed suggestion must not look like an installed/verified patch. | C: Fixes exists under overview; Investigation Solutions also exposes saving fixes and moving to creation. R: reconcile these entry points without duplicating state/actions. Preserve selected scope and announce successful save or recoverable failure. |
| 6 · Notify Groups | Group selection with asset counts, clearly selected All/Impacted/Clear state, template picker, subject/body, Compose/Preview/Per team and Download drafts. Explicit “Email delivery is not connected.” | C: current implementation downloads a text file; it does not send email. Keep draft-only language throughout. No selected groups disables export with an explanation. Export success is not notification delivery or assessment completion. |

## Investigation task sequence

Use the actual runbook configuration for labels/order, not an invented linear business process. Source currently handles inventory review, false-positive check, EOL analysis, solutions and a summary display using `installed-patch-info`. The technical task ID is not a user-facing title.

| Task | UI feedback and navigation requirements |
|---|---|
| Asset inventory review | Criteria editor, scope summary, Run assessment, result counts, partial/unresolved entries and explicit Save of edited criteria/results. C: navigation to another task is stopped with an unsaved warning when this assessment is dirty. Explain what this Save covers relative to top-level Save Investigation. |
| False-positive review | Show assessed items, evidence, analyst override and resulting excluded/review state. C: entering this task can automatically run the check after inventory assessment. R: announce running/completed/error and do not equate a check running with analyst confirmation. |
| EOL analysis | Show lifecycle result, unknown mapping and source date; distinguish no data from supported software. C: entering can run analysis when prerequisite data exists. Show prerequisite and progress clearly. |
| Solutions | Show the targeted software/version and guidance provenance, supported generation/refresh state, review and save feedback. Keep pilot-contained generative actions unavailable as currently required. |
| Summary | Display completed and incomplete work, coverage limitations, saved status and supported next action. Opening a summary must not itself certify completion. Reconcile its visible title with task identity during implementation. |

Task states should include not started, running, needs review, saved complete, partial and unavailable where applicable. Do not introduce backend enums merely for visual uniformity; map actual states truthfully. Disabled tasks need a visible prerequisite explanation and an accessible name.

## Transition and recovery ledger

| Transition | Current observation / proposed UX | Qualification scenario |
|---|---|---|
| Queue → workbench → Back | Preserve origin, filters and meaningful selection/page context. Show “Back to findings” only when it is the actual origin. | J01: open from Findings and organization queue, then return to each; direct entry has a safe explicit fallback. |
| Overview → Investigation → task | Keep CVE header and section identity stable; focus moves to the opened section heading. | J02: keyboard opens canvas/task and returns without losing context. |
| Dirty inventory task → another task | C: task guard shows an unsaved warning. R: explain Save/Stay/Discard consistently and differentiate saved criteria from other cached task state. | J03: change criteria, try Next/task click/close/Back; no silent loss or false saved notice. |
| Any dirty assessment → another section or record | C: generic WorkbenchMain dirty guard compares notes and rationale, not every decision map. Do not assert all exits are protected. | J04: edit only applicability/impact, then tab/record/route/browser Back; verify or fix visible unsaved handling under U06. Persistence semantics remain N04. |
| Save Investigation → success/failure | C: multiple server operations and refresh occur. R: one busy action, explicit scope of save, success only when appropriate, partial failure message if operations differ. | J05: success, first-stage failure, later-stage failure and refresh failure; input retained and safe retry explained. Underlying transaction/retry contract N04/N12. |
| Save Assessment → remain / continue | Distinct button names and outcomes. Do not navigate as if successful when a submission failed. | J06: successful save remains; successful save-and-continue opens impacted assets; rejected save remains with rationale/decisions retained. |
| Unresolved applicability → partial save | Show unresolved count and partial outcome without forcing every item into applicable/not applicable. | J07: mixture of decisions, unknown impact and unresolved evidence; no misleading all-clear/completed status. Eligibility semantics N03/N12. |
| Impacted Assets → create/configure | Selection scope, required owner/deadline fields and existing-finding handling are clear before submit. | J08: zero selection, partial selection, filtered select-all, duplicate/already-open and failed creation; match displayed counts to authoritative results. |
| Findings created → ticket failed | Separate the successful result from the failed follow-up, with finding links and a specific retry. | J09: no generic failure that encourages duplicate finding creation. API/idempotency work N04/N12. |
| Investigation Solutions ↔ Fixes | Same supported fix identity/scope and clear save feedback; returning keeps current record context. | J10: no guidance, saved fix, unavailable generation, generation error and save error. No generated draft labelled verified. |
| Impacted scope → Notify Groups | Group/asset counts, date and template tokens match selected scope or disclose the broader population. Confirm current selection after reopening. | J11: impacted-only, all, clear, missing ownership and missing due date; no stale/incorrect “All teams” highlight. |
| Compose → Preview → Download | Retain edited subject/body; preview exact per-team draft; warn on unresolved tokens where appropriate. | J12: zero/one/multiple groups; inspect exported draft content and filename. No network send, “sent” toast or delivery claim. |
| Reopen/direct-entry/reload | Current section, current data, drafts and authoritative saved state are distinguishable. | J13: successful saved assessment/runbook reopens; unsaved local content is not represented as saved. Stable-ID and URL/persistence dependencies N01/N04/N07. |
| Valid/invalid URL → active view/history | Canonicalize tab/task, preserve unrelated filters/return context, push deliberate changes and replace normalization. | J14: direct link, refresh, invalid tab/task, task outside Investigation, Back and Forward restore the intended view. |
| Panel unmount/remount → same draft | Parent owns edits; inactive panel effects do not continue running. | J15: edit each panel, leave through the specified guard, remount and verify retained or explicitly discarded state; no inactive generation/check/refresh requests. |
| Dirty route exit / native unload | One router-backed SPA guard plus dirty-only beforeunload; no private history interception. | J16: blocked/cancelled/proceeded Push/Replace/Pop, close/reload after user interaction, clean exit without prompt and enforced auth redirect not vetoed. |
| Dirty form modal → discard prompt | Replace modal content in place. | J17: one visible modal, draft intact on Stay, field focus restored, Discard follows pending navigation and pending writes prevent duplicate operations. |
| Refetch / record swap during edits | Edited fields are not overwritten by background responses or another CVE. | J18: pending older response, refetch while dirty, successful/failed save baseline and guarded record change; no cross-record draft leakage. |

These are acceptance scenarios, not recorded test results. Several behaviors are source-confirmed while the cross-stage experience remains unqualified. Existing `e2e/cve-journey.mjs` already covers parts of applicability/VEX/finding flows; extend it rather than claiming this is an entirely new untested feature or duplicating all existing assertions.

## Responsive and accessible controls

At 1440/1280px use the proposed content hierarchy and readable tables. At 768px permit header/action wrapping and section reflow. At 390px prioritize identity/current stage/next supported action and concise counts; put long evidence beneath disclosure and use internal table scroll. Touch target sizing keys off any-pointer:coarse independently of width; verify a wide touch tablet and a narrow mouse window. Keep supported edits reachable unless a separate mobile capability decision is made.

Tab navigation needs selected/current semantics and logical keyboard behavior; tabs must not double as misleading completion indicators. Task stepper labels and progress are announced; keyboard focus follows opened sections and returns from dialogs. Every decision group has a contextual accessible label. Tooltips and score explanations work without pointer hover. Verify 200% zoom, screen-reader names, focus visibility and readable severity/status labels in both themes.

## Adoption and evidence record

Owner: CVE feature frontend + UI designer, with QA for J01–J18. Status: **Stage 4 integrated, not verified** (see the [Stage 4 record](UI_IMPLEMENTATION_PLAN.md#stage-4-implementation-record--october-29-2026)): six peer tabs, validated `tab`/`task` URL, parent-owned drafts, guarded in-Workbench exits and dirty-only `beforeunload`. J01–J18 QA and the N07a-dependent exits remain pending. Dependencies: shared roots U01/U03/U04/U05/U06, N07a for complete exit guarding, and other explicitly linked non-UI contracts only when necessary. No live assessment, finding creation, ticket creation or notification was performed by this review.

Acceptance requires the representative Findings slice first, then all applicable transition scenarios with current candidate/role/fixture/environment and evidence attached. Record intentionally unsupported scenarios as unsupported, not passes. Underlying data/eligibility/persistence fixes are closed in the separate ledger; UI closure confirms the user-facing behavior, not a hidden backend guarantee.

Sources: [WorkbenchMain](../../../frontend/src/features/cve-workbench/components/WorkbenchMain.tsx), [CveOverviewTab](../../../frontend/src/features/cve-workbench/components/CveOverviewTab.tsx), [ApplicabilityTab](../../../frontend/src/features/cve-workbench/components/ApplicabilityTab.tsx), [InvestigationCanvas](../../../frontend/src/features/cve-workbench/components/InvestigationCanvas.tsx), [FindingsTab](../../../frontend/src/features/cve-workbench/components/FindingsTab.tsx), [NotifyGroupsPanel](../../../frontend/src/features/cve-workbench/components/NotifyGroupsPanel.tsx), [existing fixture journey](../../../frontend/e2e/cve-journey.mjs).
