# UI 2.0 implementation plan

Prepared October 24, 2026. Historical plan: its source migration phases have been implemented. Updated record status October 28, 2026; the dated body below preserves the original sequence and starting assumptions.

For present code, ownership and qualification limits read [CURRENT_STATE.md](CURRENT_STATE.md). For the later cleanup/retirement plan read [UI2-Final-Implementation-Plan.md](UI2-Final-Implementation-Plan.md). For new screens follow [the UI development standard](ui-development-standard.md). Old reference/report/checklist paths, baseline counts and version-switch instructions below are historical; retired inputs can be recovered from Git at `eedc8a0864cadf7c0cd0e55ec733f4637ff6622a`. Do not restart these phases or reintroduce their transitional mechanisms.

## Recommended delivery model

Implement the redesign in small, verified slices grouped by shared components and complete user workflows. Release a cohesive experience to each tenant after the required slices pass qualification.

Use one coordinated implementation effort with automatic progression between phases. Left navigation remains a coverage checklist, rather than the order of work. Vulnerability and AI Findings should be implemented together because their inconsistent presentation is a known problem. Their query/filter/action behavior remains separate.

The existing mock and research are enough to begin. They do not justify replacing every production page in one patch: the mock contains simulated persistence, several routes have representative rather than complete compositions, the live frontend has 49.41% line coverage, and fresh authenticated end-to-end qualification is still outstanding. A passing 715-test baseline is valuable protection, not proof of complete coverage.

The redesign scope is the tenant and platform application plus their authentication/setup entry points. Marketing landing pages, blog content and demo marketing content remain outside the redesign scope; preserve their existing links and routing.

## Reuse existing work

These are the starting inputs, not research to repeat:

1. `BEHAVIOR_PARITY_AND_IMPLEMENTATION.md`: domain contracts, preserved selectors and behavior, shared component families, route acceptance gaps.
2. `VERIFICATION_RESULTS_2026-10-24.md`: 715 live tests, 35 reference tests, build/lint results, known verification limits.
3. `BEHAVIOR_BASELINE_2026-10-24.json`: hashes of the critical behavior source and the tested Git base. The baseline includes existing uncommitted work.
4. `design-reference/`: existing visual vocabulary, tokens, compositions, states, themes and interactions. Production controllers remain the behavior authority.
5. Existing live tests, including the 25 added regression cases, existing workbench repairs and route error boundary.
6. Repository-root `output/CVE_WORKBENCH_VERIFICATION_2026-10-24.md`: earlier browser/PostgreSQL evidence, explicitly attributed to that earlier verification.
7. Existing CI in `.github/workflows/quality.yml`: lint, typecheck, build/bundle verification, coverage, backend verification and PostgreSQL integration jobs.

Only inspect new or changed source and uncovered route behavior as necessary. If a source hash has changed, review that delta and refresh the affected baseline; do not repeat the whole audit or overwrite newer work.

## Sequence and dependencies

Each row can contain several small changes. Complete and validate a row before starting its dependent row. Keep changes independently reviewable and reversible.

| Phase | Implementation scope | Reason for this position | Exit evidence |
|---|---|---|---|
| 0 — Preserve baseline and prepare gates | Snapshot current tracked/untracked relevant work; reconcile current source against the existing audit; populate route checklist; establish reproducible visual/behavior fixtures | Avoid losing the current uncommitted work or building from an older checkout | Source checkpoint; current baseline checks; list of missing access/fixtures; planned route coverage |
| 1 — Shared foundation and shell | Tokens/theme bridge, type/spacing, buttons/fields/badges, table frame, header/freshness, state panels and compatible overlays; tenant/platform shell | Establishes the common experience once | Dark/light and narrow/desktop checks; navigation, workspace, role and entitlement behavior preserved; no unintended global CSS spillover |
| 2 — Findings family | Vulnerability Findings and detail; AI policy findings and detail; AI software-vulnerability tab; AI exposure list/detail | Validates the most important consistency requirement and the highest-priority filter contract early | Full filter/queue/widget/group/cursor/selection/URL cases; AI scope and return navigation; read-only gates; empty/error/refresh behavior |
| 3 — Complete CVE workflow | Intelligence/organization records, overview, investigation canvas, applicability and separate impact, impacted assets and dedicated assets/software routes, finding configuration, fixes and notification drafts | Reuses Findings primitives and validates the longest critical workflow | Both finding entry paths; partial assessments; local/server persistence boundaries; VEX retry/cache; eligibility/overrides; duplicate/mode/ticket failures; draft export; dirty guards |
| 4 — Inventory and lifecycle | Hosts, software identities/detail, EOL, AI inventory categories, AI asset/declared-resource details and relationships | Reuses dense tables, detail sections and evidence components | Long identifiers, missing data, nested rows, provenance, graph interaction, route context, entitlement restrictions and pagination |
| 5 — Governance and platform administration | Tenant policies/framework coverage, platform policy studio/distribution, tenants, users, service accounts, invites, audit/schema/entitlement views, authorized workspaces | Extends the shared system to both workspaces without mixing authority models | Role/lifecycle matrix; policy validation/approval/publication; form failure retention; tenant scope; audit/export; no expanded permissions |
| 6 — Connectors and configuration | Connector catalog, all supported provider forms and run history; SLA/risk/ownership/suppression configuration | Uses established form patterns while protecting provider-specific behavior | Exact fields/validation/API payloads; test/save/sync/retry; credentials handling; contained/retired connectors remain contained |
| 7 — Remaining experience and consistency sweep | Exposure/dashboard, campaigns/detail, operations, login/setup/invites/authentication entry points, legacy redirects; sweep every active left-nav destination and direct-link route | Completes the application and catches inconsistencies introduced by shared styles | Route checklist complete; no orphan legacy presentation on active routes; all existing behavior/redirects retained |
| 8 — Integrated qualification and release handoff | Full frontend checks, affected backend/PostgreSQL checks, authenticated staging journeys, visual/accessibility/responsive/performance review, rollback rehearsal and release evidence | Qualifies the integrated application rather than assuming individual pages imply a complete journey | All required gates green; no unresolved behavior regression; reviewable release candidate and rollback instructions |

Phases 5–7 can be reordered for availability of fixtures, but dependencies and shared-file ownership must remain explicit. No automatic parallel writers to shared tokens, shell, primitives, route configuration or global CSS. Separate agents/parallel implementation are not part of the default plan.

## Architecture: shared presentation, existing behavior

Create controlled presentation primitives with content/action slots. Keep feature queries, reducers, DTOs, validation, calculations, event handlers and mutation orchestration in their current feature modules.

- Share the list header, table spacing, toolbar layout, badges, filter-control styling, disclosure/evidence patterns, state treatment and overlays.
- Preserve current filters and request serialization. Do not substitute the mock's array filtering, local queues or sliced pagination for live hooks.
- Preserve vulnerability row selection and AI row navigation through explicit adapters. A shared table does not imply shared actions or data models.
- Keep full investigation/graph components and restyle their internals incrementally. Do not replace them with simplified mock panels.
- Preserve existing labels, accessible names, route helpers, return context, router state, selectors, theme storage, roles, entitlements and lifecycle/containment behavior.
- Keep domain behavior changes in separate changesets. A discovered filter bug is recorded with a reproduction and impact; the redesign does not silently fix it.
- Introduce no new production framework or component-library migration as a prerequisite. Translate the reference's established tokens/components into the current stack.

### Contain global styling changes

Use a UI 2.0 root scope or equivalent presentation boundary so the new token bridge and component styles can be tested without partially restyling unrelated pages. Avoid unscoped rules for `button`, `table`, `.panel`, `.active` or shared legacy classes that change every page unexpectedly.

Keep the current UI available until the release candidate is qualified. Prefer the existing deployment/preview mechanism for isolation. If tenant-cohort opt-in is needed, implement a presentation-only rollout setting with a safe default and documented rollback. It must not alter authorization, entitlements, API behavior or the URL contract. Do not use it to mount both versions, duplicate data queries or switch an in-progress form.

## Automated execution loop

Once the whole implementation scope is authorized, the agent follows this loop without requesting approval after every page:

1. Read `IMPLEMENTATION_PROGRESS.json` and the latest accepted checkpoint. Inspect only the current phase, its dependencies and source changes since the baseline.
2. Select the next uncompleted unit and define its exact route/control coverage from the existing contract. Reuse reference patterns; make routine spacing/layout choices autonomously.
3. Implement the smallest coherent change. Preserve unrelated working-tree changes. Do not blindly commit all files, reset the checkout, or start an isolated checkout from an older clean HEAD that omits the current repairs/research.
4. Run targeted meaningful tests for touched behavior, then the shared acceptance gate for that slice. Changes to tokens/shell/overlays require cross-family checks, not just the local page test.
5. Inspect browser output against the reference in both themes and relevant viewport sizes. Check focus/keyboard/overflow and error/loading/empty/permission states. Compare behavior to the live baseline and visuals to the new reference.
6. Repair implementation regressions autonomously and rerun the affected checks. Never weaken existing assertions, lower coverage floors or automatically bless changed behavior to make a gate pass.
7. Save a checkpoint with changed files, tests/results, route coverage, screenshots, known limitations and rollback instructions. Mark the unit complete only when its required checks pass.
8. Continue automatically to the next dependent unit. On interruption, resume from the recorded checkpoint; do not restart completed research or phases.

The JSON file is a resumable ledger, not an executable scheduler. A normal active implementation run can use it directly. Background continuation or scheduled runs should be configured explicitly if wanted; none has been created by this planning task.

### Phase verification versus release qualification

A phase's code/fixture checkpoint can pass while a separately recorded authenticated staging gate awaits access. Record the missing evidence explicitly in the release ledger. Do not claim an authenticated pass from mocked fixtures or screenshots. This allows foundation and other independent implementation work to continue without repeatedly requesting login. Phase 8 cannot be verified until every required release gate is actually satisfied.

For phase 0, completion means the baseline, route inventory, executable checks and access requirements are recorded. Availability of staging authentication is tracked as a release dependency; it is not a reason to restart research or block all code changes.

### Gate implementation

Reuse existing npm/CI commands. Preserve the current Node 20 CI environment; local Node 26 may need `NODE_OPTIONS=--no-experimental-webstorage` for jsdom tests. Avoid changing application runtime configuration to address that local test-runner difference.

For every completed family:

```sh
npm run lint
npm run typecheck
npm run build
npm run test:coverage
```

Run from `prototype-app/frontend`. Coverage floors currently stand at lines 49.4%, statements 46.7%, functions 38.9%, branches 38.1%; retain or raise them. Keep all baseline test cases and assertions, while adding coverage for previously uncovered behavior. A test count alone is not an acceptance criterion.

Keep the standalone reference's typecheck/tests/build passing when its source changes. Avoid repeatedly rerunning it when only production files change.

The repository currently has no declared browser-E2E test script or dedicated visual-regression workflow in the frontend package/CI inspected for this plan. Phase 0 should establish a reproducible browser smoke/visual fixture route using approved test access, and integrate the chosen runner into CI if needed. Do not describe this missing gate as already automated.

Browser assertions should cover URLs, accessible controls, selection, visible state, API request shapes and intended mutation outcomes. Screenshots support visual review; they do not prove persistence. Save representative captures for each family and meaningful states, not every minor spacing edit.

For CVE/policy/connector/administration actions, exercise writes against disposable or explicitly approved staging fixtures. Preserve the existing backend/PostgreSQL jobs; rerun relevant integration checks for high-risk workflow qualification and run full release checks before rollout. Do not exercise external delivery or destructive operations against customer records merely to prove a visual change.

### Minimum critical browser journeys

1. Findings: URL scope → multi-column narrowing → widget toggle → queue-wide totals unchanged → group selection → cursor next/back/reset → row selection → detail/CVE links → return context → read-only actions.
2. AI Findings: provider/status/subscription + deep-link scope → detail/return → AI software-vulnerability tab → retained AI-resource constraint → exposure navigation → entitlement-unavailable state.
3. CVE: Intelligence → record overview → investigation save/reopen → applicability/analyst impact → VEX disclosure/retry → partial assessment → eligible assets → both finding-creation entry paths → configured creation/duplicate result → ticket partial failure → fixes → notification draft export.
4. Inventory: list/facets → expanded versions → detail/provenance → lifecycle → AI/declared-resource graph → back/return and entitlement states.
5. Platform/tenant authority: authorized tenant selection → tenant controls versus platform controls → policy lifecycle/cohort → identity/admin forms → audit/role/lifecycle restrictions.
6. Connectors/configuration: supported provider form → validation → test/save → sync/run failure/retry → existing risk/SLA/ownership/suppression settings.

Authenticate using an existing approved test session or fixture. The previous browser attempt reached login; if authentication is unavailable, continue independent implementation and checks, and leave authenticated qualification visibly pending. Request one login/access action when it becomes necessary. Do not inject credentials/tokens, bypass auth, or mark that gate complete without evidence.

## Minimal-interaction policy

Normal component extraction, styling, responsive choices, adding regression checks, fixing self-introduced regressions, recording evidence and moving to the next phase require no per-page approval once the implementation is authorized.

Provide concise milestone updates with the accepted result and next phase. Routine green phases are informational and do not pause work.

Ask for user input only when it changes the work materially:

- A genuine product decision that the existing design reference and behavior cannot resolve, such as a proposed filter/selection/workflow change.
- Missing access or an external condition required for a gate, after completing all independent work.
- A destructive operation, security-sensitive access change, or other action requiring explicit approval.
- Production release if the user has not already authorized that specific release. Present the concrete release candidate, evidence and rollback first.

No questions are needed now to produce this plan. Starting implementation under this plan is a separate action from preparing it.

## Release and rollback

Implementation checkpoints and deployments are separate decisions. Finish related routes together in preview/staging; avoid exposing tenants to an unfinished mix of old/new Findings, detail and CVE interactions.

Qualify the complete navigation experience before enabling UI 2.0 for a tenant. If a pilot cohort is used, it receives the same qualified route set and existing authorization rules. Expand only after the agreed release checks pass. Do not assume a presentation flag alone makes incomplete workflows releasable.

Rollback should restore the prior UI version or presentation setting without a data migration. Preserve URLs, data structures and workflow APIs throughout the redesign so saved filters, queued work and existing records remain compatible. Test rollback against current data and open-route navigation before release.

## Definition of done

- Every active tenant and platform route is recorded and visually consistent with the shared system, including direct links and routes absent from the left navigation.
- All current domain behavior and containment are preserved, with explicit evidence for critical journeys.
- Existing frontend/affected backend tests, bundle policy and coverage gates pass without weakened checks.
- Required authenticated, responsive, keyboard, visual and persistence qualification is complete; unavailable external integrations remain truthfully labelled.
- The release candidate has route coverage, screenshots, test evidence, limitations and a tested rollback.
- Production release occurs through the authorized existing process; preparing this plan does not deploy anything.
