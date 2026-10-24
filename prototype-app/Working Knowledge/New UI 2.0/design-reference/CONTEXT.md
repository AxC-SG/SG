## Behavior parity audit — October 24, 2026

Before production work, read `../BEHAVIOR_PARITY_AND_IMPLEMENTATION.md` and
`../VERIFICATION_RESULTS_2026-10-24.md`. Live hooks/controllers are the behavior
authority. The mock is a presentation specimen with simulated data and saves.

This audit adds AI Findings parity and corrects the CVE model: separate
applicability/impact, partial saves, ASSET_CVE/CVE_FIX creation, fixes and
notification drafts. Retain the full existing investigation component in production.

# ScoutGrid UI modernisation — design reference (context)

## Enrichment update — 24 October 2026

The reference now opens at `http://127.0.0.1:5174/design-preview.html#/reference`.
The review hub links the CVE assessment workbench, AI asset detail with relationship
graph/evidence, Platform policy distribution, dense inventory/lifecycle drawer, and
States & permissions fixtures. Original example pages remain available.

Role fixtures now change navigation and mutation controls; entitlement and lifecycle
fixtures withhold unavailable content. Background-refresh, partial-error and
save-failure examples preserve existing results/edits. All effects are browser-local
simulations. No API, cloud service, real credential or tenant state is used.

Shared fixes include portal-based table popovers, modal/drawer focus containment and
restoration, unmounted closed drawers, accessible field descriptions/errors, stronger
secondary text contrast, responsive labeled scoring rows, and route scroll reset.
Retired Patch Management entries have been removed; contained generic Azure/SCCM
connectors are read-only. Command search/collapse are opt-in reference enhancements.

The standalone Vite build now targets `design-preview.html`. The test harness supplies
deterministic browser Storage rather than depending on Node's global Web Storage.
`Enrichment.test.tsx` adds workflow, failure-retention, permission, scope, and overlay
regressions alongside the original tests. Use `npm test` without a Node compatibility flag.

The original notes below describe the initial copy. For current setup and enrichment
routes, use `src/design-preview/README.md`. This remains a representative design
reference; unmodeled live routes still require migration parity checks.

## What this is
A standalone visual + behavioural reference for restyling the ScoutGrid frontend
(React 18 + TypeScript + Vite, plain CSS, lucide-react, @xyflow/react) with a modern
SaaS look, **without changing any functionality**. It was built as a mock of the live
app at `prototype-app/frontend`, and is intended as the input for the full-app restyle.

## Files
- `design-preview.html` — Vite entry; loads `src/design-preview/main.tsx`.
- `src/design-preview/` — the reference source (see its README.md for route map,
  component mapping and migration order).
  - `DesignPreviewApp.tsx`, `nav.ts` — shell and nav IA mirroring App.tsx.
  - `pages/` — Overview (Exposure), Findings, FindingDetail, Connect, Configurations,
    PlatformTenants, Login, Components library.
  - `components/` — primitives, forms, feedback, overlays, disclosure, command palette.
  - `styles/tokens.css` — design tokens (light + dark).
  - `styles/legacy-bridge.css` — maps legacy app CSS variables onto the new tokens (phase-2 step 1).
  - `styles/components.css` — all component and page styles.
  - `DesignPreviewApp.test.tsx` — 14 tests pinning the behaviours the reference promises to keep.

## Hard constraint
Zero functional change: keep visible text, roles/accessible names, element types,
navigation targets, first-render visibility, and the class names existing tests read.
Full rules in `src/design-preview/README.md`.

## Decisions made
- Design direction: Inter + JetBrains Mono, flat surfaces with 1px borders, one indigo
  accent, four severity hues, 6/8/12px radii, dark theme default (matches App.tsx).
- Command palette, sidebar collapse and toasts are in the reference but are *new
  behaviour*: they need explicit approval before shipping.
- Overview is the risk-metrics page only (per root CLAUDE.md rule).
- No invented data: trend sparklines and deltas only where the page has real series.
- Coverage floors in the live app were not raised by the reference; coverage must never go down.

## Known gaps / not yet done
- Runs standalone from this folder (own `package.json`, `vite.config.ts`, `tsconfig.json`,
  `vitest.config.ts`, `src/test-setup.ts`, `public/favicon.svg`).
  - Install with `npm install --legacy-peer-deps` (npm 10.9.2 fails on a peer-dep
    resolution bug without this flag).
  - Run with `npm run dev`, then open http://127.0.0.1:5174/design-preview.html.
  - Tests: `npm test` (14 pass). Typecheck: `npm run typecheck`.
- Mock data in `src/design-preview/data.ts` is fake; it is shaped like the real DTOs but
  is not connected to the API.
- Not every live route is mocked (Inventory, AI Grid, Vulnerability Repository, Campaigns,
  EOL, Admin, etc.). `#/x/<path>` shows which pattern to use for each.
- Legacy-bridge migration has not been applied to the app.
- Three lint warnings in the live app (`GithubPipelineManager.tsx`, `PageFreshnessStatus.tsx`,
  `ConfigurationsPage.tsx`) are pre-existing and unrelated to this work.

## Setup files added after the first copy
The first copy had only the HTML and source, so the page showed nothing. The setup files above
were added to make it runnable.

## Source location
Built from `prototype-app/frontend` on branch `codex/application-prerequisite-fixes`.
The prototype app itself was not modified by this copy step.
