# UI 2 styles, browser gates and rollback

Updated October 28, 2026. UI 2.0 is the only application presentation. New development follows [the UI development standard](ui-development-standard.md), including approval for changes to shared patterns. The implementation and the limits of recorded qualification are in [CURRENT_STATE.md](<../Working Knowledge/New UI 2.0/CURRENT_STATE.md>).

## Stylesheet ownership and order

`src/main.tsx` imports `src/styles/index.css` once. Pages and components do not import application CSS. The exact order is:

```text
styles/index.css
  existing public Google Fonts import
  public-tokens.css
  public-before.css
  public.css
  public-after.css
  ui2/index.css
    tokens.css
    app-base.css
    shell.css
    primitives.css
    experience-base.css
    inventory-base.css
    findings-base.css
    cve-base.css
    governance-base.css
    connect-base.css
    findings.css
    cve.css
    inventory.css
    governance.css
    connect.css
    experience.css
    tables.css
    @xyflow/react/dist/style.css
```

| Owner | Responsibility and scope |
|---|---|
| `public-tokens.css`, `public-before.css`, `public-after.css` | Public defaults scoped outside `data-ui='2'`, retaining the shared defaults' original cascade positions. Public body/shell light palettes remain explicit even with a saved dark theme. |
| `public.css` | Public marketing/blog/demo markup, including markup reused by auth entry pages; it is not uniformly route-prefixed. Its shared auth defaults are adapted within the app scope in `ui2/app-base.css`. Do not treat it as a new app component library. |
| `ui2/tokens.css` | Canonical `--dp-*` light/dark tokens on `html[data-ui='2']`, including reduced-motion durations |
| `ui2/app-base.css` | Shared app layout/reset and controls behind zero-weight `:where(html[data-ui='2'])`; includes scoped auth-entry adaptations |
| `ui2/shell.css`, `primitives.css` | Shared shell, buttons, forms, cards, feedback, badges, overlays and keyboard focus behind the app boundary |
| `ui2/*-base.css` | Family-owned shared defaults behind the zero-weight app boundary, preserving existing specificity and cross-family consumers |
| `ui2/findings.css` | Vulnerability/AI Findings, detail and exposure presentation |
| `ui2/cve.css` | Intelligence, assessment/workbench, assets and software presentation |
| `ui2/inventory.css` | Inventory, lifecycle, quality, AI asset/declared-resource and relationship presentation |
| `ui2/governance.css` | Tenant/platform policies, administration and platform console presentation |
| `ui2/connect.css` | Connector catalog/forms, runs and configuration presentation |
| `ui2/experience.css` | Dashboards, campaigns, operations and auth-entry presentation |
| `ui2/tables.css` | Eager shared table and column controls; follows family presentation |
| XYFlow vendor CSS | Unmodified package styles, explicitly imported last; preserve graph checks when changing precedence |

`ui2/scope.test.ts` checks application scoping, family ownership, eager imports, public token isolation, retired files/aliases, semantic colors and focus rules. It does not replace browser tests of the cascade.

## Route and theme boundary

`src/lib/presentationBoundary.ts` applies `data-ui="2"` outside `/demo` and its descendants on initial load. `src/app/PresentationBoundary.tsx` reapplies it before paint on client links and browser Back/Forward. Login, setup and invitation routes retain UI 2.0. This is a presentation boundary, not an authorization or feature flag.

`AppShell` in `App.tsx` owns the mounted app theme, persists `scoutai-theme` and defaults to dark without a valid preference. The initial boundary restores a saved light/dark choice without overwriting an existing root theme. Keep the public light canvas/local palette intentional; shared auth markup must remain readable in both app themes.

The version switch, `VITE_UI_VERSION`, `uiVersion.ts`, `legacy-bridge.css`, compatibility aliases and legacy page stylesheet imports are removed. Do not reintroduce them for new development.

## Tokens and fonts

Use canonical `--dp-*` tokens in new app rules and extend their definitions centrally when necessary. Colors, semantic tones, spacing, radius, shadows, typography, controls and durations should follow the shared scale. Existing inherited literal geometry and component-owned dynamic variables are not a second token API. No app compatibility aliases remain; public-scoped old variables still serve the public site.

The app declares Inter/system and JetBrains Mono/monospace stacks in `tokens.css`; those declarations do not bundle font files. The root entry retains the original public Google Fonts import for Space Grotesk/IBM Plex Sans. Fixture browser runs answer that request from pinned `@fontsource` dev packages. Production font availability depends on the deployed CSP, so do not add a remote app font dependency or assume fixture fonts prove production font delivery.

## Browser gates

Run commands from `prototype-app/frontend` after `npm ci`. All current candidate checks run UI 2 only; legacy baselines remain historical. Build the current source with `e2e:build` before journeys, visual, affected or sweep runs.

| Command | Purpose |
|---|---|
| `npm run lint`, `npm run typecheck`, `npm run build`, `npm run test:coverage` | Frontend quality gates; build includes the production credential/bundle guard |
| `npm run e2e:build` | Build `e2e/.artifacts/ui2` and verify direct/link/history/public-style presentation boundaries |
| `npm run e2e:journeys` | Six fixture-backed family journeys; any new failed check causes failure |
| `npm run e2e:visual` | Screenshots against `e2e/visual-baselines/ui2/` in both themes |
| `node e2e/select-affected.mjs --base <git-ref>` | Map presentation changes to routes; outputs a route list, `NONE`, or `FULL_SWEEP` |
| `npm run e2e:affected -- --routes /findings,/login` | Selected routes at 390/1280px, both themes, visual and axe comparison |
| `npm run e2e:sweep -- --widths 390,768,1280,1440` | Four-width route sweeps in both themes, then the representative axe audit/comparison (audit defaults to 1280/390px) |
| `npm run e2e:update` | Rewrites UI 2 visual, journey and axe baselines after producing visual differences; inspect all changed evidence before accepting |
| `npm run e2e:live -- --base <local-frontend-url> --out <scratch-dir>` | Real-backend journeys using `LIVE_CREDENTIALS` and optional `LIVE_PLATFORM_CREDENTIALS` JSON files outside the repo; approved disposable data required |
| `npm run e2e:verify-archive -- <manifest-path>` | Verify an archive and all its files in scratch; defaults to the P0 source manifest |

Visual/affected/update runs require `mcr.microsoft.com/playwright:v1.63.0-noble`, matching exact-pinned `@playwright/test` 1.63.0. `E2E_PLAYWRIGHT_IMAGE` must name the image and the runner checks `/ms-playwright`; setting the variable alone is insufficient. Keep screenshot tolerance (`maxDiffPixelRatio: 0.001`), assertions and coverage floors. No baseline refresh solely to turn an unexplained failure green.

Fixtures use fixed time, locale `en-US`, timezone `UTC`, reduced motion and blocked nonlocal requests; they reject unexpected API requests. Axe comparisons key violations by route/theme/rule/element. Existing baselines can contain known failures: a passing comparison means no new regression relative to that baseline, not zero accessibility defects. Missing data/accounts remain pending scenarios, never passes.

`.github/workflows/quality.yml` runs the quality and browser gates; `frontend-e2e-sweep.yml` runs the scheduled/on-demand full sweep. Unknown presentation files select `FULL_SWEEP`, never zero routes. Add new routes and presentation ownership to `e2e/routes.mjs` and `affected-routes.json` with the screen. Live journeys are separate from default CI.

## Retained archives

In `Working Knowledge/New UI 2.0/checkpoints/`:

| Archive | Purpose | SHA-256 |
|---|---|---|
| `P0-baseline-frontend-src.tar.gz` | Previous frontend source, 320 manifest entries; historical baseline rather than the qualified rollback build | `487865af537e764fbeb1e3ed701913f48214a9f88c775275ece4c57d56b13fe1` |
| `UI1-frozen-a3f1d1db.tar.gz` | Frozen Step 5 UI 1 build, 86 manifest entries; legacy comparison and rollback artifact | `f040137d4956b5bcc68133b89b2eb1f28136a456561a76f7236200352c81a707` |

Each retains its `.sha256` and per-file `-manifest.json`. Verify P0 with `npm run e2e:verify-archive`; verify the frozen artifact with:

```bash
npm run e2e:verify-archive -- "../Working Knowledge/New UI 2.0/checkpoints/UI1-frozen-a3f1d1db-manifest.json"
```

## Rollback

1. Verify the frozen UI 1 archive and all manifest files using the command above. If integrity fails, stop before serving it.
2. Extract into a new scratch directory and use its built `dist/` unchanged. Its baked API base is `https://api.scoutgrid.io/api`; a local rehearsal must route that to the approved local backend and block other hosts, as `tools/rollback-rehearsal.mjs` does.
3. Under separate release/deployment authorization, replace the frontend artifact with the verified frozen build. The presentation change does not call for a database reset or migration. Requalify compatibility against the current API/auth/data first; the artifact's historical rehearsal is not proof of compatibility after future backend changes.
4. Do not rebuild UI 1 from current source or switch an environment variable. For source investigation, extract P0 in isolation or inspect commit `a3f1d1db`; restoring P0 over the current frontend is not the qualified artifact rollback.
5. Keep both archives, manifests/checksums, decision provenance and the rehearsal tool until the release owner explicitly closes the rollback window.
