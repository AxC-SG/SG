# UI 2 styles, e2e and rollback

UI 2 is the only app presentation. The legacy stylesheets are retired; this page records who owns what and how to roll back.

## Stylesheet ownership

`src/styles/index.css` is the only stylesheet entry. Order matters (later wins at equal specificity):

| Sheet | Owns | Scope |
|---|---|---|
| `public-tokens.css`, `public-before.css`, `public.css`, `public-after.css` | Public marketing, blog and demo routes, plus shared defaults in their original order | `html:not([data-ui='2'])`, zero specificity via `:where()` |
| `ui2/tokens.css` | `--dp-*` design tokens, light and dark | `html[data-ui='2']` |
| `ui2/app-base.css`, `shell.css`, `primitives.css` | App layout, shell, shared controls (buttons, badges, forms, overlays, table frame) | `html[data-ui='2']` |
| `ui2/*-base.css` (experience, inventory, findings, cve, governance, connect) | Base class declarations shared across families, kept at their original specificity | `:where(html[data-ui='2'])` |
| `ui2/findings.css`, `cve.css`, `inventory.css`, `governance.css`, `connect.css`, `experience.css` | Family presentation, anchored on page roots (`.fpl-root`, `.fd3-page`, `.ui2-<family>-family`) | `html[data-ui='2']` |
| `ui2/tables.css` | Shared table presentation, loaded last | `html[data-ui='2']` |

The import order lives in `src/styles/ui2/index.css`. `ui2/scope.test.ts` fails if any app rule lacks the route boundary, so public routes stay isolated. The boundary itself is `src/lib/presentationBoundary.ts`: app and auth routes carry `data-ui="2"`, public routes never do.

## Tokens

- Use `var(--dp-*)` for every colour, spacing, radius, font and duration in app CSS. Do not hard-code hex values.
- Dark mode is the same token names redefined under the dark theme in `ui2/tokens.css`; never branch per component.
- Legacy token aliases remain in the `*-base.css` sheets so existing selectors keep their meaning. Do not add new alias uses.
- Do not import remote fonts in app CSS: the deployed CSP (`font-src 'self'`) blocks them (see the note in `ui2/tokens.css`).

## e2e commands (run in `prototype-app/frontend`)

| Command | Purpose |
|---|---|
| `npm run e2e:build` | Build the UI 2 candidate and check its route boundary |
| `npm run e2e:journeys` | Family journeys against fixtures |
| `npm run e2e:visual` | Visual snapshots (`e2e/visual-baselines/`) |
| `npm run e2e:affected -- --routes …` | Routes touched by a CSS change (`e2e/select-affected.mjs` picks them) |
| `npm run e2e:sweep` | Full route sweep, 4 widths, both themes |
| `npm run e2e:live` | Live-backend journeys |
| `npm run e2e:update` | Rewrite known-failure baselines; review the diff |
| `npm run e2e:verify-archive [-- manifest]` | Verify a checkpoint archive against its per-file manifest |

Per-slice gate: `npm run lint && npm run typecheck && npm run test:coverage`, then the journeys and visual runs.

Accessible control names must include their visible text. The account menu includes the workspace and role, exposure funnel stages include the count and supporting metric, and policy links retain the visible “Open policy” wording before the policy name. Axe-core 4.14 checks these through `label-content-name-mismatch`; run `npm run e2e:sweep -- --checks accessibility --widths 390,768,1280,1440` to compare both themes against the reviewed baseline.

## Checkpoint archives

`Working Knowledge/New UI 2.0/checkpoints/`:

- `P0-baseline-frontend-src.tar.gz` (+ `.sha256`, `-manifest.json` with path and sha256 per file): the pre-UI 2 frontend source. Check with `node e2e/verify-archive.mjs`.
- `UI1-frozen-a3f1d1db.tar.gz` (+ `.sha256`, `-manifest.json`): the frozen legacy build, the rollback artifact.

## Rollback

1. Take `UI1-frozen-a3f1d1db.tar.gz` and check it: `shasum -a 256 -c UI1-frozen-a3f1d1db.tar.gz.sha256` must pass (expected `f040137d4956b5bcc68133b89b2eb1f28136a456561a76f7236200352c81a707`).
2. Extract it; it contains the built `dist/`. Deploy that in place of the current build. No data, API or URL changes are involved.
3. Source rollback: restore the frontend from `P0-baseline-frontend-src.tar.gz` (verify first), or check out commit `a3f1d1db`, the source of the frozen legacy build.
4. Keep the frozen artifact until UI 2 is released, accepted and the rollback window is closed.
