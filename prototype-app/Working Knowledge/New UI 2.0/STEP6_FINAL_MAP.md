# Step 6 final slice — deterministic stylesheet and permanent route boundary

Starting commit: `0049451a` on the existing `feat/ui2-step6-retire-legacy` branch. The user explicitly authorized proceeding past checkpoint B on 2026-10-27. Checkpoint B remains evidence for its tested sources, not final qualification.

## Ownership captured before edits

`gate-final/cascade-before.json` was captured before application edits. `cascade-map.mjs` now supports `final` ownership and reads the final entry's imports recursively after retirement. Its after map records no lazy application sheets. Static overlap counts include mutually exclusive public/app selectors and are not browser failures.

| Previous source | Final ownership |
|---|---|
| `base.css` import wrapper | `styles/index.css`, imported only by `main.tsx` |
| `shared-before-public.css`, `shared-after-public.css`, `shared.css`, `cve-workbench.css`, `eol.css` | App defaults in `ui2/app-base.css`; public defaults in `public-before.css` and `public-after.css`, retaining their position around `public.css` |
| `public.css` shared auth markup | Original public presentation remains byte-identical; canonical-token defaults at the original position inside `ui2/app-base.css`, restricted to the Experience root or its descendants |
| `components/DataTable.css` | `ui2/tables.css`, eager after family presentation, retaining table control precedence |
| Lazy XYFlow vendor import | Explicit last import in `ui2/index.css`; package CSS unchanged |
| Empty family/page import stubs | Removed together with their imports |
| `ui2/legacy-bridge.css` and constant compatibility aliases in family sheets | App CSS and 31 inline consumers use their design tokens/expressions directly; bridge removed |
| `uiVersion.ts` / `UiVersionPresentation` | `presentationBoundary.ts` / `PresentationBoundary`, always app UI 2 outside `/demo` |

All remaining shared rules retain conditional contexts, selector specificity, declaration order, priorities and values. Zero-weight app/public scopes isolate shared defaults. Auth markup retains its original public defaults through a zero-weight Experience subject constraint, including pseudo-elements. The universal reset includes the document root. Public token values remain unchanged and now apply only outside the app boundary. App spacing preserves the old 4/8/12/16/24/32/40/48px values; it does not substitute the differently numbered design spacing scale. Added canonical 40px control, 16px radius, 40/48px spacing tokens preserve those values. App colour-scheme stays light/dark as before.

Component-local tone, impact and behavior-driven properties remain component-owned. No compatibility alias is retained by renaming the bridge or moving it into tokens. Shared `rise-in` becomes app-private `ui2-app-rise-in`; its public counterpart is preserved.

## Evidence and permanent checks

Scratch: `/private/tmp/sg-ui2-step6.QsSmLw/gate-final/`. The manifest records source ownership, alias substitutions and all 16 retired files. Independent static verification checks 5,863 rules / 23,652 declaration-selector pairs, 31 inline consumers, unchanged existing design tokens and byte-identical public presentation. It covers states and conditional rules without using reachability as a deletion criterion. This is not a browser, visual, axe or live pass.

Permanent tests retain family ownership, semantic colours, focus and shared-consumer assertions, updating retired-file checks to require actual absence. Boundary tests cover direct public/auth/app loads, real router links and browser Back/Forward in both themes while preserving `scoutai-theme`. Scope checks enforce one startup stylesheet import, app/public token isolation, eager shared controls and alias retirement. `e2e:build` retains all 15 direct routes and adds 20 theme/width link/history checks, including computed-public-style equivalence to direct load. Active CI was already UI 2 only; no workflow change is needed. Historical UI 1 baselines remain in the repository.

## Gate and limits

The post-commit fast gate passed on `6d4906fc6aaa28d1e5d78a75bba49064864e04c2`: lint 0 errors / 2 existing warnings; typecheck passed; Vitest **801 passed / 0 failed / 0 skipped**, 84 files including **35 scope tests**. Tested frontend tree `fc25b50ef295346291ce154d37641b2e8ab5f7d8`; application src tree `3faa6a35201678a56311e437d62735a1634e1b5e`. Subsequent evidence amendment changes only Working Knowledge documentation; these source trees remain unchanged. Step 6 is complete; Step 7 is next. No coverage floor, assertion, visual baseline or tolerance was lowered. The full final gate remains Step 8 after Step 7; it has not run on this source. The new browser checks are added for that qualification and CI, not claimed as executed in this fast slice.

Checkpoint B's CSS was 752338 raw / 96964 gzip bytes (+16.53% raw / +1.50% gzip against qualified Step 5). This slice duplicates the still-shared defaults behind separate public/app scopes and can increase CSS size. A fresh production bundle comparison is due at Step 8; do not present checkpoint B's size as this final slice's measurement.

All three original baseline files match `baseline/source.json` at original `68a4a3bc`; they remain unchanged. Podman was stopped; no competing checkout editor/test process or live SG service was found (idle app tool servers only). No backend/API/auth/tenant/schema/workflow changes, customer data, resets, external delivery, push, remote merge or deploy. The user's deletion and two untracked documents remain untouched. Accessibility review and unrelated defects remain open; staging/human review remain waived. The two outbound ServiceNow success scenarios remain skipped in checkpoint B evidence.

Reversal: revert only this final slice to restore the checkpoint B entry, aliases and rollout switch. Release rollback remains the checksum-verified frozen Step 5 UI 1 artifact, never a new UI 1 build.


First fast attempt on `cf215701`: lint 0 errors / 2 existing warnings; typecheck passed; Vitest 800 passed / 1 failed / 0 skipped. The new alias-retirement assertion correctly rejected 16 references to four never-defined executive `--color-*` properties in `experience-base.css`. Repository search confirmed there are no definitions; their literal fallback palette was preserved in four direct `--dp-exec-*` tokens, identical in both themes. The assertion was retained unchanged. Original logs are in `gate-final/attempt-1/`. Historical deleted paths also remain in the affected-route map so this retirement diff selects all routes instead of taking an unnecessary unknown-file full-sweep fallback.
