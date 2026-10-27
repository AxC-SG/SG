# UI 2.0 cleanup check tools

Helper scripts used to qualify Steps 4 and 5 of the cleanup plan (`../CLEANUP_PLAN.md`). They are not part of the app or its CI. They live here, outside `frontend/`, so lint, typecheck and the builds never see them. Each script reads the e2e helpers in `prototype-app/frontend/e2e/` (fixtures, deterministic browser setup, artifact server), so run `npm run e2e:build` first.

Put every output in a scratch folder, never in the repo. The probe outputs are about 23 MB each.

| Script | What it does |
|---|---|
| `host-gate.sh <label>` | Host half of the gate: lint, typecheck, `test:coverage` (saves `coverage-summary.json`), both builds with bundle sizes, `e2e:build`, `e2e:journeys`, the style probe for both versions, and the state check. Needs `GATE_WORK`; `GATE_BASELINE` is optional. Podman VM must be stopped. |
| `ctr-gate.sh <label>` | Container half: `e2e:visual` and `e2e:affected` (routes from `select-affected.mjs --base $AFFECTED_BASE`) in `mcr.microsoft.com/playwright:v1.63.0-noble`, on a `git archive` copy of HEAD. Needs `GATE_WORK` and `AFFECTED_BASE`, plus an npm cache filled on the host. |
| `style-probe.mjs <frontend> <ui2\|legacy> <out.json>` | Computed styles of the foundation targets, including `::before`/`::after` and hover/focus, on every e2e route × dark/light × 1280/390. Measured from a cold direct link, after a client-side navigation sequence that loads every lazy route sheet, and after Back. Also checks the `data-ui` boundary through `/demo`. |
| `probe-compare.mjs self <probe.json>` / `diff <before> <after>` | `self`: cold link vs navigation vs Back within one run, plus the boundary sequences. `diff`: one run against another. |
| `state-check.mjs <frontend> <artifact dir> <port> <out.json>` | Sub-navigation hover (every expanded group) and the modal scrims (`.modal-backdrop`, `.fd3-modal-overlay`, `dialog.confirm-dialog::backdrop`), which the probe does not reach. Compare two outputs with `cmp`. |
| `cascade-map.mjs <frontend> <out.json>` | Static map of which rule wins per (subject, property) against the foundation sheets, in effective load order. Step-4 specific; see its header. |
| `height-diag.mjs` | Finds the element and style behind a cold-vs-navigation difference. |
| `rollback-rehearsal.mjs` | Rollback rehearsal with the frozen UI 1 archive (see its header): checks the sha256 and manifest, serves the archive as is, and answers its production API base from the local backend. Every other host is blocked and counted. |
| `ui-attr.mjs` | Prints `data-ui` on a few routes of a served artifact. A UI 1 build must print null. |
| `perf-compare.mjs <frontend> <out.json> <label>=<dir> ...` | Runtime load comparison of builds on fixture routes: median DOMContentLoaded, load, LCP and transferred JS/CSS bytes over cold loads. Run an A/A pair (the same build twice) to see the noise floor, and run on a quiet machine. |
| `keyboard-zoom.mjs <frontend> <ui2\|legacy> <out.json>` | Automated aid for the keyboard and 200% zoom review: Tab stops with on-screen and focus-indicator checks, and overflow at 640×450 CSS px with 2× pixel density. Not a substitute for the human review. |

Known limits:
- The probe measures up to 4 elements per selector and a fixed property list. It is a regression net, not a full visual review.
- Height-only differences between cold and navigation come from lazily loaded `findings-list.css` (see the ledger, S4 `findingsForLaterSteps`).
