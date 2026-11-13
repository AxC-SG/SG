# Retained qualification and rollback tools

These six scripts are retained because final branch-tip qualification is still outstanding in the historical ledger and the rollback window is not recorded as closed. They are outside the shipped app and CI. Routine new-screen validation uses `frontend/e2e/` and [the UI development standard](../ui-development-standard.md).

All outputs belong in scratch directories. `<frontend>` is the absolute path to `prototype-app/frontend`; build current artifacts with `npm run e2e:build` there first. Install its pinned dependencies/browser before running tools. Personal paths from old ledgers are provenance, not portable inputs.

| Command (run with `node` from this directory) | Purpose and limits |
|---|---|
| `style-probe.mjs <frontend> ui2 <out.json> [--widths 1280,390]` | Computed foundation styles on fixture routes, both themes, cold/navigation/history and public boundary; samples a bounded element/property set |
| `probe-compare.mjs self <probe.json>` / `diff <before.json> <after.json>` | Compare cold/navigation/history within a run or source snapshots; classify differences before acceptance |
| `state-check.mjs <frontend> <artifact-dir> <port> <out.json>` | Navigation hover and overlay/scrim states outside the computed-style probe; inspect/compare outputs |
| `keyboard-zoom.mjs <frontend> ui2 <out.json>` | Automated focus/Tab aid and simulated zoom geometry; cannot replace real keyboard and browser 200% zoom review |
| `perf-compare.mjs <frontend> <out.json> <label>=<artifact-dir> ... [--runs 7]` | Cold fixture-load timing/size medians; run an A/A control to assess noise; outputs measurements, not a release decision |
| `rollback-rehearsal.mjs <frontend> <checkpoints-dir> UI1-frozen-a3f1d1db <empty-extract-dir> <out.json>` | Serve the checksum-checked frozen build against an approved local backend at 8080, blocking nonlocal hosts and mapping its baked production API base to local; requires `LIVE_CREDENTIALS` and `LIVE_PLATFORM_CREDENTIALS` JSON files outside the repo |

Current candidate checks use `ui2` only. Tools that accept `legacy` need a separately extracted, integrity-verified frozen artifact at the expected location; never rebuild UI 1 from current source. Verify both archive and manifest **before** invoking the rehearsal, using `frontend/e2e/verify-archive.mjs` as documented in [styles and rollback](../ui2-styles-and-rollback.md#retained-archives). The rehearsal expects an existing empty extraction directory and a prepared disposable local backend/tenant; it does not provision or reset databases.

The style/state/performance/keyboard tools report observations that require inspection; not every recorded issue produces a failing exit. Treat actual findings, missing coverage and historical accessibility failures explicitly. Use the maintained npm/CI gates for regression enforcement.

Removed tools: phase-specific host/container wrappers, static cascade mapping, height diagnosis and ad-hoc attribute printing. Their purposes are covered by the maintained build/scope/route/boundary/visual checks or were one-time retirement diagnostics. Historical tracked versions remain available in Git at `eedc8a0864cadf7c0cd0e55ec733f4637ff6622a`.
