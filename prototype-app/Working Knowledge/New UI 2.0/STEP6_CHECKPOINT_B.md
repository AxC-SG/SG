# Step 6 checkpoint B — in progress

Original baseline: `68a4a3bc`, checksum-verified in `/private/tmp/sg-ui2-step6.QsSmLw/baseline`. Candidate before the bar fix: `3c3e6695`.

- Host lint: 0 errors / 2 existing warnings; typecheck passed; coverage 787 passed / 0 failed / 0 skipped in 84 files, unchanged floors met. UI 2 build and 15-route boundary passed. Fixture journeys 737 passed / 0 failed / 0 skipped (67 Findings, 80 CVE, 106 Inventory, 166 Governance, 116 Connect, 202 Experience). Full probe/state still running.
- Live: 250 passed / 0 failed / 2 skipped (ServiceNow outbound delivery); backend unchanged, cwd verified, 7 JDBC connections to scout_ui2_qual, public Flyway V8, tenant ui2-qual-2 ACTIVE at V6. Credentials not printed. Live services stopped after the run.
- Container: native aarch64 Playwright v1.63.0-noble. Visual 130 passed / 10 failed / 0 skipped. Affected routes (all 35 since 68a4a3bc): same visual result; axe 883 current = 883 baseline, zero new or resolved.
- Visual diffs: all ten inspected. Shared Findings filters/widgets now load eagerly on CVE/Inventory routes. A focused comparison to starting UI 2 navigation confirms the AI Inventory styles match; it also caught a real Inventory status-bar colour priority regression. Explicit combined semantic/fill selectors restore the exact existing success/warning/muted values; no redesign. One Hosts light/390 diagnostic capture was incomplete after SPA navigation (59 versus 109 controls), so it requires a fixture-ready wait before comparison.
- No visual baselines or tolerances changed yet. No final version switch, bridge removal, push, merge or deploy.

Scratch logs: `gate-checkpoint-b/` and `gate-checkpoint-b-ctr/` under the same scratch root. The failed font-import build and sandbox port denial are retained separately in `gate-checkpoint-b-attempt-1/`. Current app CSS is larger: 752039 raw / 96916 gzip bytes versus Step 0 645010 / 95396 and Step 5 645193 / 95440. Repeated zero-specificity boundary scopes explain the raw increase; no UI 1 build was made.

Inventory colour fix fast gate: 788 passed / 0 failed / 0 skipped (32 scope tests), lint 0 errors / 2 existing warnings, typecheck passed. Corrected focused probe shows zero shared-control differences from starting UI 2 navigation on Hosts and AI Inventory in both themes/widths. CVE's remaining seven properties per case are the existing CVE-owned toolbar background/padding and consequent geometry, kept consistently instead of the later lazy Findings override.

The full host probe sampled old React pages after synchronous history changes; affected snapshots contain the preceding route's title/tabs and height. Two public observations were also taken before React committed /demo; UiVersionPresentation remains unchanged and uses useLayoutEffect before paint. The probe now waits for target route identity and settled requests, with all style/boundary assertions retained. Full rerun is required.

Probe-readiness repair fast gate: 788 passed / 0 failed / 0 skipped in 84 files (32 scope tests), lint 0 errors / 2 existing warnings, typecheck and Node syntax passed. All 240 cold/navigation/Back comparisons and 120 boundary sequences remain; route waits do not wait for matching style values or force the UI attribute.
