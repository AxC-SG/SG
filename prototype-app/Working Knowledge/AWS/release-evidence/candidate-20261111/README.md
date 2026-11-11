# Standard Part 1 and dependency consolidation — November 11, 2026

This candidate combines the prepared frontend/lab repair with all eight open dependency PRs (#59–#66) against `cd741250faf4a098d1519f073f7e38a0f503016e`. Each original PR tip is preserved as an ancestor; `consolidated-prs.json` records the exact inputs. The owner will merge the single combined PR manually after its checks complete.

## Resulting behavior

The frontend repair corrects the public logo accessible name, reuses theme tokens for contrast, waits for rendered content in browser checks and refreshes the 22 previously reviewed stale screenshots. Existing accessibility/journey baselines and screenshot tolerances remain unchanged.

The disposable lab can use one NAT while retaining two-AZ private task/database boundaries. Production requires zonal NATs. The live-tested RDS TLS parameter apply method is retained. Formatting, locked-provider validation and Standard/network mocks are mandatory offline Quality checks, without AWS credentials.

The combined dependencies are Maven/Temurin 26 for container builds, Temurin 25 for runtime, setup-java 6.2.0, Vitest and its coverage provider 5.1.0, Playwright 1.65.0, Sentry React 11.11.0, Dagre 3.1.3 and Vite 8.3.6. Java compilation still targets 17. Backend unit, PostgreSQL and performance workflows test Java 25 to match the new runtime. The Playwright container is updated to the verified official 1.65.0 image digest. SpotBugs Maven plugin 4.10.4.1 replaces the Java-25-incompatible analyzer while retaining Max effort, High threshold and fail-on-error. The XML traversal test now constructs its 10,000-level DOM directly and separately checks parsing below the runtime depth limit; no parser limits are relaxed. Sentry 11 uses explicit disabled data-collection categories and the existing allowlist scrubbers; privacy tests preserve this behavior.

## Evidence and validation

The earlier frontend repair passed lint/typecheck/build, 1,159 unit tests, 823 journey assertions, 172 visuals and 780 route checks with zero new accessibility regressions. Those results describe the pre-upgrade source and do not qualify the new dependencies or browser. Fresh combined-candidate checks are required.

Local preparation passed 18 Standard and two network mocks with Terraform 1.13.5 and AWS provider 6.64.0, six CI contracts, five browser runner contracts, one Maven report test and seven certification harness tests. Fresh combined frontend verification and GitHub Quality, Trivy, Semgrep, Performance Governance and full Frontend E2E Sweep results must be reviewed for the final branch SHA. The source manifest records the implementation hashes at preparation; it does not certify CI success.

The Playwright upgrade changed Chromium 153 to 158. All 58 failing screenshot cases were compared with the unchanged previous application build in the new browser, and their before/after/diff sheets were reviewed. Findings table width changes reproduced with identical prior build bytes. The refreshed 58 snapshots retain the same controls and content; 114 other candidate snapshots remain byte-identical. Screenshot tolerance remains 0.001, and accessibility/journey baselines are unchanged. The exact comparison and update hashes are in `browser-comparison.json` and `browser-snapshot-review.json`. This is automated visual/source review, not a new human design approval.

## Release boundary

This PR neither deploys AWS resources nor enables the GitHub OIDC publisher. Keep `github_publisher = null`. A merge still requires the owner's manual decision. Successful main-push workflows and a newly retained scanned backend archive are needed for the resulting main SHA. Independent candidate approval, live certificate/DNS and secret references, scoped operator access, and bounded lab budget/cleanup approval remain live-release requirements. Capacity, recovery and production cutover gates remain open.
