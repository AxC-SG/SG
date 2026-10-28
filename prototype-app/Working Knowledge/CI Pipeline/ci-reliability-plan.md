# CI reliability implementation plan — revised after review

## Outcome and policy

Repair false-green certification before enforcing merges, then remove duplicated work and improve execution. Keep both frontend checks and all existing application assertions, coverage floors, screenshot tolerance, Semgrep enforcement and Trivy CRITICAL thresholds. CodeQL uses GitHub default setup, managed in repository settings, for Actions, Java/Kotlin, JavaScript/TypeScript and Python; native merge protection requires completed CodeQL results and blocks error-level alerts and high/critical security alerts.

Require PRs into main, five uniquely named gates bound to GitHub Actions, CodeQL scanning results and up-to-date branches. Require zero human approvals, no bypass actors and no merge queue. Accept the extra re-runs caused by main advancing as the cost of checking integration before merge. Main pushes run verification too. Remove unused master and merge-group triggers.

## Delivery sequence

1. Strict certification: enterprise commands default to strict, diagnostic commands default to non-strict; propagate the flag, validate positive iterations, every route sample, complete reports and required measurements. Keep the public scorecard API diagnostic. Preserve failure evidence and summaries. Audit all four accessibility widths.
2. Shared selection and stable gates: introduce one classifier before the gate relies on it; intentionally skip expensive suites for root README.md and documentation Markdown only. Backend/script/configuration inputs continue to trigger relevant certification. Treat step skips independently from required job outcomes. Reject missing results, failures, cancellations and undeclared job skips. Lock five gate names, GitHub Actions source binding and the native CodeQL policy with contract tests.
3. Remove duplicates: let Trivy build/load/scan each image once with separate cache scopes and retained image identities. Use a dedicated serial Failsafe profile; derive expected integration classes from source and reject missing/skipped XML evidence. Keep unit coverage and SpotBugs in ordinary verify and prove both migration tests ran without PostgreSQL. Run full visuals once and affected accessibility separately.
4. Runtime and operations: run at most two independent journey processes, each with separate browser/context/fixture state and output; share only the read-only artifact server. Keep updates serial. Pin maintained Node-24-native Actions and container digests, add updates/linting, explicit read-only permissions, PR cancellation, per-job timeouts and 14-day evidence retention including hidden browser results. Keep initial timeout caps until enough comparable measurements exist to estimate p95.
5. Separate baseline review commit: append only the inspected 768/1440 entries, preserve every existing 390/1280 entry and confirm on pinned Linux amd64 CI. Keep debt remediation and live release tests separate.

## Qualification and rollout

Exercise strict failures (all 20 routes returning 500, missing samples, auth skips, invalid reports and missing required measurements), valid diagnostic mode, gate failure/cancellation/skip cases, documentation-only selection and source-derived test execution. Repeat serial/concurrent journey verification with the same assertions and audit all four widths. Retain artifacts, including raw axe evidence; distinguish accepted baseline entries from new patterns.

Compare three representative runs with runner/runtime versions and warm/cold/unknown Docker and Maven cache labels. Separate ordinary application work from full harness qualification; do not infer p95 from three samples. Record exact head SHA, elapsed and runner-job minutes, counts and conclusions.

Qualify every gate and all configured CodeQL languages before activation. Export the existing ruleset, apply the reviewed main-only payload, verify the actual settings and demonstrate an incomplete candidate cannot merge. Never automatically weaken enforcement on failure: use a reviewed recovery payload, or an explicitly approved temporary Disabled state with manual checks and immediate restoration; do not assume Evaluate is available. See the rollout record and PR #27 for actual results.

## Boundaries

No deployment changes, accessibility remediation or live-backend browser rollout. Node 24 build configuration is included; the connected Vercel team exposes no project, so deployed hosting runtime alignment remains independently unverified.
