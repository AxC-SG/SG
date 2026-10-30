# Security checks on the current GitHub plan

As of October 28, 2026, CodeQL default setup analyzes Actions, Python, JavaScript/TypeScript and Java/Kotlin. Successful analyses were observed on the CI reliability PR, in addition to the initial setup run. Semgrep Community Edition remains a separate blocking check; its community rules complement CodeQL and are not assumed equivalent.

| Check | Enforcement | Evidence |
|---|---|---|
| Gitleaks CLI 8.30.1 | Fails on detected secrets or scanner errors; PR scans compare the base/head commit range, pushes compare before/after, and events without a base scan all history | Redacted SARIF Actions artifact, 14 days |
| Semgrep CE 1.182.0 | Community `p/ci` rules over backend Java and frontend source; `--error --strict` blocks findings and parser/configuration errors | JSON and SARIF Actions artifacts, 14 days |
| SpotBugs | Existing Maven verify gate; existing thresholds unchanged | Maven/CI output |
| Trivy filesystem and images | Existing CRITICAL vulnerability threshold and scoped ignore file unchanged; enforcement precedes report retention | Filesystem and backend/frontend image SARIF Actions artifacts, 14 days |

Gitleaks uses a pinned CLI binary with a checked-in SHA-256 verification, instead of the separately licensed organization action wrapper. Its existing `.gitleaks.toml` and `.gitleaksignore` remain in effect. The workflow needs no Gitleaks license or organization secret, including on Dependabot PRs. Reports are redacted; never publish raw credentials in logs or artifacts.

Semgrep downloads the public `p/ci` rule configuration; rule contents may evolve independently of the pinned engine. Metrics and version checks are disabled and no Semgrep account token is supplied. Source analysis runs on the CI runner. This is the selected community rule coverage, not an exhaustive security audit. Named type imports and escaped JSX ampersands avoid three parser errors without changing runtime behavior or displayed text. No source path exclusions or findings baseline were added for these errors.

SARIF reports are retained with `actions/upload-artifact` as Actions evidence independently of GitHub Security dashboard availability. This avoids a dashboard entitlement failure preventing the actual Trivy vulnerability gates from running. Artifact upload failure still fails the job. Docker image scans require a working CI Docker environment; local source scans do not certify image findings.

Require Quality, Semgrep SAST and Trivy Security Scan to pass on the current PR/main candidate, with Performance Governance where its workflow applies. Branch rules are enforceable only when supported by the organization's plan; otherwise maintainers must verify all jobs before merging. Do not bypass scanner failures, lower thresholds or add broad suppressions to obtain a green result.

CodeQL is managed through GitHub default setup. Qualify all four configured languages on an ordinary PR, then require CodeQL through the native code-scanning rule rather than generated Analyze status-check names. Re-check dashboard alerts and entitlement behavior when repository visibility or the GitHub plan changes.


## CI reliability and merge enforcement

The five stable required gates are Quality gate, Semgrep SAST gate, Trivy filesystem gate, Trivy images gate and Performance gate. Quality evaluates every expected job and rejects unexpected skips or cancellations. All PRs report a Performance gate, including an explicit not-applicable result. Conservative selection skips expensive application checks only for root README.md and Markdown under prototype-app/docs; pushes run full verification. Lightweight guards and security scans still run.

Trivy owns cached, locally loaded Docker builds and scans those same images; nothing is published. The dedicated ci-postgres-it Maven profile runs only PostgreSQL Failsafe tests. The ordinary backend job retains Surefire, the unchanged unit coverage floor and SpotBugs, and proves both migration test classes ran. Report validation rejects missing classes and skipped integration tests.

Performance Governance sets CERTIFICATION_STRICT=true. Enterprise certification defaults to strict, whereas standalone baseline, scorecard and correlation commands default to diagnostic mode. Strict certification rejects HTTP errors, auth skips, incomplete samples, malformed reports and missing required measurements; the public scorecard API remains diagnostic. Three serial samples are a regression smoke check, not a representative load certification. Missing Server-Timing headers remain visible diagnostics.

The scheduled sweep audits layouts and accessibility at 390/768/1280/1440px in both themes and runs the visual screenshot comparison. PRs run fixture journeys only. Screenshot tolerances and existing assertions are unchanged. Baseline updates require inspected browser evidence.

See [rollout evidence and remaining administrator steps](ci-reliability-rollout.md). Repository settings must not be considered enforced merely because workflow gates exist.

The main ruleset binds the five stable gates to the GitHub Actions app and requires CodeQL code-scanning results with error-level alerts and high/critical security alerts blocking merges. CodeQL default setup is managed in repository settings for Actions, Java/Kotlin, JavaScript/TypeScript and Python. Its native merge-protection limitations, including default-setup Dependabot PR exceptions, are documented by GitHub; Semgrep and both Trivy gates continue on those PRs. Gate renames must coordinate the workflow, ruleset and contract test in the same change before enforcement is updated.

## UI 2.0 regression gates (October 28, 2026)

UI 2.0 is the only current candidate. Quality's frontend job runs lint, typecheck, build (including the production credential/bundle guard) and coverage. Its `frontend-e2e` job uses `mcr.microsoft.com/playwright:v1.63.0-noble`, exact-pinned Playwright 1.63.0, Node 24 and two workers: artifact/boundary build and fixture journeys. Results are retained for 14 days. `frontend-e2e-sweep.yml` runs the four-width dark/light sweep, axe comparison and visual checks on schedule or dispatch; run `e2e:visual` or `e2e:affected` locally before merging presentation changes.

Keep visual, journey and axe baselines under review: a pass against an existing baseline does not mean zero known defects. `e2e:update` rewrites all three types and requires inspected differences, never reduced assertions or tolerance. Live-backend persistence, approved exceptions and release qualification remain separately evidenced. See [browser gate commands](ui2-styles-and-rollback.md#browser-gates) and [the UI development standard](ui-development-standard.md) for new-screen acceptance and approval for shared-pattern changes.
