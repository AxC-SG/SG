# Security checks on the current GitHub plan

As of October 21, 2026, SG uses scanners that can run for its private repository without a GitHub Code Security subscription. Semgrep Community Edition replaces the unavailable CodeQL check. This changes SAST coverage; it does not make Semgrep equivalent to CodeQL's interprocedural analysis or provide GitHub-native code-scanning alerts.

| Check | Enforcement | Evidence |
|---|---|---|
| Gitleaks CLI 8.30.1 | Fails on detected secrets or scanner errors; PR scans compare the base/head commit range, pushes compare before/after, and events without a base scan all history | Redacted SARIF Actions artifact, 14 days |
| Semgrep CE 1.182.0 | Community `p/ci` rules over backend Java and frontend source; `--error --strict` blocks findings and parser/configuration errors | JSON and SARIF Actions artifacts, 14 days |
| SpotBugs | Existing Maven verify gate; existing thresholds unchanged | Maven/CI output |
| Trivy filesystem and images | Existing CRITICAL vulnerability threshold and scoped ignore file unchanged; enforcement precedes report retention | Filesystem and backend/frontend image SARIF Actions artifacts, 14 days |

Gitleaks uses a pinned CLI binary with a checked-in SHA-256 verification, instead of the separately licensed organization action wrapper. Its existing `.gitleaks.toml` and `.gitleaksignore` remain in effect. The workflow needs no Gitleaks license or organization secret, including on Dependabot PRs. Reports are redacted; never publish raw credentials in logs or artifacts.

Semgrep downloads the public `p/ci` rule configuration; rule contents may evolve independently of the pinned engine. Metrics and version checks are disabled and no Semgrep account token is supplied. Source analysis runs on the CI runner. This is the selected community rule coverage, not an exhaustive security audit. Named type imports and escaped JSX ampersands avoid three parser errors without changing runtime behavior or displayed text. No source path exclusions or findings baseline were added for these errors.

SARIF reports are retained with `actions/upload-artifact` rather than sent to the unavailable GitHub Security dashboard. This avoids a dashboard entitlement failure preventing the actual Trivy vulnerability gates from running. Artifact upload failure still fails the job. Docker image scans require a working CI Docker environment; local source scans do not certify image findings.

Require Quality, Semgrep SAST and Trivy Security Scan to pass on the current PR/main candidate, with Performance Governance where its workflow applies. Branch rules are enforceable only when supported by the organization's plan; otherwise maintainers must verify all jobs before merging. Do not bypass scanner failures, lower thresholds or add broad suppressions to obtain a green result.

If Code Security is purchased later, add and qualify a licensed CodeQL workflow and SARIF dashboard uploads in a separately reviewed change. Purchasing a plan does not resolve existing dependency conflicts or validate a deployed environment.
