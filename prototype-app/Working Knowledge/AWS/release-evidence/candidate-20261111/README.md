# Standard Part 1 candidate — November 11, 2026

This candidate builds on `cd741250faf4a098d1519f073f7e38a0f503016e`. It combines the locally qualified frontend repair with the prepared Sydney lab network changes and an offline Terraform CI gate. It creates no AWS resources and does not close application, capacity, recovery or production release gates.

## Included changes

- Match the public logo's accessible name to its visible AI Security text, and use existing theme tokens for impact, investigation and selected-scope contrast.
- Wait for visible page content before browser captures, route inspection and accessibility audits. Wait for the existing expected journey states and use an exact Copilot Studio heading locator.
- Refresh the 22 reviewed public/auth and vulnerability-dashboard screenshots. Keep the other 150 screenshots, accessibility baseline, journey baseline and screenshot tolerance unchanged.
- Permit a single NAT for a disposable lab while retaining private task/database subnets across two AZs. The first input AZ owns the NAT. Production rejects this topology and retains zonal egress.
- Preserve the live-tested RDS TLS parameter's pending-reboot apply method. Add mocks for integrated runtime preparation, enrollment-secret removal and actual network routes.
- Make formatting, locked-provider validation and all Standard/network mocks mandatory in Quality CI. This job has no AWS identity or deployment step.

The source manifest records all 44 changed implementation/test files. The application, test, build and screenshot bytes match the previously qualified frontend tree in 751 files. The sole remaining manifest difference is `frontend/CLAUDE.md`, which retains the base commit's documentation. The workspace's unrelated changes, lab operator scripts, backend configuration files and state inputs are excluded.

## Local verification

The preceding frontend qualification ran in the pinned Linux/amd64 Playwright 1.63.0 image: lint/typecheck/build passed; 1,159 unit tests, 823 journey assertions, 172 visual comparisons and 780 route checks passed. The full four-width/two-theme accessibility comparison had zero new regressions against its unchanged baseline; known accessibility defects remain. These are local results for the matching frontend bytes, not new GitHub check results.

Candidate preparation rechecked Terraform formatting and validation with Terraform 1.13.5 and locked AWS provider 6.64.0. All 18 Standard and two network mocks passed. CI contracts (six), browser runner contracts (five), Maven report validation (one) and certification harness tests (seven) passed. Local provider IPC and the certification harness's localhost server required execution outside the filesystem sandbox; the Terraform tests used mocked AWS resources.

The React review found no new hooks, data fetching, authorization, component framework or shared UI pattern. The repair uses the existing design tokens and visible-label accessibility contract.

## Release boundary

Run Quality, Trivy, Semgrep and Performance Governance for the new candidate and run the full Frontend E2E Sweep. PR checks are review evidence; the publisher still requires successful main-push workflows and a newly retained scanned backend archive for the eventual exact main SHA. Results from the parent commit do not transfer.

Independent candidate approval is still required. Keep `github_publisher = null`. The next live application lab also requires verified certificate/DNS access, runtime/enrollment secret references, complete scoped operator access, and a bounded run and cleanup budget. Confirmed domains are `lab.scoutgrid.io` and `api-lab.scoutgrid.io`. Production remains a separate gate.
