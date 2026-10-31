# UI 2.0 wiring fixes — 30 October 2026

The gaps from the [initial audit](ui2-backend-wiring-verification-2026-10-30.md) have been repaired in the local working tree and local backend. Existing unrelated UI changes were preserved. Nothing was deployed to a shared environment.

## Changes

| Gap | Repair | Regression evidence |
| --- | --- | --- |
| Unconfigured AWS Bedrock returns an empty successful response and hides setup | The controller explicitly returns JSON `null` with `application/json`. Configured responses retain their fields; entitlement checks still run. | MockMvc tests for both response states; a page test through the actual fetch/request helper; browser assertions that initial setup is usable |
| Tenant Operations routes request forbidden platform APIs | Non-owner tenant users visiting pipeline or platform health redirect to Exposure before the Operations page mounts. Tenant quality navigation and platform-owner access remain available. | Twelve role/route regression cases, plus browser tests for tenant redirects, absence of forbidden requests, and retained quality access |
| GitHub success count includes failed repositories | Saved-source and standalone repository completion paths use `repositoriesSucceeded` for `assetsIngested`. | Parameterized service tests exercise both public execution paths with nine attempted, two successful, seven failed repositories |
| Browser tests target old navigation | Home-route expectations use the current Exposure home. Live inventory checks follow host, software-identity, and declared-resource links. | Browser journey and real-backend interaction runs |
| Unused candidate methods target missing endpoints | Removed the two unused portfolio-candidate client methods and their unused type. | Type checking and static method/path inspection find no remaining unmatched frontend API call sites |

The AWS change is limited to its response contract. Unexpected non-JSON responses and actual read failures still surface as errors; no generic client error behavior was relaxed. Backend authorization rules were not changed.

## Local data and runtime

The backend retains `APP_RUNTIME_ROLE=all` so accepted jobs have a worker. It was restarted with the new code. The known completed GitHub sync run's erroneous historical `assetsIngested` value was corrected from nine to two, guarded by its exact ID, partial-success status, and original nine/seven counts. One row changed. No shared database migration or broad historical backfill was performed.

Live browser assertions confirm that AWS's absent configuration is HTTP 200 with body `null`, the setup form is enabled, and the GitHub run displays **Assets ingested: 2**. Its partial-success status, seven failures and 2,107 components remain recorded.

## Revalidation

- All **1,095 frontend tests** pass, including the new regressions. Coverage gates pass: lines 58.59%, statements 55.95%, functions 47.98%, branches 47.98%.
- All **42 targeted backend tests** pass, including two HTTP-response tests and both repository completion paths.
- Type checking, production build, production bundle checks, and 35 UI/public boundary browser checks pass.
- Lint passes with the same two pre-existing warnings.
- Static inspection matches all **436 frontend API call sites** to backend method/path mappings. The generic `post(path, body)` helper is resolved through its concrete callers.
- The real-backend route sweep covers **62 routes and 447 API responses**, with zero HTTP errors and zero JavaScript page errors. The AWS setup error is absent; tenant Operations routes finish at `/exposure`. The intentionally incomplete software-assets deep link still explains that a software identity is required.
- Read-only live interaction journeys pass **106/106 checks** across both themes, with two explicitly skipped declared-resource detail/history checks because the tenant has no declared resources.
- All **823/823 fixture browser checks** pass across all six suites: findings, CVE, inventory, governance, connectors, and experience. No failures were added to a baseline or suppressed.

Browser evidence: [AWS initial setup](verification/ui2-backend-2026-10-30/fixes/aws-setup.png) and [corrected SBOM result](verification/ui2-backend-2026-10-30/fixes/sbom-count.png).

## Review and limits

The main source changes are in:

- `backend/src/main/java/com/prototype/vulnwatch/aisecurity/controller/AiSecurityConnectorController.java`
- `backend/src/main/java/com/prototype/vulnwatch/service/GithubSbomSourceService.java`
- `frontend/src/App.tsx`
- `frontend/src/api/client.ts`
- `frontend/src/features/ai-security/types.ts`

The React review retained hook ordering, existing lazy route boundaries, and existing presentation components. No new UI state or shared styling pattern was introduced.

These results establish the repaired local behavior, not a claim that every external integration has been qualified. Real platform-owner credentials, provider success tests, full PostgreSQL integration suites and deployed-service verification remain outside the available evidence. Fixture-based policy and platform checks do not replace those live checks.

[Post-fix machine-readable evidence](verification/ui2-backend-2026-10-30/fixes/summary.json) records the final test counts, network observations and browser assertions. The initial audit's evidence remains unchanged.
