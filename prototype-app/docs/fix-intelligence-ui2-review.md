# Fix Intelligence UI 2 review — 28 October 2026

## Scope and resulting behavior

Reviewed All Fixes, Patches, Workarounds, Compensating Controls, imported/recommendation and analyst fix details, create/edit forms, and the embedded Remediation options panel.

The family now uses the UI 2 page canvas and header divider, token-based colors, labelled filters outside the table card, a result-count header, contained horizontal table scrolling, responsive metric/form grids, and theme-aware links. The severity distribution includes None and Unrated. Unavailable metrics use an em dash instead of a misleading zero. Summary, list, detail, asset-scope and embedded-context failures provide retry actions. Detail failures distinguish a 404 from a service failure. Empty catalogs and empty filtered results have distinct messages, and patch guidance refers to supported sources. Detail navigation has a direct All fixes destination. KB identifiers no longer gain a second KB prefix when a source already supplies it.

## All Fixes loading failure

The running local app at `localhost:5180` used `scout_ui2_qual`. The SG Internal account shown in the browser belongs to `tenant_default` (tenant `e5fe0d29-1d64-4175-8ce6-c34f42b214cc`). Its tenant Flyway history stopped at V6. Fix Intelligence needs the columns and tables introduced in V9, so both summary and list queries failed.

Applied the repository's pending V7, V8 and V9 migrations through Flyway with validation enabled, only to that existing local tenant. No baselines were reset and no histories were repaired. Updated that tenant's readiness version/checksum with the application's existing status service. The other local tenants were left unchanged. Live browser checks then showed four fixes, three critical fixes, four high-priority fixes and one ecosystem; all four list views and an existing fix detail loaded successfully.

The release already declares V9 as its required and maximum supported tenant schema, but service/config defaults still used V6 (and the directly constructed schema service initialized its maximum to V5). Defaults now agree on V9. Environment overrides still narrow compatibility, and pre-V9 tenants are not treated as compatible. The controller regression runs with schema-version enforcement enabled.

## Verification

- Frontend lint: passed with two existing warnings in PageFreshnessStatus and ConfigurationsPage.
- TypeScript and production build/bundle checks: passed.
- UI 2 boundary checks: passed on 15 direct routes and 20 public/history checks.
- Frontend coverage suite: 92 test files and 859 tests passed.
- Backend targeted unit and PostgreSQL controller tests: passed, including summary/list requests for every view and control authorization/approval behavior. PostgreSQL integration uses its disposable test database; local owner-bootstrap is explicitly disabled for that test invocation.
- Native fixture screenshots: 36 captures, six routes × two themes × three widths (1440, 768, 390), with zero runtime errors and zero document horizontal overflow.
- Axe: all six routes at 1280 and 390 pixels in both themes. The only reported rule is `nested-interactive`, targeting existing shared sidebar navigation buttons. The shared navigation structure was not changed in this task.

Local screenshot/audit evidence is in `frontend/output/playwright/fix-intelligence/`, including `fix-ui2-local_log.json` and `fix-ui2-local_axe.json`. These are fixture-based presentation checks. Authenticated live checks above were performed separately against the running local backend.

The pinned visual-baseline runner requires its Playwright Linux container and was unavailable on this host. Local native screenshots are review evidence, not a passing visual-baseline comparison; existing baselines were not rewritten.

## Reproduction commands

Run frontend commands from `prototype-app/frontend`:

```sh
npm run lint
npm run typecheck
npm run build
npm run test:coverage
npm run e2e:build
```

Run targeted backend checks from `prototype-app/backend`:

```sh
mvn -q -Dapp.security.bootstrap.platform-owners.enabled=false \
  -Dtest=FixIntelligenceQueryServiceTest,TenantSchemaServiceTest,PilotCapabilityPolicyTest \
  -Drun.postgres.it=true -DfailIfNoTests=false \
  -Dit.test=FixIntelligenceControllerPostgresIntegrationTest -Ppostgres-it \
  test-compile surefire:test failsafe:integration-test failsafe:verify
```

The local database repair is an environment operation, not an application-startup migration. Other environments require their normal authorized migration workflow before running this V9-dependent release.
