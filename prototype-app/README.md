# VulnWatch Prototype

Last updated: 2026-10-28 (UI 2.0 documentation alignment)

VulnWatch is a Spring Boot + React prototype for SBOM ingestion, vulnerability intelligence ingestion, deterministic CPE-based correlation, and tenant-scoped finding projection and workflow.

## Documentation

| Document | Contents |
|----------|---------|
| [Architecture](docs/architecture.md) | System shape, data flow, security model, tech decisions |
| [Backend](docs/backend.md) | REST API reference, services, external integrations, config |
| [Business Logic Guide](docs/business-logic-guide.md) | Domain concepts, pipeline flows, finding lifecycle, EOL tracking |
| [Database](docs/database.md) | Schema design, table inventory, migration strategy |
| [Frontend](docs/frontend.md) | React app structure, routes, components, state management |
| [UI development standard](docs/ui-development-standard.md) | Required new-screen architecture, component reuse, consistency and approval for departures |
| [UI 2 styles and rollback](docs/ui2-styles-and-rollback.md) | CSS ownership/order, browser gates, presentation boundary and verified rollback artifacts |
| [UI 2.0 migration record](<Working Knowledge/New UI 2.0/README.md>) | Previous state, implemented plans, current state and retained evidence |

UI 2.0 is the only tenant/platform/auth presentation. Future screens extend the shared system; changes to shared patterns need user approval during development with pros/cons and an app-wide consistency plan. Public `/demo` content retains its intentional separate presentation boundary.

Current prerequisite contracts and local verification: [implementation closure](<Working Knowledge/AWS/AWS_APPLICATION_PREREQUISITES_IMPLEMENTATION_CLOSURE.md>). [Review handoff](<Working Knowledge/AWS/AWS_APPLICATION_PREREQUISITES_REVIEW_HANDOFF.md>) records the local P30 patch-form repair, exact commit/CI steps and environment qualification. The formal register remains open; nothing here authorizes deployment or shared-database changes.

## Quick Start

### Backend

Use a fresh disposable local PostgreSQL database for the reset baselines. From this `prototype-app` directory:

```bash
cd backend
cp .env.example .env.local
cp src/main/resources/application-local.example.yml src/main/resources/application-local.yml
# Configure private local DB values and generate signing/encryption secrets in .env.local.
# Never commit .env.local or application-local.yml.
mvn clean
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

`application.yml` imports `.env.local` in properties format. The copied local example declares `APP_ENVIRONMENT=local` and `APP_RUNTIME_ROLE=all` through Spring properties; without it both must be explicitly configured. LOCAL JWT login requires `APP_JWT_HMAC_SECRET` (at least 32 UTF-8 bytes) and `APP_JWT_LOCAL_ISSUER`; omit external issuer/JWK settings. Configure a generated AES-256 `APP_CREDENTIAL_ENCRYPTION_KEY` consistently for encrypted state. API-key/header compatibility is a separate explicit local choice, not a browser-login prerequisite. The local example does not enable header tenant selection.

The deployed runtime owns no migrations. For disposable local bootstrap/provisioning details, read [database control plane](docs/database.md#tenant-schema-control-plane); starting the API alone is not proof that tenant schemas/grants are ready. Do not apply the reset baselines to an existing shared database.

For GitHub SBOM/GHCR/GHSA, supply a scoped token through `GITHUB_API_TOKEN_FILE`, `backend/secrets/github-api-token` (gitignored), or `GITHUB_API_TOKEN`, in that order. Customer source credentials/explicit anonymous scope remain separate from platform feed credentials; ServiceNow cannot inherit platform/global credentials.

### Frontend

```bash
cd frontend
npm install
npm run dev    # dev server on port 5173
```

### Default Local URLs

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8080/api`
- Performance scorecard helper: `./scripts/performance-scorecard.sh`
- Baseline warmup helper: `./scripts/performance-baseline.sh`
- Correlation freshness helper: `./scripts/correlation-certification.sh`
- Full enterprise certification helper: `./scripts/enterprise-performance-certification.sh`

Declare `APP_RUNTIME_ROLE` explicitly: `api` suppresses background callbacks, `worker`/`all` permit eligible work, and `schema-migrator` suppresses ordinary jobs. Missing/invalid role or environment fails startup. Every source cron is UTC; effective topology, replicas and flags require [schedule qualification](<Working Knowledge/AWS/PHASE_3_SCHEDULE_MATRIX.md>).
Set `MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,info,prometheus` when running the performance and correlation certification scripts in environments where Prometheus exposure is not enabled by default.

Example enterprise certification pass:

```bash
cd prototype-app
BASE_URL=http://127.0.0.1:8080 \
API_KEY="${APP_API_KEY:?configure a private local key first}" \
CREATOR_KEY="${APP_CREATOR_KEY:?configure a private local creator key first}" \
SEED_DEMO_DATA=false \
FAIL_ON_NONCOMPLIANT=true \
./scripts/enterprise-performance-certification.sh
```

This orchestrates the baseline capture, correlation/freshness certification, and a final performance scorecard snapshot into one artifact directory.

For a one-command local or CI governance pass that can start the backend, wait for readiness, and emit the certification artifact set:

```bash
cd prototype-app
BASE_URL=http://127.0.0.1:8080 \
API_KEY="${APP_API_KEY:?configure a private local key first}" \
CREATOR_KEY="${APP_CREATOR_KEY:?configure a private local creator key first}" \
START_BACKEND=true \
SPRING_PROFILES_ACTIVE=local \
APP_ENVIRONMENT=test \
APP_RUNTIME_ROLE=all \
MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,info,prometheus \
sh ./scripts/run-performance-governance.sh
```

## Performance Governance

[Performance Governance](../.github/workflows/performance-governance.yml) is committed and runs on relevant PRs, a UTC schedule and manual dispatch. Quality, CodeQL and Trivy workflows also exist. Their presence is not a successful result for the dirty candidate; exact committed/merge-queue checks and image builds remain pending. The certification helpers above target a disposable local/test environment; do not point seed/write operations at a shared service without explicit authorization.

### Local and deployed authentication

The browser stores the login token in `localStorage` and sends Bearer authentication. Development-only static token/API/creator/header fallbacks exist in `frontend/src/api/client.ts`; a stored token takes precedence. The backend has no default API key. If explicitly enabled locally, an absent creator key gives all valid API-key callers compatibility owner authority. Deployed validation rejects API-key/creator/header fallback. Production frontend builds reject nonempty static auth inputs; use real login/session credentials rather than VITE secrets.

LOCAL mode uses ACTIVE DB users, bcrypt passwords and current stored grants/membership/support authority; shared localhost login is disabled unless explicitly configured, with no built-in shared password. EXTERNAL mode requires issuer/audience/access-token validation and disables local issuance. Human role claims cannot create global grants; tenant roles are limited to the four customer roles. Machine JWTs need an active same-tenant registry entry for their verified subject. See [auth contracts](docs/backend.md#authentication).

### Platform-owner bootstrap boundary

Application-startup owner seeding is local/test only and rejected in a deployed runtime. Deployed platform/tenant migration, runtime grants and any explicitly enabled owner identity/setup-link operation belong to the separate `ProductionBootstrapCli` using privileged migration credentials. The permanent API uses only the restricted runtime identity. The [wrapper](backend/scripts/run-render-migration.sh) and [grant script](backend/scripts/provision-runtime-role.sql) are the operational sources; invoking them against a live target, sending setup email or rotating keys is outside this documentation task's authorization.

Tenant/demo invitations use hashed records, fragment links with POST exchange, and encrypted durable delivery intent. Retry/reconciliation preserves unknown provider outcomes; provider acceptance does not prove inbox delivery. See [delivery](docs/backend.md#durable-work-scheduling-and-delivery).

## Core Runtime Shape

| Component | Stack |
|-----------|-------|
| Frontend | React 18 + TypeScript + Vite |
| Backend | Java 17 + Spring Boot 3.5.16 + Spring Data JPA + Spring Security |
| Database | PostgreSQL, schema-per-tenant |
| Migrations | Independent platform/tenant Flyway lines; `ddl-auto=none` |

## Database Setup

Current packaged heads are **platform V8 / tenant V8**, with required tenant range V8–V8. Next versions are platform V9 / tenant V9. Preserve every applied migration; add the next version and update `MigrationCatalogTest`. `mvn clean` removes stale build resources, not database history. Startup/readiness checks shared work structures and grants; individual incompatible tenants remain blocked without taking compatible tenants offline.

The last observed deployed backend predates the development migration-history reset. Actual deployed histories are unverified. Fresh local V5→V6 checks do not establish deployed upgrade or rollback compatibility. Inspect actual histories read-only and rehearse an authorized representative-clone transition with backup/restore and candidate/rollback digests. Never reset a shared database, replay baselines over existing tables or use `flyway:repair` to disguise differing histories. See [release qualification](<Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).

## Capability scope

Generic Azure, local archive file operations, tenant OSV correlation, synthetic Fix Intelligence, runtime evidence, pilot generative assistance and destructive tenant purge remain unavailable. Static AWS/Azure/Copilot AI inventory and deterministic assessment are independently retained under roles, entitlements and provider controls. The deployed pilot requires ENFORCE and the named cohort; entitlement allow does not override containment.

Unsupported Patch Management cards and mock forms have been retired, including their input-logging handlers. Old connector query IDs and direct paths cannot mount them. Supported inventory/BOM and static AI connectors remain; generic Azure retains disabled/read-only status; SCCM/MECM is a live connector (SQL Server authentication, operator-approved hosts only). [Repair evidence](<Working Knowledge/AWS/DOCUMENTATION_RECONCILIATION.md#p30-frontend-repair>) records the new regressions and local verification.

## Tests

```bash
# Backend
cd backend
mvn test                          # unit tests + JaCoCo
mvn -Ppostgres-it verify          # unit + Postgres integration tests

# Frontend
cd frontend
npm run lint && npm run typecheck && npm run test:coverage
```

## CI Gates

Backend: `mvn -q verify` — Surefire units + JaCoCo coverage floor + SpotBugs. `mvn -Ppostgres-it verify` additionally runs the PostgreSQL Failsafe integration gate (the default profile does not execute those cases).

Frontend: `npm run lint` → `npm run typecheck` → `npm run build` → `npm run test:coverage`.

Browser CI additionally builds the UI 2 artifact, runs fixture journeys, visual tests and affected-route/axe checks in the pinned Playwright image. The scheduled workflow runs the full responsive sweep. Live-backend and release qualification remain separately evidenced; see the browser gate guide above.
