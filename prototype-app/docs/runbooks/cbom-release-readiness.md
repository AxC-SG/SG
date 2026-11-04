# CBOM Release Readiness

Status: deployment-ready after the gates below pass  
Scope: P0, Milestones 0a–5 application changes; runtime assurance collectors and external pipeline credentials remain separately gated by design.

## Implemented release surface

- V11: canonical, expiry-bounded suppression requests and legacy cutover.
- V12: reproducible assessments, validation issues, important-claim assurance, packaged tenant rules, and isolated asynchronous workers.
- V13: canonical target state and verification request/result fields; accepted evidence plus assessment provenance is required for verified resolution.
- V14: tenant-isolated declared/observed crypto relationships and bounded graph traversal.
- Customer UI: assessment provenance, validation, semantic diff, unsigned reports, suppression governance, verification workflow, effective rule package, and PQC readiness.
- Governance APIs: tenant-admin rule impact preview/update within immutable bounds, PQC prioritization, and authenticated internal CI gate evaluation.
- Ingestion protection: secret-bearing CBOM rejection before asset/source/BOM persistence.

## Build artifacts

```bash
cd backend
JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home mvn clean package

cd ../frontend
npm run build
```

The backend artifact is `backend/target/vulnwatch-backend-*.jar`; the frontend artifact is `frontend/dist/`. The backend Dockerfile can be built only after the Maven package succeeds. Image publication and environment deployment require the target registry, cluster/service, secrets, and change window supplied by the deployment owner.

## Required environment controls

- Deploy first with `APP_CBOM_ASSESSMENT_ENABLED=false` (Spring property `app.cbom.assessment.enabled`).
- Use Java 17 for build and runtime.
- Keep tenant migration service quarantine enabled for `DRIFTED` schemas.
- Do not expose `/governance/gates/evaluate` as an unauthenticated pipeline API. It is an internal tenant-role endpoint until a one-job correlation-token credential passes security review.
- Do not enable runtime assurance collectors; no outbound collector is part of this release.

## Go/no-go checklist

- Full backend test suite passes.
- Frontend unit suite, typecheck, production build, and production-bundle verifier pass.
- Packaged migration target reports tenant V14 and platform V9.
- Eligible tenant migration failures are zero; drifted tenants are quarantined.
- Legacy null-expiry CRYPTO suppression count is zero after cutover.
- Secret-bearing fixture is rejected before persistence.
- Canary assessment queue age remains under five minutes and does not consume SBOM executor capacity.
- Assessment, diff, report, verification, rule preview, PQC, internal gate, and bounded graph smoke tests pass for a canary tenant.
- No cross-tenant query or object-storage access succeeds in negative tests.

## Rollout and rollback

Follow [CBOM V11–V14 Deployment Runbook](cbom-v11-v12-deployment.md). Migrations are forward-only; recover with worker disablement and forward fixes. Never restore the legacy accept route. After canary stability, enable CBOM workers gradually and backfill active CBOM artifacts idempotently.
