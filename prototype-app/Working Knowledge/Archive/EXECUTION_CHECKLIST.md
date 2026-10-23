# Fix Intelligence Platform - Weekly Execution Checklist

## Week 1: Test & Verify (Days 1-5)

### Day 1-2: Full Test Suite Run
- [ ] `mvn clean -Ppostgres-it verify` — all tests pass
- [ ] Check JaCoCo coverage: >80% line coverage
- [ ] SpotBugs scan: zero critical/high findings
- [ ] Gitleaks check: no secrets in git history
- **Owner:** Lead | **Target:** Green CI/CD by EOD Day 2

### Day 3-5: Connector Parsing Validation

**SCCM Connector:**
- [ ] SccmPatchConnector.parseJsonResponse() extracts 20+ fields
- [ ] Test null/missing field handling
- [ ] Test empty response (returns empty list, not error)
- [ ] Test date parsing (handles multiple formats)
- [ ] Unit test: testParseJsonResponse()

**BigFix Connector:**
- [ ] BigFixPatchConnector.parseJsonResponse() extracts query_results array
- [ ] Test nested structure (query_results[].title, query_results[].id)
- [ ] Test date field conversion to Instant
- [ ] Test missing fields gracefully (null, not NullPointerException)
- [ ] Unit test: testParseQueryResultsArray()

**Tanium Connector:**
- [ ] TaniumPatchConnector.parseGraphQLResponse() extracts data.patches.edges[].node
- [ ] Test GraphQL structure navigation (path traversal)
- [ ] Test supportedPlatforms array parsing
- [ ] Test date parsing with ISO format
- [ ] Unit test: testParseGraphQLResponse()

**Integration Testing:**
- [ ] Each connector returns VendorPatchData with all required fields
- [ ] Deduplication works (same patch from two sources = one Fix entity)
- [ ] AssetFixStatus created for each asset-patch pair

**Owner:** Backend | **Target:** 5 new unit tests, 100% pass rate by EOD Day 5

---

## Week 2: Performance & Security (Days 6-10)

### Day 6-7: Performance Testing

**Ingestion Performance:**
- [ ] Load 1000 patches for 100 assets in <30 seconds
  - Measure start time, end time, log duration
  - Break down: parsing (ms), normalization (ms), dedup (ms), save (ms)
  - Database query count (verify <1000 queries for 1000 patches = batch processing)
- [ ] Verify batch processing: patches saved in 100-patch batches
- [ ] Check connection pooling: active connections <10 (not exhausted)
- [ ] Verify no N+1 queries in asset correlation loop

**Dashboard Query Performance:**
- [ ] Coverage metrics query: <500ms response time (3 runs, average)
- [ ] Deployment drill-down (per-asset): <1s response time
- [ ] Dashboard overview (all sections): <2s response time

**Database Index Validation:**
- [ ] Index on `asset_fix_status(tenant_id, fix_id)` exists
- [ ] Index on `fixes(external_id, source_system)` exists
- [ ] Index on `asset_fix_status(deployment_status)` exists
- [ ] Query plan verified: full scans → index seeks

**Owner:** Database | **Deliverable:** Performance baseline doc (benchmarks, indexes verified)

### Day 8-10: Security Hardening

**Credential Encryption:**
- [ ] Verify credentials stored encrypted in DB (check: SELECT encrypted_secret FROM patch_connector_credentials;)
- [ ] Confirm decryption only during connector execution (audit logs show decrypt time = sync start)
- [ ] Audit trail: every credential access logged with timestamp, user_id, operation
- [ ] Test credential rotation (old cred disabled, new cred works)
- [ ] Credentials never appear in logs (grep all .log files for password-like strings = zero results)

**API Security:**
- [ ] All `/api/connectors/patches/*` endpoints require `X-API-Key` or Bearer token
- [ ] Multi-tenant isolation test:
  - Create patch1 for tenant1, patch2 for tenant2
  - Query as tenant1: see only patch1 ✓
  - Query as tenant2: see only patch2 ✓
  - Attempt cross-tenant query: 403 Forbidden ✓
- [ ] Header injection test: add extra headers, no side effects
- [ ] CSRF protection: POST without CSRF token → verify behavior

**RLS Policy Verification:**
- [ ] Query `asset_fix_status` as tenant1 user → returns only tenant1.asset_fix_status rows
- [ ] Directly execute SQL as tenant2 with `SET app.current_tenant_id = tenant1_uuid;` → RLS blocks query
- [ ] Verify `FORCE ROW LEVEL SECURITY` set on all tables in tenant schema
- [ ] Verify role cannot bypass RLS: `BYPASSRLS` not granted to runtime role

**Dependency Security:**
- [ ] Scan: `mvn dependency-check:check`
- [ ] Result: zero high/critical CVEs in dependencies
- [ ] If found: update to patched version or document accepted risk

**Owner:** Security | **Deliverable:** Security audit pass, RLS enforcement confirmed

---

## Week 3: Frontend & Dashboard (Days 11-15)

### Day 11-12: Dashboard Page Implementation

**Patch Dashboard** (`/patches/dashboard`):
- [ ] Coverage metrics section (total, deployed, pending, failed patches)
- [ ] Health score card (EXCELLENT/GOOD/FAIR/POOR + score 0-100)
- [ ] Top patches list (5 patches: title, ecosystem, severity, deployment %)
- [ ] Recent activity timeline (last 10 activities: deployed/failed/auto-resolved)
- [ ] Recommendations panel (actionable items: "Deploy to X assets", "Fix failed sync")

**Styling & Responsiveness:**
- [ ] Desktop: full layout, all elements visible
- [ ] Tablet: responsive cards, no overflow
- [ ] Mobile: stacked layout, touch-friendly

**Owner:** Frontend | **Target:** Page renders, all sections visible, responsive by EOD Day 12

### Day 13: Drill-Down & Configuration UI

**Deployment Drill-Down** (`/patches/{fixId}/deployment-status`):
- [ ] Asset table: asset name, status (DEPLOYED/PENDING/FAILED), deployed date
- [ ] Filters: by status, by ecosystem, search by asset name
- [ ] Sorting: by name, by status, by date

**Connector Configuration UI** (`/connect/patches`):
- [ ] List connectors: SCCM (status + last sync), BigFix, Tanium
- [ ] Test connection button (calls POST /api/connectors/{type}/test)
- [ ] Manual sync trigger button (calls POST /api/connectors/{type}/sync)
- [ ] Sync history: last 5 syncs with timestamp, status, patch count, error message (if failed)

**Owner:** Frontend | **Target:** Both pages complete by EOD Day 13

### Day 14: Integration with Finding Detail

**Finding Detail Page Updates:**
- [ ] If finding has associated fix:
  - Show "Fix Available" badge with KB/patch title
  - Show deployment status (deployed on 45/100 assets)
  - Link to patch deployment drill-down
  - Show auto-close reason if already resolved (e.g., "CVE resolved - patch deployed to all applicable assets")
- [ ] If no fix deployed: show "No remediation deployed" with link to patch

**Owner:** Frontend | **Target:** Integration complete by EOD Day 14

### Day 15: End-to-End Testing

**Browser Testing:**
- [ ] Chrome: all pages render, no errors in console
- [ ] Firefox: all pages render, no errors
- [ ] Safari: all pages render, no errors
- [ ] Mobile (iOS Safari): responsive, touch-friendly

**Performance:**
- [ ] Dashboard loads in <2 seconds (chrome devtools)
- [ ] Drill-down loads in <1 second
- [ ] Configuration page loads in <1 second

**Functionality:**
- [ ] Navigate: dashboard → drill-down → finding detail → back (no errors)
- [ ] Sync trigger: click → loading state → success message
- [ ] Filter/search: apply filters → results update without full page reload

**Owner:** QA | **Deliverable:** All pages verified in 3 browsers, responsive design confirmed by EOD Day 15

---

## Week 4: Hardening & Monitoring (Days 16-20)

### Day 16-17: Advanced Security

**Rate Limiting:**
- [ ] Patch ingestion endpoints: max 10 syncs/hour per connector per tenant
- [ ] Dashboard queries: max 100 requests/minute per user
- [ ] Verify: 11th request in same minute → 429 Too Many Requests

**Error Message Sanitization:**
- [ ] Database error in response: should NOT show SQL query or table name
- [ ] Credential error: should NOT show plaintext password
- [ ] Connector error: should NOT show internal IP address or port

**Logging & Audit:**
- [ ] All patch ingestion events logged: `{ tenant_id, user_id, timestamp, event_type, patch_count, status }`
- [ ] Failed connections logged: `{ tenant_id, connector_type, error_code, timestamp }` (NO password)
- [ ] Audit trail searchable: grep/ELK search by tenant_id, date range

**Owner:** Security | **Target:** Rate limiting enforced, errors sanitized, audit trail working by EOD Day 17

### Day 18-19: Monitoring & Alerting

**Micrometer Metrics:**
- [ ] `patch_ingestion_duration_seconds` (histogram, tags: connector_type, tenant_id)
- [ ] `patch_ingestion_total_patches` (counter)
- [ ] `patch_ingestion_errors_total` (counter, tags: error_type)
- [ ] `patch_deduplication_duplicates_found` (counter)
- [ ] `finding_auto_resolution_count` (counter)
- [ ] Metrics exported to: Prometheus / CloudWatch / DataDog (as configured)

**Health Check Endpoints:**
- [ ] `GET /actuator/health` → returns UP/DOWN
- [ ] `GET /actuator/health/custom` → connector status (last sync time, status for each)
- [ ] `GET /actuator/health/readiness` → ready for traffic (all checks pass)
- [ ] `GET /actuator/health/liveness` → process alive

**Alert Rules (Example using Prometheus):**
- [ ] Critical: `patch_ingestion_duration_seconds > 15min`
- [ ] Critical: `pg_stat_connections > 20` (connection pool exhausted)
- [ ] Warning: `patch_ingestion_errors_total increase > 0 in 1h`
- [ ] Warning: `api_request_duration_seconds{endpoint="/patches/dashboard"} > 5s`

**Owner:** DevOps | **Target:** Metrics flowing, health checks operational, alerts configured by EOD Day 19

### Day 20: Documentation

**Operator Runbook (`OPERATOR_RUNBOOK.md`):**
- [ ] Common issues: SCCM connection timeout, BigFix API error, Tanium auth failure
- [ ] Resolution for each: step-by-step (check firewall, verify credentials, review logs)
- [ ] Emergency procedures: how to pause sync, how to rollback
- [ ] Escalation: who to contact for each issue

**API Documentation (`API_DOCS.md`):**
- [ ] All `/api/connectors/patches/*` endpoints documented
- [ ] Example curl commands for each endpoint
- [ ] Request/response JSON examples
- [ ] Error codes (400, 401, 403, 500) and meanings

**Architecture Guide (`ARCHITECTURE.md`):**
- [ ] System diagram: connectors → orchestrator → normalize → dedup → store
- [ ] Multi-tenancy flow: tenant context → schema execution → RLS enforcement
- [ ] Data flow: patch in → Fix entity → AssetFixStatus → finding auto-resolve

**Owner:** Tech Writer | **Target:** All docs complete, reviewed by team, published by EOD Day 20

---

## Week 5: Final Validation & Go-Live (Days 21-25)

### Day 21-22: Staging Deployment

**Deployment Steps:**
- [ ] Build Docker image: `docker build -t vulnwatch-backend .`
- [ ] Test image locally: `docker run -e DB_URL=... vulnwatch-backend`
- [ ] Push to registry: `docker push registry.example.com/vulnwatch-backend:v1.0.0`
- [ ] Deploy to staging Kubernetes: `kubectl apply -f kubernetes/deployment-staging.yaml`
- [ ] Verify pods running: `kubectl get pods -n staging`
- [ ] Run smoke tests: connect to staging API, verify health check passes

**Staging Validation:**
- [ ] Create test tenant on staging
- [ ] Configure SCCM connector with staging credentials
- [ ] Trigger manual sync: should complete in <30 seconds
- [ ] Verify patches ingested: dashboard shows metrics
- [ ] Verify finding auto-resolution works
- [ ] Verify multi-tenant isolation (create 2nd tenant, confirm isolation)

**Owner:** DevOps / QA | **Target:** Staging deployment green, smoke tests pass by EOD Day 22

### Day 23: Load Testing

**Load Test Scenario:**
- [ ] 100 concurrent users querying dashboard
- [ ] Each user loads dashboard (100 parallel requests)
- [ ] Measure: response time (p50, p95, p99), error rate
- [ ] Target: p99 latency <5s, error rate <1%

**Load Test Tools:**
- Apache JMeter, Locust, or similar
- 5-minute sustained load test
- Capture: CPU %, memory %, DB query count

**Result:**
- [ ] If passes: proceed to production
- [ ] If fails: identify bottleneck (DB, app, network), optimize, retry

**Owner:** QA | **Target:** Load test results documented by EOD Day 23

### Day 24: Go/No-Go Decision

**Checklist:**
- [ ] All tests passing (unit, integration, performance, load)
- [ ] Security audit passed (encryption, RLS, auth)
- [ ] Documentation complete (runbook, API, architecture)
- [ ] Staging deployment validated
- [ ] Performance benchmarks met
- [ ] Monitoring and alerting operational

**Decision Meeting:**
- [ ] Product Manager: Feature set complete? ✓
- [ ] Engineering Lead: Code quality acceptable? ✓
- [ ] Security Lead: Security requirements met? ✓
- [ ] DevOps: Deployment ready? ✓
- **Outcome:** GO / NO-GO decision documented

**Owner:** Project Lead | **Target:** Decision by EOD Day 24

### Day 25: Production Deployment (if GO)

**Pre-Production Steps:**
- [ ] Database backup (full backup + verify restore works)
- [ ] Deployment runbook walkthrough (no surprises)
- [ ] Rollback procedure tested (can revert if needed)
- [ ] Monitoring dashboards opened (ready to watch metrics)
- [ ] Escalation contacts on-call

**Production Deployment:**
- [ ] Run database migrations: `mvn flyway:migrate` on production schema
- [ ] Verify migration success: check flyway_schema_history table
- [ ] Deploy application: `kubectl apply -f kubernetes/deployment-production.yaml`
- [ ] Monitor: health checks, error rates, latency for 30 minutes
- [ ] Verify: connectors can authenticate, patches ingesting
- [ ] Verify: findings auto-resolving correctly

**Post-Deployment:**
- [ ] Production metrics dashboard showing data
- [ ] No alert spikes (error rate, latency)
- [ ] User testing: real tenants accessing patches dashboard
- [ ] Documentation: update with actual production URLs, IP addresses

**Owner:** DevOps / Engineering Lead | **Target:** Production live by EOD Day 25

---

## Weekly Sign-Off

| Week | Lead | Start | End | Status |
|------|------|-------|-----|--------|
| Week 1 | Lead Eng | 2026-09-30 | 2026-10-04 | ⏳ Pending |
| Week 2 | Backend Eng | 2026-10-07 | 2026-10-11 | ⏳ Pending |
| Week 3 | Frontend Eng | 2026-10-14 | 2026-10-18 | ⏳ Pending |
| Week 4 | DevOps Eng | 2026-10-21 | 2026-10-25 | ⏳ Pending |
| Week 5 | Project Lead | 2026-10-28 | 2026-11-01 | ⏳ Pending |

---

## Escalation Contacts

- **Blocker on tests:** Lead Engineer
- **Performance issue:** Database Engineer
- **Security concern:** Security Engineer
- **Frontend issue:** Frontend Lead
- **Deployment issue:** DevOps Lead
- **Executive update:** Project Manager

---

## Notes

- Each day's deliverables should be validated by end of day (not left for "later review")
- Any blockers should be surfaced immediately (don't wait for weekly retro)
- Keep this checklist updated in real-time (mark items complete as they're done)
- Weekly retro: review what slipped, adjust priorities for next week
