# Week 2: Performance & Security Hardening

> Historical archive: endpoint, role and migration descriptions below may be obsolete. See [current implementation closure](../AWS/AWS_APPLICATION_PREREQUISITES_IMPLEMENTATION_CLOSURE.md). API-key examples require explicitly configured local development authentication; deployed environments use the current authentication contract.

**Timeline:** Oct 7 - Oct 11, 2026  
**Owner:** Backend Engineer + Security Engineer  
**Goal:** Achieve performance baseline + security audit pass

---

## Day 6-7: Performance Testing

### Task 1.1: Load Test Setup

**Goal:** Ingest 1000 patches for 100 assets in <30 seconds

**Load Test Scenario:**
```
Patches: 1000
Assets: 100
Deployment statuses: DEPLOYED (50%), PENDING (30%), FAILED (20%)
Expected duration: <30 seconds
Target P95 latency: <100ms per patch
Target P99 latency: <200ms per patch
```

**Test Data Generation:**
```bash
# Create test data generation script
cat > /tmp/generate-test-data.sql << 'EOF'
-- Generate 1000 test patches for performance testing
INSERT INTO platform.fixes (
  id, external_id, source_system, fix_type, title, description, 
  ecosystem, severity, effort, status, fixed_version, created_at
) SELECT 
  gen_random_uuid() as id,
  'KB-PERF-' || LPAD(x::text, 5, '0') as external_id,
  'SCCM' as source_system,
  'PATCH' as fix_type,
  'Performance Test Patch ' || x as title,
  'Test patch for performance validation' as description,
  'Windows' as ecosystem,
  CASE WHEN x % 4 = 0 THEN 'CRITICAL'
       WHEN x % 4 = 1 THEN 'HIGH'
       WHEN x % 4 = 2 THEN 'MEDIUM'
       ELSE 'LOW' END as severity,
  'LOW' as effort,
  'ACTIVE' as status,
  '1.0.' || x as fixed_version,
  NOW() as created_at
FROM generate_series(1, 1000) as x;

-- Create 100 test assets
INSERT INTO public.assets (id, name, asset_type, created_at) SELECT 
  gen_random_uuid() as id,
  'perf-asset-' || LPAD(x::text, 3, '0') as name,
  'Computer' as asset_type,
  NOW() as created_at
FROM generate_series(1, 100) as x;

-- Create asset_fix_status records (100,000 rows)
INSERT INTO tenant_default.asset_fix_status (
  id, tenant_id, asset_id, fix_id, deployment_status, source_system, created_at
) SELECT 
  gen_random_uuid() as id,
  '00000000-0000-0000-0000-000000000000'::uuid as tenant_id, -- default tenant
  assets.id,
  fixes.id,
  CASE WHEN random() < 0.5 THEN 'DEPLOYED'
       WHEN random() < 0.8 THEN 'PENDING'
       ELSE 'FAILED' END as deployment_status,
  'SCCM' as source_system,
  NOW() as created_at
FROM public.assets, platform.fixes
LIMIT 100000;
EOF

# Load test data
psql -U $USER -d vulnwatch -f /tmp/generate-test-data.sql
```

**Owner:** Database Engineer  
**Time:** 30 minutes  
**Deliverable:** 1000 patches + 100,000 asset_fix_status records

### Task 1.2: Execute Performance Test

**Test 1: Patch Ingestion Performance**
```bash
#!/bin/bash

# Measure patch ingestion time for 1000 patches
echo "Starting patch ingestion performance test..."

START_TIME=$(date +%s%N | cut -b1-13)

# Trigger ingestion via API
curl -X POST http://localhost:8080/api/connectors/SCCM/sync \
  -H "X-API-Key: test-key" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nStatus: %{http_code}\n"

# Wait for ingestion to complete
sleep 60  # Wait for async job to complete

END_TIME=$(date +%s%N | cut -b1-13)
DURATION=$((($END_TIME - $START_TIME) / 1000))

echo "Patch ingestion completed in $DURATION seconds"

# Target: <30 seconds
if [ $DURATION -lt 30000 ]; then
  echo "✓ PASS: Ingestion completed in $DURATION ms (<30s target)"
else
  echo "✗ FAIL: Ingestion took $DURATION ms (target: <30s)"
fi
```

**Expected Results:**
- Ingestion time: <30 seconds
- Throughput: >33 patches/second
- Memory usage: <500MB peak
- Database connections: <5 active

**Measurement Points:**
- Patch query time: ~1-2 seconds
- Normalization time: ~2-3 seconds
- Deduplication time: ~1-2 seconds
- Asset correlation time: ~3-5 seconds
- Save time: ~5-10 seconds
- Total: 15-25 seconds

**Owner:** Performance Engineer  
**Time:** 1 hour  
**Deliverable:** Performance test results

### Task 1.3: Dashboard Query Performance

**Test 2: Coverage Metrics Query**
```bash
#!/bin/bash

echo "Testing dashboard coverage metrics query..."

# Measure query latency (3 runs, take average)
for i in {1..3}; do
  time curl -s http://localhost:8080/api/connectors/patches/coverage/metrics \
    -H "X-API-Key: test-key" | jq . > /dev/null
done

# Target: <500ms per query
```

**Expected Results:**
- First run (cache miss): <500ms
- Subsequent runs: <100ms (if caching enabled)
- Query breakdown:
  - SELECT from asset_fix_status: <50ms
  - GROUP BY aggregations: <100ms
  - JSON formatting: <50ms

**Test 3: Deployment Drill-Down Query**
```bash
#!/bin/bash

echo "Testing deployment drill-down performance..."

# Get a fix ID first
FIX_ID=$(curl -s http://localhost:8080/api/connectors/patches \
  -H "X-API-Key: test-key" | jq -r '.[0].id')

# Measure drill-down latency
time curl -s "http://localhost:8080/api/connectors/patches/$FIX_ID/deployment-status" \
  -H "X-API-Key: test-key" | jq . > /dev/null

# Target: <1 second
```

**Expected Results:**
- Query latency: <1 second
- Result set size: <100 asset records (typical)
- Memory overhead: <10MB

**Test 4: Dashboard Overview Query**
```bash
#!/bin/bash

echo "Testing full dashboard overview..."

# Measure full dashboard load
time curl -s http://localhost:8080/api/patches/dashboard/overview \
  -H "X-API-Key: test-key" | jq . > /dev/null

# Target: <2 seconds
```

**Expected Results:**
- Total load time: <2 seconds
- Includes: coverage metrics, auto-resolution stats, health score, patches list, activity
- JSON response size: <1MB

**Owner:** Performance Engineer  
**Time:** 1 hour  
**Deliverable:** Dashboard performance baseline

### Task 1.4: Database Query Optimization

**Verify Batch Processing:**
```sql
-- Check query count during ingestion
SELECT 
  query,
  calls,
  mean_exec_time,
  max_exec_time
FROM pg_stat_statements
WHERE query LIKE '%patch%' OR query LIKE '%fix%'
ORDER BY calls DESC
LIMIT 10;
```

**Expected:** Batch inserts (100 patches per batch), not individual inserts (N+1 queries)

**Verify Indexes:**
```sql
-- Check if indexes exist
SELECT indexname FROM pg_indexes 
WHERE tablename = 'asset_fix_status' 
  AND (indexname LIKE '%tenant%' OR indexname LIKE '%fix%' OR indexname LIKE '%deployment%');

-- Expected indexes:
-- - asset_fix_status_tenant_fix_idx (tenant_id, fix_id)
-- - asset_fix_status_deployment_status_idx (deployment_status)
-- - asset_fix_status_tenant_id_idx (tenant_id)
```

**Verify Query Plans:**
```sql
-- Check query plan for coverage metrics (should use indexes)
EXPLAIN ANALYZE
SELECT deployment_status, COUNT(*) 
FROM tenant_default.asset_fix_status 
WHERE tenant_id = '...' 
GROUP BY deployment_status;

-- Expected: Index Scan (not Seq Scan), <50ms
```

**Owner:** Database Engineer  
**Time:** 1 hour  
**Deliverable:** Database query optimization report

---

## Day 8-10: Security Hardening

### Task 2.1: Credential Encryption Validation

**Goal:** Verify credentials stored encrypted, decryption only during execution

**Test 1: Verify Encrypted Storage**
```bash
#!/bin/bash

# Check database contains encrypted secret (not plaintext)
psql -U $USER -d vulnwatch -c "
SELECT connector_type, encrypted_secret 
FROM platform.patch_connector_credentials 
LIMIT 1;
" | head -20

# Verify: encrypted_secret should be long hex string, not readable text
# Should NOT see: password=xxx, api_token=xxx, or any readable credentials
```

**Expected:**
- Credentials stored as base64/hex encrypted blob
- Not readable as plaintext
- Length >100 characters for typical credentials

**Test 2: Verify Decryption Only During Execution**
```bash
#!/bin/bash

# Check application logs during sync
# Should NOT contain plaintext passwords/tokens

mvn spring-boot:run -Dspring-boot.run.profiles=local > /tmp/app.log 2>&1 &
APP_PID=$!
sleep 5

# Trigger sync
curl -X POST http://localhost:8080/api/connectors/SCCM/sync \
  -H "X-API-Key: test-key"

sleep 30

# Kill app and check logs
kill $APP_PID
sleep 2

# Search for exposed credentials
grep -i "password\|token\|secret\|credential" /tmp/app.log | grep -v "^#" | grep -v "Configuration"

# Expected output: EMPTY (no credentials in logs)
# If any matches found: SECURITY ISSUE
```

**Owner:** Security Engineer  
**Time:** 1 hour  
**Deliverable:** Credential encryption audit pass

### Task 2.2: Multi-Tenant Isolation Verification

**Goal:** Verify tenant_id filters on all queries, RLS enforcement

**Test 1: API Endpoint Multi-Tenant Isolation**
```bash
#!/bin/bash

# Create two test tenants
TENANT1="11111111-1111-1111-1111-111111111111"
TENANT2="22222222-2222-2222-2222-222222222222"

# Add patches for tenant1
curl -X POST http://localhost:8080/api/connectors/patches/coverage/metrics \
  -H "X-API-Key: test-key" \
  -H "X-Tenant-ID: $TENANT1"

# Query as tenant1 (should see patches)
RESULT1=$(curl -s http://localhost:8080/api/connectors/patches/coverage/metrics \
  -H "X-API-Key: test-key" \
  -H "X-Tenant-ID: $TENANT1" | jq '.totalPatches')

echo "Tenant1 sees: $RESULT1 patches"

# Query as tenant2 (should see 0 patches)
RESULT2=$(curl -s http://localhost:8080/api/connectors/patches/coverage/metrics \
  -H "X-API-Key: test-key" \
  -H "X-Tenant-ID: $TENANT2" | jq '.totalPatches')

echo "Tenant2 sees: $RESULT2 patches"

# Verify: Tenant1 > 0, Tenant2 = 0
if [ "$RESULT1" -gt 0 ] && [ "$RESULT2" -eq 0 ]; then
  echo "✓ PASS: Multi-tenant isolation verified"
else
  echo "✗ FAIL: Multi-tenant isolation BROKEN"
fi
```

**Expected:**
- Tenant1 sees only Tenant1 data
- Tenant2 sees only Tenant2 data (empty initially)
- Cross-tenant access returns zero results

**Test 2: Database RLS Enforcement**
```sql
-- Test RLS policy enforcement at database level

-- Set context for tenant1
SELECT set_config('app.current_tenant_id', '11111111-1111-1111-1111-111111111111', FALSE);
SELECT set_config('search_path', 'tenant_default,platform', FALSE);

-- Query asset_fix_status as tenant1
SELECT COUNT(*) as tenant1_count FROM tenant_default.asset_fix_status;

-- Set context for tenant2
SELECT set_config('app.current_tenant_id', '22222222-2222-2222-2222-222222222222', FALSE);
SELECT set_config('search_path', 'tenant_default,platform', FALSE);

-- Query asset_fix_status as tenant2
-- Expected: Same table structure but different rows due to RLS
SELECT COUNT(*) as tenant2_count FROM tenant_default.asset_fix_status;

-- Try to bypass RLS (should fail)
SET app.current_tenant_id = '11111111-1111-1111-1111-111111111111';
SELECT * FROM tenant_default.asset_fix_status WHERE tenant_id != current_setting('app.current_tenant_id');
-- Expected: RLS policy blocks this query (0 rows returned)
```

**Expected:**
- Tenant1 RLS query returns tenant1 rows
- Tenant2 RLS query returns tenant2 rows
- Bypass attempt blocked by RLS policy

**Owner:** Security Engineer  
**Time:** 1 hour  
**Deliverable:** Multi-tenant isolation verified

### Task 2.3: API Authentication & Authorization

**Test 1: Unauthenticated Request Rejection**
```bash
#!/bin/bash

# Request without auth header
curl -s http://localhost:8080/api/connectors/patches
# Expected: 401 Unauthorized

# Request with invalid API key
curl -s http://localhost:8080/api/connectors/patches \
  -H "X-API-Key: ${INVALID_API_KEY:-invalid-key}"
# Expected: 401 Unauthorized
```

**Test 2: Authorization Check**
```bash
#!/bin/bash

# Request with valid API key
curl -s http://localhost:8080/api/connectors/patches \
  -H "X-API-Key: ${APP_API_KEY:?Set a local development API key}"
# Expected: 200 OK

# Request to protected admin endpoint without PLATFORM_OWNER role
curl -s http://localhost:8080/api/platform/status \
  -H "X-API-Key: ${APP_API_KEY:?Set a local development API key}"
# Expected: 403 Forbidden (unless role granted)
```

**Expected:**
- Authenticated requests: 200 OK
- Unauthenticated requests: 401 Unauthorized
- Role-protected endpoints: 403 Forbidden (without role)

**Owner:** Security Engineer  
**Time:** 30 minutes  
**Deliverable:** Auth/authz tests pass

### Task 2.4: RLS Policy Verification (Production Schema)

**Goal:** Verify FORCE ROW LEVEL SECURITY on tenant tables

**Check RLS Configuration:**
```sql
-- Verify RLS enabled on critical tables
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'tenant_default'
  AND tablename IN ('asset_fix_status', 'finding_fix_recommendation', 'fix_deployment_campaign');

-- Expected: rowsecurity = true for all tenant tables

-- Check RLS policies exist
SELECT tablename, policyname, permissive, roles
FROM pg_policies
WHERE schemaname = 'tenant_default'
  AND tablename = 'asset_fix_status';

-- Expected: At least one RESTRICT policy on tenant_id column
```

**Verify Runtime Role Cannot Bypass RLS:**
```sql
-- Check runtime role permissions
SELECT rolname, bypassrls, superuser
FROM pg_roles
WHERE rolname = 'scout_runtime';

-- Expected: bypassrls = false, superuser = false
-- If either is true: SECURITY ISSUE
```

**Owner:** Database Admin  
**Time:** 30 minutes  
**Deliverable:** RLS enforcement confirmed

---

## Performance & Security Baseline Report

### Task 3.1: Generate Performance Report

**Create performance baseline document:**
```
# Performance Baseline Report - Week 2

## Test Date: 2026-10-11

### Ingestion Performance
- Patches processed: 1000
- Duration: X seconds
- Throughput: X patches/second
- Status: PASS / FAIL (target: <30s)

### Dashboard Query Performance
- Coverage metrics: X ms (target: <500ms)
- Deployment drill-down: X ms (target: <1000ms)
- Dashboard overview: X ms (target: <2000ms)
- Status: PASS / FAIL

### Database Performance
- Batch processing verified: YES / NO
- Indexes in place: YES / NO
- Query N+1 issues: NONE / X FOUND
- Status: PASS / FAIL

### Recommendations
1. [If issues found: specific optimization recommendations]
2. ...
```

**Owner:** Performance Engineer  
**Time:** 30 minutes  
**Deliverable:** Performance baseline report

### Task 3.2: Generate Security Report

**Create security audit document:**
```
# Security Hardening Report - Week 2

## Test Date: 2026-10-11

### Credential Encryption
- Credentials encrypted: YES / NO
- Decryption only during execution: YES / NO
- No plaintext in logs: YES / NO
- Status: PASS / FAIL

### Multi-Tenant Isolation
- API isolation verified: YES / NO
- RLS policies enforced: YES / NO
- Cross-tenant access blocked: YES / NO
- Status: PASS / FAIL

### Authentication & Authorization
- Unauthenticated requests blocked: YES / NO
- Authorization checks working: YES / NO
- Protected endpoints secured: YES / NO
- Status: PASS / FAIL

### Database Security
- FORCE ROW LEVEL SECURITY enabled: YES / NO
- Runtime role cannot bypass RLS: YES / NO
- Status: PASS / FAIL

### Findings & Remediation
- Critical Issues: 0
- High Priority Issues: 0
- Medium Priority Issues: X
- Status: PASS / FAIL (target: 0 critical/high)

### Sign-Off
- Security Lead: _________________ Date: _____
```

**Owner:** Security Engineer  
**Time:** 30 minutes  
**Deliverable:** Security audit report

---

## Week 2 Success Criteria

| Metric | Target | Status |
|--------|--------|--------|
| Patch Ingestion Time | <30s for 1000 patches | ⏳ |
| Coverage Metrics Query | <500ms | ⏳ |
| Drill-Down Query | <1000ms | ⏳ |
| Dashboard Overview | <2000ms | ⏳ |
| Credentials Encrypted | YES | ⏳ |
| No Plaintext in Logs | YES | ⏳ |
| Multi-Tenant Isolation | VERIFIED | ⏳ |
| RLS Enforcement | VERIFIED | ⏳ |
| Auth/Authz Working | YES | ⏳ |
| Performance Pass Rate | 100% | ⏳ |
| Security Pass Rate | 100% | ⏳ |

---

## Troubleshooting

### Performance Issue: Queries >1 second
1. Check database indexes: `SELECT * FROM pg_stat_user_indexes WHERE idx_scan = 0;`
2. Analyze query plan: `EXPLAIN ANALYZE SELECT ...`
3. Check for N+1 queries in logs
4. Consider adding caching layer

### Security Issue: Plaintext credential in logs
1. Verify credential masking in error handling
2. Check application logging configuration
3. Ensure CredentialEncryptionService used everywhere
4. Add credential scrubbing to log output

### Multi-Tenant Isolation Failure
1. Verify TenantContext properly set before query
2. Check all queries have `WHERE tenant_id = ...` filter
3. Verify RLS policy definition
4. Test with manual SQL to verify RLS works

---

## Sign-Off & Next Steps

**After Week 2 completion:**
- [ ] Performance baseline documented
- [ ] All performance tests passing
- [ ] Security audit passed
- [ ] All credentials encrypted
- [ ] Multi-tenant isolation verified
- [ ] Code review approval

**Proceed to Week 3:** Frontend Dashboard Implementation
