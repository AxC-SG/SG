# Week 1: Test Suite Validation & Connector Verification

**Timeline:** Sept 30 - Oct 4, 2026  
**Owner:** Lead Engineer  
**Goal:** Achieve 100% test pass rate, >80% code coverage, zero security findings

---

## Day 1-2: Full Test Suite Execution

### Task 1.1: Run Full Test Suite
```bash
cd /Users/ravikumar.kanukollu/Documents/GitHub/NoScan/Scout/prototype-app/backend

# Full clean build with all tests
mvn clean -Ppostgres-it verify

# Expected output:
# - Compilation: SUCCESS
# - Surefire (unit tests): 150+ tests passing
# - Failsafe (Postgres integration tests): 15+ tests passing
# - JaCoCo coverage: >80%
# - SpotBugs: zero critical/high findings
```

**Owner:** Lead Engineer  
**Time:** 30-45 minutes  
**Target:** All tests GREEN ✅

### Task 1.2: Capture Baseline Metrics

**Create metrics file:**
```bash
cat > /tmp/baseline-metrics.txt << 'EOF'
=== TEST SUITE BASELINE ===
Date: 2026-09-30
Build Status: [PASS/FAIL]
Unit Tests: X passed, Y failed
Integration Tests: X passed, Y failed
Total Tests: X
Pass Rate: X%
Code Coverage: X%
SpotBugs Critical: X
SpotBugs High: X
Build Time: X minutes
EOF
```

**Owner:** Lead Engineer  
**Time:** 5 minutes  
**Deliverable:** `baseline-metrics.txt`

---

## Day 3-5: Connector Response Parser Verification

### Task 2.1: SCCM JSON Parser Verification

**File:** `SccmPatchConnector.java`

**Unit Test:** Run SCCM-specific tests
```bash
mvn test -Dtest=SccmPatchConnectorTest
```

**Expected Results:**
```
✓ testParseJsonResponse_ValidData — Parses all 20+ fields
✓ testParseJsonResponse_MultiplePatches — Handles batch correctly
✓ testParseJsonResponse_MissingOptionalFields — Nulls missing fields
✓ testParseJsonResponse_NullValues — Handles null JSON values
✓ testParseJsonResponse_EmptyValueArray — Returns empty list
✓ testParseJsonResponse_InvalidJson — Logs error, returns empty list
✓ testParseJsonResponse_AdditionalFields — Captures extra fields
✓ testParseJsonResponse_DateParsing — Converts release_date to Instant
✓ testParseJsonResponse_Null FieldHandling — Graceful null handling
✓ testParseJsonResponse_TypeConversions — String/Long conversions work
```

**Verification Checklist:**
- [ ] All 10 tests pass
- [ ] No null pointer exceptions
- [ ] Error logs show appropriate warnings
- [ ] Parsed patches have all required fields

**Owner:** Backend Engineer  
**Time:** 1 hour  
**Status:** PASS/FAIL

### Task 2.2: BigFix JSON Parser Verification

**File:** `BigFixPatchConnector.java`

**Unit Test:** Run BigFix-specific tests
```bash
mvn test -Dtest=BigFixPatchConnectorTest
```

**Expected Results:**
```
✓ testParseJsonResponse_ValidData — Parses query_results array
✓ testParseJsonResponse_MultiplePatches — Handles 100+ patches
✓ testParseJsonResponse_MissingQueryResultsArray — Handles missing array
✓ testParseJsonResponse_NullValues — Handles null fields
✓ testParseJsonResponse_DateFormatISO8601 — Parses ISO dates
✓ testParseJsonResponse_AdditionalFields — Preserves extra fields
✓ testParseJsonResponse_EmptyInput — Returns empty list
✓ testParseJsonResponse_InvalidJson — Logs and returns empty list
✓ testParseJsonResponse_FieldMapping — Maps BigFix → standard names
✓ testParseJsonResponse_NestedStructures — Handles complex JSON
✓ testParseJsonResponse_TypeConversions — Safe type handling
✓ testParseJsonResponse_ErrorRecovery — Continues on partial errors
```

**Verification Checklist:**
- [ ] All 12 tests pass
- [ ] ISO 8601 date parsing works
- [ ] Nested query_results extraction works
- [ ] Field mapping is correct (BigFix names → standard names)

**Owner:** Backend Engineer  
**Time:** 1 hour  
**Status:** PASS/FAIL

### Task 2.3: Tanium GraphQL Parser Verification

**File:** `TaniumPatchConnector.java`

**Unit Test:** Run Tanium-specific tests (via integration tests)
```bash
mvn -Ppostgres-it verify -Dit.test=PatchConnectorControllerPostgresIntegrationTest
```

**Expected Results:**
- Tanium connector authentication works
- GraphQL query execution successful
- Response parsing extracts data.patches.edges[].node correctly
- Supported platforms array extracted as List<String>
- Boolean fields (requiresReboot) parsed correctly
- Date fields parsed to Instant

**Verification Checklist:**
- [ ] GraphQL structure navigation works
- [ ] Array handling (supportedPlatforms) works
- [ ] Boolean fields extracted correctly
- [ ] Date parsing works
- [ ] Additional fields captured

**Owner:** Backend Engineer  
**Time:** 1 hour  
**Status:** PASS/FAIL

### Task 2.4: Integration Test Verification

**File:** `PatchConnectorControllerPostgresIntegrationTest.java`

**Run Integration Tests:**
```bash
mvn -Ppostgres-it verify -Dit.test=PatchConnectorControllerPostgresIntegrationTest
```

**Expected Test Results (10 tests):**
1. ✓ testListConnectors — Returns 3 connectors (SCCM, BigFix, Tanium)
2. ✓ testTestConnectionFailsWithBadCredentials — Returns 400 error
3. ✓ testTriggerSyncReturnsAccepted — Returns 202 queued status
4. ✓ testGetSyncHistory — Returns sync history list
5. ✓ testGetCoverageMetrics — Returns metrics with totals
6. ✓ testGetFixDeploymentStatus — Returns per-asset status
7. ✓ testCoverageMetricsMultiTenant — Tenant isolation verified
8. ✓ testDashboardOverview — Returns all dashboard sections
9. ✓ testDashboardHealth — Returns health score
10. ✓ testHealthStatusExcellent — Calculates correct health score

**Verification Checklist:**
- [ ] All 10 integration tests pass
- [ ] Multi-tenant isolation working (tenant1 ≠ tenant2 data)
- [ ] API endpoints accessible with auth
- [ ] RLS enforcing tenant boundaries

**Owner:** QA Engineer  
**Time:** 1 hour  
**Status:** PASS/FAIL

---

## Code Quality Metrics

### Task 3.1: JaCoCo Coverage Report

**Generate coverage report:**
```bash
# Coverage report already generated by mvn verify
# Open report at: backend/target/site/jacoco/index.html

# Check line coverage:
# Expected: >80% for all modules
# Target: >85% for patch connector modules
```

**Verification:**
- [ ] Overall line coverage >80%
- [ ] Patch connector modules >85% coverage
- [ ] All public methods have test coverage
- [ ] No untested exception paths

**Owner:** Lead Engineer  
**Time:** 30 minutes  
**Deliverable:** Coverage screenshot + analysis

### Task 3.2: SpotBugs Security Scan

**Run SpotBugs:**
```bash
mvn clean compile spotbugs:check

# Expected results:
# - Critical bugs: 0
# - High priority: 0
# - Medium priority: acceptable with justification
```

**Categories to check:**
- [ ] NullPointerException risks
- [ ] SQL injection vulnerabilities
- [ ] Potential resource leaks
- [ ] Hardcoded credentials
- [ ] Weak cryptography usage

**Owner:** Security Engineer  
**Time:** 30 minutes  
**Deliverable:** SpotBugs report with zero critical/high findings

### Task 3.3: Dependency Security Scan

**Run dependency check:**
```bash
mvn dependency-check:check

# Expected: No HIGH or CRITICAL CVEs
# Acceptable: MEDIUM CVEs with documented risk acceptance
```

**Check specific dependencies:**
- Jackson (JSON parsing)
- Spring Framework
- PostgreSQL JDBC driver
- All other runtime dependencies

**Owner:** Security Engineer  
**Time:** 30 minutes  
**Deliverable:** Dependency check report showing clean status

---

## Test Summary & Sign-Off

### Task 4.1: Generate Test Report

**Create summary document:**
```markdown
# Week 1 Test Validation Report
Date: 2026-10-04
Status: PASS/FAIL

## Unit Tests
- SCCM Connector: 10/10 PASS
- BigFix Connector: 12/12 PASS
- Tanium Connector: (via integration)
- Total: X/X tests passing

## Integration Tests
- Connector Controller: 10/10 PASS
- Multi-tenant Isolation: VERIFIED
- API Endpoints: ALL ACCESSIBLE
- Total: X/X tests passing

## Code Quality
- JaCoCo Coverage: X%
- SpotBugs Critical: 0
- SpotBugs High: 0
- Dependency CVEs: 0 critical, 0 high

## Performance Baseline
- Build time: X minutes
- Test execution time: X minutes
- Total CI/CD time: X minutes

## Sign-Off
- Lead Engineer: _____ Date: _____
- QA Lead: _____ Date: _____
- Security Lead: _____ Date: _____
```

**Owner:** Lead Engineer  
**Time:** 30 minutes  
**Deliverable:** Test report signed off by all stakeholders

### Task 4.2: Document Failures (if any)

**For each test failure:**
1. Capture error message
2. Identify root cause
3. Create fix and retry
4. Document in failure log

**Example failure handling:**
```
FAILURE: testParseJsonResponse_InvalidJson
ERROR: NullPointerException in parseJsonResponse()
ROOT CAUSE: Missing null check before array iteration
FIX: Add null check at line 95
RESULT: Test passes after fix
```

**Owner:** Backend Engineer  
**Time:** 2+ hours if failures exist  
**Deliverable:** All tests passing or failures documented with fixes

---

## Success Criteria

| Metric | Target | Status |
|--------|--------|--------|
| Unit Tests Pass Rate | 100% | ⏳ |
| Integration Tests Pass Rate | 100% | ⏳ |
| Code Coverage | >80% | ⏳ |
| SpotBugs Critical | 0 | ⏳ |
| SpotBugs High | 0 | ⏳ |
| Dependency CVEs Critical | 0 | ⏳ |
| Dependency CVEs High | 0 | ⏳ |
| Build Time | <15 minutes | ⏳ |

---

## Troubleshooting Guide

### Issue: Tests fail to run (Database connection)
**Solution:**
1. Verify PostgreSQL running: `psql postgres://localhost:5432/vulnwatch`
2. Check database exists: `\l` in psql
3. Clear test database: `dropdb vulnwatch_it_*`
4. Retry: `mvn clean -Ppostgres-it verify`

### Issue: Tests timeout (>10 minutes)
**Solution:**
1. Check database performance: `EXPLAIN ANALYZE` on queries
2. Run single test: `mvn test -Dtest=SccmPatchConnectorTest`
3. Check system resources (CPU, memory)
4. Increase timeout: `-Dtimeout=60000`

### Issue: Coverage below 80%
**Solution:**
1. Identify uncovered code: Review `target/site/jacoco/index.html`
2. Add unit tests for uncovered paths
3. Especially for error/exception handling
4. Rerun coverage: `mvn clean verify`

### Issue: SpotBugs finds violations
**Solution:**
1. Review each finding in detail
2. Determine if it's a real issue or false positive
3. For real issues: fix the code, add test, retry
4. For false positives: document justification in code comment

---

## Next Steps (After Week 1 Validation)

Once all tests pass:
1. ✅ Commit changes to git with message "Week 1: Test suite validation complete"
2. ✅ Create pull request with test results attached
3. ✅ Request code review from security team
4. ✅ Proceed to Week 2: Performance & Security Hardening

---

## Week 1 Checklist

**Daily Standups:**
- [ ] Monday: Test suite execution started
- [ ] Tuesday: All tests passing or failures identified
- [ ] Wednesday: Connector parsers verified
- [ ] Thursday: Code quality metrics verified
- [ ] Friday: Sign-off and final approval

**Deliverables:**
- [ ] Baseline metrics captured
- [ ] SCCM parser tests: 10/10 PASS
- [ ] BigFix parser tests: 12/12 PASS
- [ ] Integration tests: 10/10 PASS
- [ ] JaCoCo coverage >80%
- [ ] SpotBugs: 0 critical/high
- [ ] Dependency scan: clean
- [ ] Final test report signed off

**Owner Sign-Off:**
- [ ] Lead Engineer: _________________ Date: _____
- [ ] Backend Engineer: _________________ Date: _____
- [ ] QA Lead: _________________ Date: _____
- [ ] Security Lead: _________________ Date: _____
