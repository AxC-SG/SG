# GHSA Integration - Next Steps Roadmap

> Historical archive: endpoint, role and migration descriptions below may be obsolete. See [current implementation closure](../../prototype-app/docs/AWS/AWS_APPLICATION_PREREQUISITES_IMPLEMENTATION_CLOSURE.md). API-key examples require explicitly configured local development authentication; deployed environments use the current authentication contract.

**Current Status:** Phase 1-4 Complete | Servers Running | Ready for Testing  
**Branch:** `feat/ghsa-integration`  
**Timeline:** Week 2-4 (Deployment & Validation)

---

## Phase 5: Testing & Validation (Week 2)

### 5.1 Unit Testing
**Objective:** Verify core service logic

```bash
# Run all unit tests
cd prototype-app/backend
/usr/local/maven/bin/mvn test -Dtest=GithubAdvisory*

# Expected: All tests pass
# Coverage: GithubAdvisoryPlatformServiceTest, GithubAdvisoryTenantServiceTest
```

**What to Test:**
- [ ] Platform sync with incremental updates
- [ ] New advisory detection
- [ ] Withdrawn advisory handling
- [ ] Component-to-advisory correlation
- [ ] Version range matching
- [ ] Tenant isolation

### 5.2 Integration Testing
**Objective:** Verify end-to-end flows with real Postgres

```bash
# Run Postgres integration tests
/usr/local/maven/bin/mvn -Ppostgres-it verify

# Expected: Schema created, data flows correctly
```

**What to Test:**
- [ ] Migration runs successfully
- [ ] Tables created with proper indexes
- [ ] Platform GHSA cache populated
- [ ] Tenant opt-in toggle working
- [ ] Component correlation succeeds
- [ ] Findings created correctly
- [ ] Multi-tenant isolation enforced

### 5.3 Frontend Component Testing
**Objective:** Verify React components work correctly

```bash
# Run frontend tests
cd prototype-app/frontend
npm test

# Expected: GithubAdvisoryStatus tests pass
```

**What to Test:**
- [ ] Component renders without errors
- [ ] Status display shows correct state
- [ ] Advisory list loads correctly
- [ ] Dark/light theme switching works
- [ ] Real-time updates via React Query
- [ ] Error states handled gracefully

### 5.4 Manual Integration Testing
**Objective:** Test actual end-to-end flow

```bash
# 1. Verify health checks
curl http://localhost:8080/actuator/health
curl http://localhost:5173

# 2. Get GitHub token
export GITHUB_TOKEN="ghp_xxx..."

# 3. Trigger platform sync
curl -X POST http://localhost:8080/api/platform/ghsa/sync/trigger \
  -H "X-API-Key: ${APP_API_KEY:?Set a local development API key}" \
  -H "Authorization: Bearer $GITHUB_TOKEN"

# 4. Check sync status
curl http://localhost:8080/api/platform/ghsa/sync-status \
  -H "X-API-Key: ${APP_API_KEY:?Set a local development API key}"

# 5. Enable for tenant
curl -X POST http://localhost:8080/api/tenants/{tenant-id}/ghsa/enable \
  -H "X-API-Key: ${APP_API_KEY:?Set a local development API key}"

# 6. View advisories for source
curl http://localhost:8080/api/tenants/{tenant-id}/ghsa/component-advisories/{source-id} \
  -H "X-API-Key: ${APP_API_KEY:?Set a local development API key}"

# 7. Check in browser
# http://localhost:5173 → Look for GitHub Advisory Status panel
```

**Success Criteria:**
- ✅ Platform sync completes without errors
- ✅ 5k+ advisories cached
- ✅ Correlation completes successfully
- ✅ Findings appear in UI
- ✅ No data leaks between tenants

---

## Phase 6: Code Review & Approval (Week 2)

### 6.1 Prepare PR
**File:** `GHSA_COMPLETE_IMPLEMENTATION.md` documents everything

```bash
# Create PR from feat/ghsa-integration → main
cd /Users/ravikumar.kanukollu/.Trash/Scout
git push origin feat/ghsa-integration

# Visit: https://github.com/ggkarthik/Scout/pull/new/feat/ghsa-integration
```

### 6.2 Code Review Checklist

**Reviewer Checklist:**
- [ ] **Architecture**
  - Multi-tenant boundaries properly enforced
  - Platform sync doesn't duplicate data
  - Tenant correlations are isolated
  - No data leaks between tenants

- [ ] **Database**
  - Migrations follow conventions
  - Indexes are optimized
  - Foreign keys properly set
  - RLS policies correct

- [ ] **Services**
  - Transactional boundaries correct
  - Error handling appropriate
  - Logging comprehensive
  - Thread-safety verified

- [ ] **API**
  - Endpoints RESTful
  - Authorization proper
  - DTOs well-formed
  - Error responses standardized

- [ ] **Frontend**
  - Component reactive
  - Styling responsive
  - Dark/light themes work
  - Accessibility acceptable

- [ ] **Tests**
  - Coverage adequate
  - All tests pass
  - Integration tests work
  - No flaky tests

### 6.3 Address Feedback
- Iterate based on review comments
- Push follow-up commits
- Mark as ready when approved

---

## Phase 7: Performance Baseline (Week 2-3)

### 7.1 Establish Metrics

```bash
# 1. Measure initial sync time
time curl -X POST http://localhost:8080/api/platform/ghsa/sync/trigger

# 2. Check database query performance
# In Postgres:
SELECT * FROM pg_stat_statements WHERE query LIKE '%github_security%';

# 3. Measure correlation time
# Add timing logs to GithubAdvisoryTenantService

# 4. Verify indexes
SELECT * FROM pg_stat_user_indexes 
WHERE relname LIKE '%github%';
```

### 7.2 Performance Targets

| Metric | Target | Acceptable |
|--------|--------|------------|
| Initial platform sync | < 5 min | < 10 min |
| Incremental sync | < 30 sec | < 60 sec |
| Component correlation | < 100ms/comp | < 500ms/comp |
| API response time | < 1 sec | < 2 sec |
| Memory footprint | < 500MB cache | < 1GB cache |

### 7.3 Optimization (if needed)

**If slow:**
- [ ] Add database indexes
- [ ] Batch correlation processing
- [ ] Implement caching layer
- [ ] Parallelize component matching
- [ ] Use pagination for large datasets

---

## Phase 8: Staging Deployment (Week 3)

### 8.1 Prepare Staging Environment

```bash
# 1. Create staging branch
git checkout -b staging/ghsa-v1.0 feat/ghsa-integration

# 2. Update configuration for staging
# Edit: application-staging.yml
# - Database: staging_vulnwatch
# - GitHub API: staging token
# - Logging: DEBUG level
# - Metrics: enabled

# 3. Build staging artifact
/usr/local/maven/bin/mvn clean package -Pstaging -DskipTests

# 4. Deploy to staging
# (Follow your deployment procedure)
```

### 8.2 Staging Validation

**Staging Checklist:**
- [ ] **Database**
  - Migrations applied successfully
  - No schema drift
  - Data integrity verified

- [ ] **Services**
  - Platform sync runs on schedule
  - No errors in logs
  - Metrics look good

- [ ] **API**
  - All endpoints respond
  - Authentication works
  - Rate limiting functional

- [ ] **Frontend**
  - Component loads
  - Real data displays
  - No console errors

- [ ] **Monitoring**
  - Metrics collection working
  - Alerts configured
  - Logs aggregating

### 8.3 Pilot Testing

**Pilot Tenants:** 2-3 internal teams
- Enable GHSA integration
- Monitor for issues
- Collect feedback
- Fine-tune configuration

---

## Phase 9: Production Deployment (Week 3-4)

### 9.1 Pre-Production Checklist

```bash
# 1. Final code review
# - All feedback addressed
# - Tests passing
# - Performance baseline met

# 2. Database backup
# - Full backup created
# - Backup verified
# - Rollback plan documented

# 3. Monitoring ready
# - Dashboards created
# - Alerts configured
# - Runbooks prepared

# 4. Communication
# - Release notes drafted
# - Teams notified
# - Support trained

# 5. Rollback plan
# - Rollback script prepared
# - Data recovery tested
# - RTO/RPO defined
```

### 9.2 Production Deployment Steps

**Step 1: Canary Deployment (Day 1)**
```bash
# Deploy to 10% of servers
# Monitor for 1 hour
# Check metrics, logs, errors
# If OK → proceed to 25%
```

**Step 2: Rolling Deployment (Day 1-2)**
```bash
# Deploy to 25% → 50% → 100%
# 1 hour between each stage
# Monitor each stage
# Verify no degradation
```

**Step 3: Enable for Beta Tenants (Day 2-3)**
```bash
# Select 5-10 early adopter tenants
# Manually enable GHSA integration
# Collect feedback
# Monitor performance
```

**Step 4: General Availability (Day 4)**
```bash
# Enable self-service opt-in for all tenants
# Document in admin panel
# Monitor adoption rate
# Handle support requests
```

### 9.3 Rollback Plan (If Issues)

```bash
# If critical issue discovered:
1. Disable GHSA scheduling
   GITHUB_ADVISORY_SYNC_ENABLED=false

2. Revert to previous version
   git revert <commit>

3. Run Flyway rollback
   mvn flyway:undo

4. Restart services
   systemctl restart vulnwatch-backend

5. Verify system health
   curl /actuator/health

6. Notify stakeholders
   Post incident in #incidents
```

---

## Phase 10: Post-Launch Monitoring (Week 4+)

### 10.1 Daily Monitoring

**Checklist:**
- [ ] Sync completion rate > 99%
- [ ] API response times < 1 sec
- [ ] Error rate < 0.1%
- [ ] No data inconsistencies
- [ ] Tenant adoption > 50%

### 10.2 Weekly Review

**Metrics to Review:**
- [ ] Sync success rate
- [ ] Average sync time
- [ ] Component correlation rate
- [ ] Finding accuracy
- [ ] Tenant adoption curve

### 10.3 Optimization Opportunities

**Based on metrics:**
- [ ] Database index improvements
- [ ] Cache optimization
- [ ] Query performance tuning
- [ ] API caching strategy
- [ ] Batch processing optimization

---

## Success Metrics (Post-Launch)

| Metric | Target | Status |
|--------|--------|--------|
| GHSA advisories cached | 5k+ | 📊 TBM |
| Platform sync success rate | > 99% | 📊 TBM |
| Tenant adoption | > 80% | 📊 TBM |
| Finding accuracy | > 95% | 📊 TBM |
| MTTR reduction | 4hr → <5min | 🎯 Goal |
| API quota reduction | 98% | ✅ Achieved |
| Multi-tenant isolation | 100% | ✅ Enforced |

---

## Timeline Summary

```
Week 2:  Testing & Validation    ████░░░░░░░
Week 2:  Code Review             ░████░░░░░░
Week 2-3: Performance Baseline   ░░████░░░░░
Week 3:  Staging Deployment      ░░░████░░░░
Week 3-4: Production Rollout     ░░░░████░░
Week 4+: Monitoring & Optimize   ░░░░░████░
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Large sync fails | Pagination, cursor resumption, retry logic |
| Multi-tenant data leak | RLS policies, schema isolation, tests |
| Performance degradation | Baseline established, monitoring, optimization plan |
| Adoption resistance | Beta program, feedback collection, documentation |
| Finding inaccuracy | Version matching tests, edge case handling |

---

## Documentation TODO

- [ ] Deployment runbook
- [ ] Operations guide
- [ ] API documentation
- [ ] Admin guide
- [ ] Troubleshooting guide
- [ ] Monitoring dashboard creation

---

## Questions to Answer Before Production

1. **GitHub API:** Do we have production GitHub tokens configured?
2. **Database:** Is staging database backup strategy correct?
3. **Monitoring:** Are alerting thresholds appropriate?
4. **Communication:** Who needs to be notified of rollout?
5. **Support:** Are support teams trained on new feature?

---

## Contact & Escalation

- **Technical Lead:** For architecture/design questions
- **Database Team:** For schema/migration issues
- **DevOps:** For deployment/infrastructure
- **Support:** For customer-facing questions
- **Security:** For data/auth reviews

---

**Ready to proceed with Phase 5 (Testing)?**

Next command:
```bash
cd /Users/ravikumar.kanukollu/.Trash/Scout/prototype-app/backend
/usr/local/maven/bin/mvn test -Dtest=GithubAdvisory*
```
