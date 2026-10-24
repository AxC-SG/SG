# Fix Intelligence Platform - Production Deployment Guide

## Pre-Deployment Checklist

### Code Quality ✅/⏳
- [x] Phase 0-3 backend implementation complete (42 files)
- [x] Connector parsing implemented (SCCM, BigFix, Tanium)
- [x] Integration tests created (PatchConnectorControllerPostgresIntegrationTest)
- [ ] All tests passing (mvn verify)
- [ ] Code review approved
- [ ] SpotBugs clean
- [ ] JaCoCo coverage >80%

### Database ✅/⏳
- [x] Migrations created (V3, V4 for patch infrastructure)
- [ ] Migrations tested on staging database
- [ ] Rollback procedures documented
- [ ] Data backup procedures in place
- [ ] RLS policies verified in production environment
- [ ] Indexes created and optimized

### Security ✅/⏳
- [x] Multi-tenant isolation (3-layer)
- [x] Credential encryption (AES-256-GCM)
- [x] API authentication required
- [ ] SSL/TLS certificates installed
- [ ] CORS policies configured
- [ ] API rate limiting implemented
- [ ] Secrets management configured (HashiCorp Vault / AWS Secrets Manager)
- [ ] Security scan passed (OWASP, SonarQube)

### Infrastructure ✅/⏳
- [ ] Docker image built and tested
- [ ] Kubernetes manifests reviewed
- [ ] Database replication configured
- [ ] Backup and restore tested
- [ ] Load balancer configured
- [ ] CDN/cache layers configured
- [ ] Monitoring agents installed

### Documentation ✅/⏳
- [x] API documentation (endpoints defined)
- [x] Connector setup guides drafted
- [ ] Connector setup guides tested
- [ ] Operator runbook completed
- [ ] Troubleshooting guide completed
- [ ] Architecture diagrams created
- [ ] Change log updated

---

## Connector Setup Procedures

### SCCM Connector Setup

#### Prerequisites
- SCCM Version: 2103 or higher
- Database access: Site Database server
- Credentials: Service account with read access to SCCM database

#### Configuration Steps
```
1. Navigate to: /api/connectors/SCCM/test
   
2. Provide credentials:
   {
     "base_url": "https://sccm-db-server.example.com",
     "database_name": "CM_ABC",
     "auth_type": "SQL_AUTH",
     "username": "sccm_service",
     "password": "encrypted_password"
   }

3. Test connection: POST /api/connectors/SCCM/test
   Expected: 200 OK, "Connected"

4. Enable patch sync:
   - UI: /api/connectors/SCCM/sync (POST)
   - Or: Enable scheduled sync (6-hour interval by default)

5. Monitor: GET /api/connectors/SCCM/sync-history
```

#### Troubleshooting
- **Connection timeout:** Check firewall, SQL Server availability
- **Authentication failed:** Verify credentials, service account permissions
- **Empty patch list:** Check SCCM views (v_UpdateInfo populated)
- **Slow sync:** Check SCCM database performance, increase batch size

### BigFix Connector Setup

#### Prerequisites
- BigFix (formerly IBM Endpoint Manager) Version 12.x or higher
- API token with Fixlet query permissions
- HTTPS enabled

#### Configuration Steps
```
1. Generate API token in BigFix:
   - Console → REST API → Generate Token

2. Provide credentials:
   {
     "base_url": "https://bigfix-server.example.com:52311",
     "api_token": "api_token_here"
   }

3. Test connection: POST /api/connectors/BIGFIX/test
   Expected: 200 OK

4. Enable sync: POST /api/connectors/BIGFIX/sync

5. Monitor: GET /api/connectors/BIGFIX/sync-history
```

### Tanium Connector Setup

#### Prerequisites
- Tanium Version 7.4 or higher
- API token with Patch module access
- GraphQL API enabled

#### Configuration Steps
```
1. Generate API token in Tanium:
   - Administration → API Tokens → Create Token

2. Provide credentials:
   {
     "base_url": "https://tanium-server.example.com",
     "api_key": "api_key_here"
   }

3. Test connection: POST /api/connectors/TANIUM/test
   Expected: 200 OK

4. Enable sync: POST /api/connectors/TANIUM/sync

5. Monitor: GET /api/connectors/TANIUM/sync-history
```

---

## Deployment Procedures

### Database Migration

```bash
# 1. Backup existing database
pg_dump -h prod-db.example.com -U postgres vulnwatch > backup_$(date +%Y%m%d_%H%M%S).sql

# 2. Run migrations (Flyway)
mvn clean flyway:migrate -Dflyway.url="jdbc:postgresql://prod-db/vulnwatch" \
  -Dflyway.user="migration_user" \
  -Dflyway.password="${DB_PASSWORD}"

# 3. Verify migrations
SELECT name, success, execution_time FROM flyway_schema_history ORDER BY installed_rank DESC LIMIT 10;

# 4. Rollback if needed
mvn flyway:undo  # Only for previous version
```

### Application Deployment

#### Docker

```bash
# 1. Build image
docker build -t vulnwatch-backend:${VERSION} .

# 2. Test locally
docker run --rm -e DB_URL="jdbc:postgresql://localhost:5432/vulnwatch" \
  -e SCCM_ENABLED=true \
  vulnwatch-backend:${VERSION}

# 3. Push to registry
docker push registry.example.com/vulnwatch-backend:${VERSION}

# 4. Update Kubernetes deployment
kubectl set image deployment/vulnwatch-backend \
  vulnwatch-backend=registry.example.com/vulnwatch-backend:${VERSION} \
  -n production
```

#### Kubernetes

```bash
# 1. Apply ConfigMap
kubectl apply -f kubernetes/configmap.yaml -n production

# 2. Apply Secrets
kubectl apply -f kubernetes/secrets.yaml -n production

# 3. Deploy or update
kubectl apply -f kubernetes/deployment.yaml -n production

# 4. Verify deployment
kubectl rollout status deployment/vulnwatch-backend -n production
kubectl logs -f deployment/vulnwatch-backend -n production --tail=50
```

#### Environment Configuration

```yaml
# kubernetes/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vulnwatch-config
  namespace: production
data:
  app.patch-sync.sccm-interval: "21600000"  # 6 hours
  app.patch-sync.sccm-initial-delay: "60000"  # 1 minute
  app.security.allow-api-key-auth: "false"
  app.allow-header-tenant-selection: "false"
  app.require-tenant-context: "true"
```

```yaml
# kubernetes/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: vulnwatch-secrets
  namespace: production
type: Opaque
stringData:
  DB_URL: "jdbc:postgresql://prod-db:5432/vulnwatch"
  DB_USER: "vulnwatch_runtime"
  DB_PASSWORD: "encrypted_password"
  APP_JWT_ISSUER_URI: "https://auth.example.com"
  APP_CREDENTIAL_ENCRYPTION_KEY: "base64_encoded_256bit_key"
  GITHUB_API_TOKEN: "github_token_for_ghsa"
```

---

## Production Validation

### Health Checks

```bash
# 1. Database connectivity
curl -s http://localhost:8080/actuator/health/db | jq .

# 2. SCCM connector status
curl -s http://localhost:8080/actuator/health/custom | jq .

# 3. API endpoint test
curl -s -H "X-API-Key: test-key" http://localhost:8080/api/connectors/patches | jq .

# 4. Dashboard metrics
curl -s -H "X-API-Key: test-key" http://localhost:8080/api/patches/dashboard/health | jq .
```

### Performance Testing

```bash
# 1. Load test: 1000 concurrent requests
ab -n 10000 -c 1000 -H "X-API-Key: test-key" \
  http://localhost:8080/api/connectors/patches/coverage/metrics

# 2. Metrics: Query performance
# - Coverage metrics should return <500ms
# - Deployment status drill-down <1000ms
# - Dashboard overview <2000ms

# 3. Database metrics
SELECT 
  query,
  calls,
  mean_exec_time,
  max_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC LIMIT 10;
```

---

## Operational Monitoring

### Metrics to Monitor

```
Application Level:
- patch_ingestion_duration_seconds (histogram)
- patch_ingestion_total_patches (counter)
- patch_ingestion_errors_total (counter)
- patch_deduplication_duplicates_found (counter)
- finding_auto_resolution_count (counter)

Database Level:
- Connection pool size (active, idle)
- Query latency (p50, p95, p99)
- Transaction duration
- Lock wait times

API Level:
- Request latency per endpoint
- Error rate by endpoint (4xx, 5xx)
- Auth failures
- Rate limit violations
```

### Alert Thresholds

```
Critical:
- Connector auth failure rate >10%
- DB connection pool exhausted
- Patch ingestion >15 min
- API error rate >5%

Warning:
- Connector auth failure rate >5%
- Patch ingestion >5 min
- API error rate >2%
- Dashboard query >5s
```

### Logging Configuration

```yaml
# application-production.yml
logging:
  level:
    com.prototype.vulnwatch: INFO
    com.prototype.vulnwatch.service.patch: DEBUG
    org.springframework.security: INFO
  pattern:
    console: "%d{ISO8601} %5p %thread %-40logger{39} : %msg%n"
    file: "%d{ISO8601} %5p %thread %-40logger{39} : %msg%n"
  file:
    name: /var/log/vulnwatch/application.log
    max-size: 10GB
    max-history: 30
```

---

## Rollback Procedures

### If Deployment Fails

```bash
# 1. Rollback Kubernetes deployment
kubectl rollout undo deployment/vulnwatch-backend -n production

# 2. Verify rollback
kubectl rollout status deployment/vulnwatch-backend -n production

# 3. Check logs
kubectl logs deployment/vulnwatch-backend -n production --tail=100
```

### If Database Migration Fails

```bash
# 1. Check Flyway history
SELECT * FROM flyway_schema_history WHERE success = false;

# 2. Analyze failure
SELECT error_message FROM flyway_schema_history 
WHERE version = 'X.X' AND success = false;

# 3. Restore from backup
psql -h prod-db -U postgres < backup_YYYYMMDD_HHMMSS.sql

# 4. Rerun migration after fix
mvn flyway:repair
mvn flyway:migrate
```

---

## Post-Deployment Validation

### Week 1 Monitoring
- [ ] No critical errors in logs
- [ ] Patch ingestion runs successfully
- [ ] Dashboard metrics accuracy verified
- [ ] Auto-resolution working correctly
- [ ] Multi-tenant isolation tested
- [ ] Performance metrics within SLA

### Week 2 Validation
- [ ] Production data volume stable
- [ ] Database growth rate acceptable
- [ ] All connectors syncing regularly
- [ ] No credential leaks in logs
- [ ] API response times stable
- [ ] Team trained on procedures

---

## Support Contacts

- **On-Call Engineer:** [contact info]
- **Database Admin:** [contact info]
- **Security Team:** [contact info]
- **Product Owner:** [contact info]

---

## Documentation Links

- [API Documentation](./API_DOCS.md)
- [Connector Setup Guide](./CONNECTOR_SETUP.md)
- [Operator Runbook](./RUNBOOK.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)
- [Architecture Guide](./ARCHITECTURE.md)
