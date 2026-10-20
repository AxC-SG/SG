package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Durable static assessment delivery. Lease metadata lives in the existing outbox JSON. */
@Service
public class AiGridAssessmentWorker {
    public static final String EVENT_TYPE = "STATIC_ASSESSMENT_REQUESTED";
    private static final Logger LOG = LoggerFactory.getLogger(AiGridAssessmentWorker.class);
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AiGridAssessmentService assessments;
    private final AiGridOwnershipService ownership;
    private final AiGridCoverageService coverage;
    private final AiGridSystemService systems;
    private final AiGridExposureService exposures;
    private final AiGridReconciliationService reconciliation;
    private final AiGridReadinessService readiness;
    private final AiGridFindingService findings;
    private final ObjectProvider<AiSecurityDigestBaselineService> baselines;
    private final long leaseSeconds;
    private final long heartbeatSeconds;
    private final ScheduledExecutorService heartbeats = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "ai-grid-assessment-heartbeat");
        thread.setDaemon(true);
        return thread;
    });

    public AiGridAssessmentWorker(NamedParameterJdbcTemplate jdbc, ObjectMapper mapper, TenantService tenants,
            TenantSchemaExecutionService tenantExecution, PlatformTransactionManager manager,
            AiGridAssessmentService assessments, AiGridOwnershipService ownership, AiGridCoverageService coverage,
            AiGridSystemService systems, AiGridExposureService exposures, AiGridReconciliationService reconciliation,
            AiGridReadinessService readiness, AiGridFindingService findings,
            ObjectProvider<AiSecurityDigestBaselineService> baselines,
            @Value("${app.ai-grid.assessment.lease-seconds:120}") long leaseSeconds,
            @Value("${app.ai-grid.assessment.heartbeat-seconds:30}") long heartbeatSeconds) {
        this.jdbc=jdbc; this.mapper=mapper; this.tenants=tenants; this.tenantExecution=tenantExecution;
        this.transactions=new TransactionTemplate(manager);
        this.transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.assessments=assessments; this.ownership=ownership; this.coverage=coverage; this.systems=systems;
        this.exposures=exposures; this.reconciliation=reconciliation; this.readiness=readiness;
        this.findings=findings; this.baselines=baselines;
        this.leaseSeconds=Math.max(2,leaseSeconds);
        this.heartbeatSeconds=Math.max(1,Math.min(heartbeatSeconds,this.leaseSeconds/2));
    }

    private ObjectProvider<AiGridDiscoveryRefreshService> refresh;
    @org.springframework.beans.factory.annotation.Autowired
    void configureRefresh(ObjectProvider<AiGridDiscoveryRefreshService> refresh,AiGridRunMetricsService metrics) { this.refresh=refresh; this.metrics=metrics; }
    private AiGridRunMetricsService metrics;
    private com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy backgroundPolicy = com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy.allowAll();
    @org.springframework.beans.factory.annotation.Autowired
    void configureBackgroundPolicy(com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy policy) { backgroundPolicy=policy; }

    @jakarta.annotation.PreDestroy
    void close() { heartbeats.shutdownNow(); }

    /** Must run in the source write transaction, so collection/configuration and delivery are atomic. */
    public UUID enqueue(Tenant tenant, UUID runId, Set<String> policyIds) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            return tenantExecution.run(tenant, () -> transactions.execute(status -> enqueue(tenant, runId, policyIds)));
        }
        assessments.lockTenant(tenant);
        UUID pending=jdbc.query("select id from ai_grid_outbox where event_type=:type and aggregate_id=:runId and status='PENDING' and attempts=0 order by created_at desc,id desc for update limit 1",
                Map.of("type",EVENT_TYPE,"runId",runId),rs -> rs.next() ? rs.getObject(1,UUID.class) : null);
        if (pending!=null) {
            jdbc.update("""
                    update ai_grid_outbox set payload_json=jsonb_set(payload_json,'{policyIds}',
                        case when jsonb_array_length(payload_json->'policyIds')=0 or jsonb_array_length(cast(:policies as jsonb))=0
                             then '[]'::jsonb else (select jsonb_agg(distinct value)
                                  from jsonb_array_elements((payload_json->'policyIds') || cast(:policies as jsonb))) end)
                     where id=:id
                    """,Map.of("id",pending,"policies",json(policyIds==null ? Set.of() : policyIds)));
            return pending;
        }
        UUID requestId=UUID.randomUUID();
        String version=requestId.toString();
        jdbc.update("""
                insert into ai_grid_outbox(id,tenant_id,event_type,aggregate_type,aggregate_id,aggregate_version,payload_json)
                values (:id,:tenantId,:type,'ASSESSMENT_RUN',:runId,:version,cast(:payload as jsonb))
                """, new MapSqlParameterSource().addValue("id",requestId).addValue("tenantId",tenant.getId())
                .addValue("type",EVENT_TYPE).addValue("runId",runId).addValue("version",version)
                .addValue("payload",json(Map.of("runId",runId,"policyIds",policyIds == null ? Set.of() : policyIds,
                        "assessmentStatus","PENDING","assessedSubjects",0,"failedPolicies",0))));
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() {
                if (!backgroundPolicy.allowsBackgroundTask("assessment.after-commit")) return;
                try { dispatch(tenant,requestId); }
                catch (RuntimeException error) { LOG.warn("Assessment request {} is retained for recovery",requestId); }
            }
        });
        return requestId;
    }

    @Scheduled(fixedDelayString="${app.ai-grid.assessment.poll-ms:5000}")
    public void recover() {
        if (!backgroundPolicy.allowsBackgroundTask("assessment.recover")) return;
        for (Tenant tenant : tenants.listActiveTenants()) {
            try {
                tenantExecution.run(tenant, () -> {
                    for (int index=0;index<5;index++) {
                        Claim claim=transactions.execute(status -> claim(null));
                        if (claim==null) break;
                        process(tenant,claim);
                    }
                });
            } catch (RuntimeException error) { LOG.warn("Assessment recovery failed for tenant {}",tenant.getId()); }
        }
    }

    void dispatch(Tenant tenant, UUID requestId) {
        if (!backgroundPolicy.allowsBackgroundTask("assessment.dispatch")) return;
        tenantExecution.run(tenant, () -> {
            Claim claim=transactions.execute(status -> claim(requestId));
            if (claim!=null) process(tenant,claim);
        });
    }

    Claim claim(UUID requestId) {
        jdbc.update("""
                update ai_grid_outbox set status='FAILED',processed_at=now(),last_error='Assessment attempt limit exhausted',
                    payload_json=payload_json || '{"assessmentStatus":"FAILED"}'::jsonb
                 where event_type=:type and status in ('PENDING','PROCESSING') and attempts>=5 and available_at<=now()
                   and (:allRequests or id=:requestId)
                """,new MapSqlParameterSource().addValue("type",EVENT_TYPE).addValue("allRequests",requestId==null).addValue("requestId",requestId));
        UUID token=UUID.randomUUID();
        return jdbc.query("""
                select id,aggregate_id,payload_json::text,attempts from ai_grid_outbox
                 where event_type=:type and status in ('PENDING','PROCESSING') and available_at<=now() and attempts<5
                   and (:allRequests or id=:requestId)
                 order by created_at,id for update skip locked limit 1
                """, new MapSqlParameterSource().addValue("type",EVENT_TYPE).addValue("allRequests",requestId==null)
                .addValue("requestId",requestId), rs -> {
            if (!rs.next()) return null;
            Claim claim=new Claim(rs.getObject(1,UUID.class),rs.getObject(2,UUID.class),token,rs.getString(3),rs.getInt(4)+1);
            jdbc.update("""
                    update ai_grid_outbox set status='PROCESSING',attempts=attempts+1,
                           available_at=now()+make_interval(secs=>:lease),
                           payload_json=payload_json || jsonb_build_object('claimToken',cast(:token as text),'assessmentStatus','RUNNING')
                     where id=:id and event_type=:type
                    """, leaseParameters(claim));
            return claim;
        });
    }

    void process(Tenant tenant, Claim claim) {
        var heartbeat=heartbeats.scheduleAtFixedRate(() -> {
            try { tenantExecution.run(tenant, () -> transactions.executeWithoutResult(status -> jdbc.update("""
                    update ai_grid_outbox set available_at=now()+make_interval(secs=>:lease)
                     where id=:id and event_type=:type and status='PROCESSING'
                       and payload_json->>'claimToken'=:token and available_at>now()
                    """,leaseParameters(claim)))); }
            catch (RuntimeException error) { LOG.warn("Assessment lease renewal failed for request {}",claim.id()); }
        },heartbeatSeconds,heartbeatSeconds,TimeUnit.SECONDS);
        int assessedSubjects=0;
        int evaluatedPolicies=0;
        try {
            JsonNode payload=mapper.readTree(claim.payload());
            Set<String> filter=new java.util.LinkedHashSet<>();
            payload.path("policyIds").forEach(value -> filter.add(value.asText()));
            Runnable guard=() -> {
                assertLease(claim);
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override public void beforeCommit(boolean readOnly) { fenceCommit(claim); }
                });
            };
            transactions.executeWithoutResult(status -> { assessments.lockTenant(tenant); guard.run(); ownership.resolveRun(tenant,claim.runId()); });
            var summary=assessments.evaluateCurrent(tenant,claim.runId(),filter,guard);
            List<AiGridAssessmentService.PolicyFailure> failures=new ArrayList<>(summary.failures());
            assessedSubjects=summary.assessedSubjects(); evaluatedPolicies=summary.evaluatedPolicies();
            // Baseline observation storage remains atomic with collection; only findings are reconciled here.
            for (String policyId : List.of("AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL","AI_GUARDRAIL_CONFIGURATION_CHANGED_AFTER_APPROVAL")) {
                if (!filter.isEmpty() && !filter.contains(policyId)) continue;
                try {
                    Integer baselineSubjects=transactions.execute(status -> {
                        assessments.lockTenant(tenant); guard.run();
                        int count=baselines.getObject().reconcileLatest(tenant,policyId);
                        jdbc.update("update ai_grid_coverage_gaps set status='RESOLVED',resolved_at=now() where policy_id=:id and artifact_id is null and state='POLICY_EVALUATION_ERROR'",Map.of("id",policyId));
                        return count;
                    });
                    if (baselineSubjects!=null && baselineSubjects>0) { assessedSubjects+=baselineSubjects; evaluatedPolicies++; }
                } catch (RuntimeException error) {
                    if (error instanceof LeaseLostException) throw error;
                    var failure=AiGridAssessmentService.PolicyFailure.from(policyId,error);
                    failures.add(failure);
                    transactions.executeWithoutResult(status -> { assessments.lockTenant(tenant); guard.run(); assessments.recordFailure(tenant,claim.runId(),failure); });
                }
            }
            transactions.executeWithoutResult(status -> {
                assessments.lockTenant(tenant); guard.run();
                UUID epoch=coverage.refreshCurrent(tenant,claim.runId());
                systems.deriveForCurrentEpoch(tenant,epoch,claim.runId());
                reconciliation.reconcileCurrent(tenant,epoch,claim.runId());
                exposures.correlateCurrentEpoch(tenant,epoch,claim.runId());
                readiness.computeCurrent(tenant,epoch,claim.runId());
                metrics.refreshAssessmentCounters(claim.runId());
                metrics.refreshUtilityMetrics(tenant,claim.runId(),coverage.currentCandidates());
                refresh.getObject().requestStaleEvidence(tenant);
            });
            transactions.executeWithoutResult(status -> { assertLease(claim); findings.refreshProjectionAfterCommit(tenant); });
            String assessmentStatus=failures.isEmpty() ? "COMPLETE" : evaluatedPolicies>0 ? "PARTIAL" : "FAILED";
            boolean retry=failures.stream().anyMatch(AiGridAssessmentService.PolicyFailure::retryable) && claim.attempt()<5;
            finish(claim,retry ? "PENDING" : failures.isEmpty() ? "PROCESSED" : "FAILED",assessmentStatus,assessedSubjects,evaluatedPolicies,failures);
        } catch (LeaseLostException ignored) {
            LOG.info("Assessment request {} was reclaimed; old delivery stopped",claim.id());
        } catch (Exception error) {
            boolean retry=retryable(error) && claim.attempt()<5;
            finish(claim,retry ? "PENDING" : "FAILED",assessedSubjects>0 ? "PARTIAL" : "FAILED",assessedSubjects,evaluatedPolicies,
                    List.of(new AiGridAssessmentService.PolicyFailure("FINALIZATION","ASSESSMENT_PROCESSING_ERROR",
                            "Assessment processing failed",retryable(error))));
        } finally { heartbeat.cancel(false); }
    }

    private void fenceCommit(Claim claim) {
        Boolean owned=jdbc.query("""
                select payload_json->>'claimToken'=:token and status='PROCESSING' and available_at>now()
                  from ai_grid_outbox where id=:id and event_type=:type for update
                """,leaseParameters(claim),rs -> rs.next() && rs.getBoolean(1));
        if (!Boolean.TRUE.equals(owned)) throw new LeaseLostException();
    }

    void assertLease(Claim claim) {
        Integer owned=jdbc.queryForObject("""
                select count(*) from ai_grid_outbox where id=:id and event_type=:type and status='PROCESSING'
                  and payload_json->>'claimToken'=:token and available_at>now()
                """,leaseParameters(claim),Integer.class);
        if (owned==null || owned!=1) throw new LeaseLostException();
    }

    private void finish(Claim claim,String status,String assessmentStatus,int subjects,int evaluatedPolicies,
                        List<AiGridAssessmentService.PolicyFailure> failures) {
        transactions.executeWithoutResult(tx -> jdbc.update("""
                update ai_grid_outbox set status=:status,
                       available_at=case when :status='PENDING' then now()+interval '1 minute' else available_at end,
                       processed_at=case when :status='PENDING' then null else now() end,last_error=:error,
                       payload_json=payload_json || cast(:summary as jsonb)
                 where id=:id and event_type=:type and status='PROCESSING'
                   and payload_json->>'claimToken'=:token and available_at>now()
                """,leaseParameters(claim).addValue("status",status)
                .addValue("error",failures.isEmpty() ? null : "Assessment contains policy failures")
                .addValue("summary",json(Map.of("assessmentStatus",status.equals("PENDING") ? "PENDING" : assessmentStatus,"assessedSubjects",subjects,
                        "failedPolicies",failures.size(),"failureSummaries",failures,"evaluatedPolicies",evaluatedPolicies)))));
    }

    public ProcessingStatus policyStatus(Tenant tenant,String policyId) {
        return tenantExecution.run(tenant,() -> jdbc.query("""
                select payload_json::text from ai_grid_outbox where event_type=:type
                   and (jsonb_array_length(payload_json->'policyIds')=0 or jsonb_exists(payload_json->'policyIds',:policyId))
                 order by created_at desc,id desc limit 1
                """,Map.of("type",EVENT_TYPE,"policyId",policyId),rs -> rs.next() ? processingStatus(rs.getString(1))
                        : new ProcessingStatus("COMPLETE",0,0,List.of(),0)));
    }
    public ProcessingStatus status(Tenant tenant,UUID runId) {
        return tenantExecution.run(tenant,() -> jdbc.query("""
                select payload_json::text from ai_grid_outbox where event_type=:type and aggregate_id=:runId
                 order by created_at desc,id desc limit 1
                """,Map.of("type",EVENT_TYPE,"runId",runId),rs -> rs.next() ? processingStatus(rs.getString(1))
                        : legacyStatus(runId)));
    }
    public ProcessingStatus statusForRequest(Tenant tenant, UUID requestId) {
        return tenantExecution.run(tenant, () -> jdbc.query("select payload_json::text from ai_grid_outbox where id=:id and event_type=:type",
                Map.of("id",requestId,"type",EVENT_TYPE), rs -> rs.next() ? processingStatus(rs.getString(1))
                        : new ProcessingStatus("MISSING",0,0,List.of(),0)));
    }
    private ProcessingStatus legacyStatus(UUID runId) {
        return jdbc.queryForObject("""
                select count(*) subjects,count(distinct policy_id) policies,
                       count(distinct policy_id) filter(where decision='ERROR') failed
                  from ai_grid_assessments where run_id=:runId and subject_type<>'EXECUTION'
                """,Map.of("runId",runId),(rs,row) -> new ProcessingStatus(rs.getInt("subjects")==0 ? "PENDING"
                        : rs.getInt("failed")==0 ? "COMPLETE" : rs.getInt("failed")<rs.getInt("policies") ? "PARTIAL" : "FAILED",
                        rs.getInt("subjects"),rs.getInt("failed"),List.of(),rs.getInt("policies")-rs.getInt("failed")));
    }
    private ProcessingStatus processingStatus(String raw) {
        try {
            JsonNode payload=mapper.readTree(raw);
            List<AiGridAssessmentService.PolicyFailure> failures=new ArrayList<>();
            for (JsonNode failure:payload.path("failureSummaries")) failures.add(mapper.treeToValue(failure,AiGridAssessmentService.PolicyFailure.class));
            // A delayed retry is pending even though its prior partial/failed result remains inspectable.
            return new ProcessingStatus(payload.path("assessmentStatus").asText("PENDING"),payload.path("assessedSubjects").asInt(),
                    payload.path("failedPolicies").asInt(),List.copyOf(failures),payload.path("evaluatedPolicies").asInt());
        } catch (java.io.IOException error) { throw new IllegalStateException("Invalid assessment status",error); }
    }

    public void replayFailure(Tenant tenant,UUID requestId) {
        tenantExecution.run(tenant, () -> transactions.executeWithoutResult(status -> jdbc.update("""
                update ai_grid_outbox set status='PENDING',attempts=0,available_at=now(),processed_at=null,last_error=null,
                    payload_json=(payload_json-'claimToken') || '{"assessmentStatus":"PENDING"}'::jsonb
                 where id=:id and event_type=:type and status in ('FAILED','PROCESSED')
                   and payload_json->>'assessmentStatus' in ('FAILED','PARTIAL')
                """,Map.of("id",requestId,"type",EVENT_TYPE))));
    }

    static boolean retryable(Throwable error) {
        for (Throwable cause=error;cause!=null;cause=cause.getCause()) {
            if (cause instanceof java.sql.SQLException sql) {
                String state=sql.getSQLState();
                if (state!=null && (state.startsWith("08") || state.equals("40001") || state.equals("40P01"))) return true;
            }
            if (cause instanceof org.springframework.dao.TransientDataAccessResourceException
                    || cause instanceof org.springframework.dao.CannotAcquireLockException
                    || cause instanceof org.springframework.transaction.CannotCreateTransactionException) return true;
        }
        return false;
    }
    private MapSqlParameterSource leaseParameters(Claim claim) {
        return new MapSqlParameterSource().addValue("id",claim.id()).addValue("token",claim.token().toString())
                .addValue("type",EVENT_TYPE).addValue("lease",(double)leaseSeconds);
    }
    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (java.io.IOException error) { throw new IllegalArgumentException("Invalid assessment request",error); }
    }
    record Claim(UUID id,UUID runId,UUID token,String payload,int attempt) {}
    public record ProcessingStatus(String assessmentStatus,int assessedSubjects,int failedPolicies,
                                   List<AiGridAssessmentService.PolicyFailure> failureSummaries,int evaluatedPolicies) {}
    static final class LeaseLostException extends RuntimeException {}
}
