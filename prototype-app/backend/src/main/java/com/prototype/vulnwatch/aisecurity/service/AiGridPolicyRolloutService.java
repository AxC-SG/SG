package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Idempotent, tenant-isolated rollout executor for immutable policy versions. */
@Service
public class AiGridPolicyRolloutService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AiGridAssessmentService assessments;
    private com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy backgroundPolicy=com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy.allowAll();
    @org.springframework.beans.factory.annotation.Autowired
    void configureBackgroundPolicy(com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy policy) { backgroundPolicy=policy; }

    public AiGridPolicyRolloutService(NamedParameterJdbcTemplate jdbc, TenantService tenants,
                                      TenantSchemaExecutionService tenantExecution,
                                      TransactionTemplate transactions, AiGridAssessmentService assessments) {
        this.jdbc = jdbc;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.assessments = assessments;
    }

    private org.springframework.beans.factory.ObjectProvider<AiGridAssessmentWorker> worker;
    @org.springframework.beans.factory.annotation.Autowired
    void configureWorker(org.springframework.beans.factory.ObjectProvider<AiGridAssessmentWorker> worker) { this.worker=worker; }

    public List<Rollout> rollouts() {
        return TenantContext.runAsPlatform(() -> jdbc.query("""
                select id,release_id,release_type,policy_id,previous_version,new_version,package_digest,status,created_at,completed_at
                  from platform.ai_grid_policy_rollouts order by created_at desc, policy_id
                """, (rs, row) -> new Rollout(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8),
                rs.getTimestamp(9).toInstant(), rs.getTimestamp(10) == null ? null : rs.getTimestamp(10).toInstant())));
    }

    public RolloutDetail rollout(UUID rolloutId) {
        Rollout value = rollouts().stream().filter(item -> item.id().equals(rolloutId)).findFirst()
                .orElseThrow(() -> new ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND, "Policy rollout not found"));
        List<RolloutTask> tasks = TenantContext.runAsPlatform(() -> jdbc.query("""
                select id,tenant_id,status,attempts,next_retry_at,source_snapshot_run_id,assessment_run_id,failure_detail,updated_at
                  from platform.ai_grid_policy_rollout_tasks where rollout_id=:id order by created_at
                """, Map.of("id", rolloutId), (rs, row) -> new RolloutTask(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                rs.getString(3), rs.getInt(4), instant(rs, 5), rs.getObject(6, UUID.class), rs.getObject(7, UUID.class), rs.getString(8), instant(rs, 9))));
        return new RolloutDetail(value, tasks);
    }

    public void retry(UUID rolloutId) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                update platform.ai_grid_policy_rollout_tasks set status='PENDING', attempts=0,next_retry_at=null,
                       failure_detail=null, updated_at=now() where rollout_id=:id and status in ('FAILED','WAITING_FOR_SNAPSHOT')
                """, Map.of("id", rolloutId)));
    }

    @Scheduled(fixedDelayString = "${app.ai-grid.policy-rollout.delay-ms:5000}")
    public void processPendingTasks() {
        if (!backgroundPolicy.allowsBackgroundTask("policy-rollout.poll")) return;
        try {
            for (int index = 0; index < 25; index++) {
                if (!backgroundPolicy.allowsBackgroundTask("policy-rollout.claim")) return;
                ClaimedTask task = claim();
                if (task == null) return;
                process(task);
            }
        } catch (RuntimeException ignored) {
            // A failed task is recorded below; the scheduler must remain alive for other tenants.
        }
    }

    private ClaimedTask claim() {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> jdbc.query("""
                select t.id,t.tenant_id,t.rollout_id,t.assessment_request_id,t.source_snapshot_run_id
                 from platform.ai_grid_policy_rollout_tasks t
                  join platform.ai_grid_policy_rollouts r on r.id=t.rollout_id
                 where r.status='PENDING' and (t.status in ('PENDING','FAILED','WAITING_FOR_ASSESSMENT','WAITING_FOR_SNAPSHOT') or (t.status='PROCESSING' and t.lease_expires_at<=now())) and (t.attempts<5 or t.assessment_request_id is not null)
                   and (t.next_retry_at is null or t.next_retry_at <= now())
                 order by t.created_at for update of t skip locked limit 1
                """, rs -> {
            if (!rs.next()) return null;
            ClaimedTask task = new ClaimedTask(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                    rs.getObject(3, UUID.class), UUID.randomUUID(), rs.getObject(4,UUID.class), rs.getObject(5,UUID.class));
            jdbc.update("update platform.ai_grid_policy_rollout_tasks set status='PROCESSING', attempts=attempts+case when assessment_request_id is null then 1 else 0 end, claim_token=:token,lease_expires_at=now()+interval '2 minutes', "
                    + "started_at=coalesce(started_at,now()), updated_at=now() where id=:id", Map.of("id", task.id(),"token",task.token()));
            return task;
        })));
    }

    private void process(ClaimedTask task) {
        try {
            Tenant tenant = tenants.requireTenantUuid(task.tenantId());
            if (!releaseBindingIsValid(task)) {
                cancel(task, "Cancelled: release binding, approval, digest, distribution, or lifecycle is no longer valid");
                return;
            }
            UUID runId = task.sourceRunId()!=null ? task.sourceRunId() : tenantExecution.run(tenant, () -> transactions.execute(status -> latestSnapshotRun()));
            if (runId == null) {
                updateWaiting(task);
                return;
            }
            String policyId=TenantContext.runAsPlatform(() -> jdbc.queryForObject(
                    "select policy_id from platform.ai_grid_policy_rollouts where id=:id",Map.of("id",task.rolloutId()),String.class));
            UUID requestId=task.requestId();
            if (requestId==null) {
                // Persist the exact accepted request and task transition in the same transaction.
                tenantExecution.run(tenant, () -> transactions.executeWithoutResult(status -> {
                    var owned=jdbc.query("select id from platform.ai_grid_policy_rollout_tasks where id=:id and claim_token=:token and status='PROCESSING' and lease_expires_at>clock_timestamp() for update",Map.of("id",task.id(),"token",task.token()),(org.springframework.jdbc.core.ResultSetExtractor<Boolean>) rs -> rs.next());
                    if (!Boolean.TRUE.equals(owned)) throw new IllegalStateException("Rollout ownership expired");
                    UUID accepted=worker.getObject().enqueue(tenant,runId,java.util.Set.of(policyId));
                    jdbc.update("update platform.ai_grid_policy_rollout_tasks set assessment_request_id=:request,source_snapshot_run_id=:run,status='WAITING_FOR_ASSESSMENT',next_retry_at=now()+interval '5 seconds',claim_token=null,lease_expires_at=null,updated_at=now() where id=:id and claim_token=:token",Map.of("request",accepted,"run",runId,"id",task.id(),"token",task.token()));
                }));
                return;
            }
            var result=worker.getObject().statusForRequest(tenant,requestId);
            if (java.util.Set.of("PENDING","RUNNING").contains(result.assessmentStatus())) {
                update(task,"WAITING_FOR_ASSESSMENT",runId,null,null);
                return;
            }
            if (!"COMPLETE".equals(result.assessmentStatus())) throw new IllegalStateException("Policy rollout assessment is "+result.assessmentStatus());
            if (!releaseBindingIsValid(task)) { cancel(task,"Release binding changed during assessment"); return; }
            complete(task, runId);
        } catch (RuntimeException ex) {
            fail(task, ex.getMessage());
        }
    }

    private UUID latestSnapshotRun() {
        return jdbc.query("""
                select run_id from ai_grid_snapshot_manifests group by run_id
                 order by max(observed_at) desc limit 1
                """, rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
    }

    private boolean releaseBindingIsValid(ClaimedTask task) {
        return TenantContext.runAsPlatform(() -> {
            Integer matches = jdbc.queryForObject("""
                select count(*)
                  from platform.ai_grid_policy_rollouts r
                  join platform.ai_grid_policy_release_bindings binding on r.release_id = binding.id::text
                  join platform.ai_grid_policy_release_decisions decision on decision.id = binding.approval_decision_id
                  join %s policy on policy.policy_id = binding.policy_id
                      and policy.version = binding.policy_version
                  join platform.ai_grid_policy_distribution distribution on distribution.policy_id = binding.policy_id
                 where r.id=:rolloutId and binding.state='ACTIVE' and decision.decision='APPROVED'
                   and decision.approved_package_digest=binding.approved_package_digest
                   and policy.lifecycle='PUBLISHED' and policy.package_digest=binding.approved_package_digest
                   and distribution.available=true
                   and distribution.pinned_version=binding.policy_version
                """.formatted(AiGridPolicyResolution.versions(":tenantId")), Map.of("rolloutId", task.rolloutId(), "tenantId", task.tenantId()), Integer.class);
            return matches != null && matches > 0;
        });
    }

    private void updateWaiting(ClaimedTask task) { update(task,"WAITING_FOR_SNAPSHOT",null,null,null); }
    private void complete(ClaimedTask task,UUID runId) { update(task,"COMPLETED",runId,runId,null); }
    private void fail(ClaimedTask task,String detail) { update(task,"FAILED",null,null,"Policy rollout execution failed; inspect the assessment request"); }
    private void cancel(ClaimedTask task,String detail) { update(task,"CANCELLED",null,null,detail); }
    private void update(ClaimedTask task,String state,UUID sourceRun,UUID assessmentRun,String detail) {
        TenantContext.runAsPlatform(() -> transactions.executeWithoutResult(status -> {
            int changed=jdbc.update("""
                update platform.ai_grid_policy_rollout_tasks set status=:state, source_snapshot_run_id=coalesce(:sourceRun,source_snapshot_run_id),
                    assessment_run_id=coalesce(:assessmentRun,assessment_run_id),failure_detail=:detail,
                    next_retry_at=case when :state in ('FAILED','WAITING_FOR_SNAPSHOT') then now()+interval '1 minute'
                        when :state='WAITING_FOR_ASSESSMENT' then now()+interval '5 seconds' else null end,
                    completed_at=case when :state in ('COMPLETED','CANCELLED') then now() else null end,
                    claim_token=null,lease_expires_at=null,updated_at=now()
                 where id=:id and claim_token=:token and status='PROCESSING' and lease_expires_at>clock_timestamp()
                """,new MapSqlParameterSource().addValue("id",task.id()).addValue("token",task.token()).addValue("state",state)
                    .addValue("sourceRun",sourceRun).addValue("assessmentRun",assessmentRun).addValue("detail",detail));
            if (changed==1 && "COMPLETED".equals(state)) jdbc.update("""
                    update platform.ai_grid_policy_rollouts r set status='COMPLETED',completed_at=now()
                     where r.id=:id and not exists (select 1 from platform.ai_grid_policy_rollout_tasks t where t.rollout_id=r.id and t.status<>'COMPLETED')
                    """,Map.of("id",task.rolloutId()));
        }));
    }

    private static Instant instant(java.sql.ResultSet rs, int column) throws java.sql.SQLException {
        java.sql.Timestamp value = rs.getTimestamp(column); return value == null ? null : value.toInstant();
    }
    public record Rollout(UUID id, String releaseId, String releaseType, String policyId, String previousVersion,
                          String newVersion, String packageDigest, String status, Instant createdAt, Instant completedAt) {}
    public record RolloutTask(UUID id, UUID tenantId, String status, int attempts, Instant nextRetryAt,
                              UUID sourceSnapshotRunId, UUID assessmentRunId, String failureDetail, Instant updatedAt) {}
    public record RolloutDetail(Rollout rollout, List<RolloutTask> tasks) {}
    private record ClaimedTask(UUID id, UUID tenantId, UUID rolloutId, UUID token, UUID requestId, UUID sourceRunId) {}
}
