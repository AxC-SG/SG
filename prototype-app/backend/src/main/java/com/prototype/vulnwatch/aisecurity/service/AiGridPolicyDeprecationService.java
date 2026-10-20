package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Explicit, non-rekeying retirement of a logical AI Grid policy. */
@Service
public class AiGridPolicyDeprecationService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final FindingRepository findings;
    private final FindingWorkflowService workflow;
    private final AuditEventService audit;

    public AiGridPolicyDeprecationService(NamedParameterJdbcTemplate jdbc, TransactionTemplate transactions,
                                          TenantService tenants, TenantSchemaExecutionService tenantExecution,
                                          FindingRepository findings, FindingWorkflowService workflow,
                                          AuditEventService audit) {
        this.jdbc = jdbc;
        this.transactions = new TransactionTemplate(transactions.getTransactionManager(), transactions);
        this.transactions.setTimeout(90);
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.findings = findings;
        this.workflow = workflow;
        this.audit = audit;
    }

    public Deprecation deprecate(String policyId, DeprecationCommand command, String actor) {
        require(policyId, "policyId");
        if (command == null) throw badRequest("Deprecation command is required");
        require(command.reason(), "reason");
        require(command.idempotencyKey(), "idempotencyKey");
        AtomicBoolean created = new AtomicBoolean(false);
        Deprecation deprecation = TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            Deprecation existing = byIdempotencyKey(command.idempotencyKey());
            if (existing != null) {
                if (!existing.policyId().equals(policyId)) throw conflict("Idempotency key belongs to another policy");
                return existing;
            }
            List<String> versions = jdbc.query("""
                    select version from platform.ai_grid_policy_versions
                     where policy_id = :policyId and lifecycle <> 'DEPRECATED'
                     order by created_at desc, version desc for update
                    """, Map.of("policyId", policyId), (rs, row) -> rs.getString(1));
            if (versions.isEmpty()) {
                Deprecation completedWhileWaiting = byIdempotencyKey(command.idempotencyKey());
                if (completedWhileWaiting != null && completedWhileWaiting.policyId().equals(policyId)) {
                    return completedWhileWaiting;
                }
                throw notFound("AI Grid policy not found or already deprecated");
            }
            String version = versions.get(0);
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    update platform.ai_grid_policy_versions
                       set lifecycle = 'DEPRECATED', published_at = null
                     where policy_id = :policyId and lifecycle <> 'DEPRECATED'
                    """, Map.of("policyId", policyId));
            jdbc.update("""
                    insert into platform.ai_grid_policy_distribution
                        (policy_id, available, default_selection, rollout_stage, canary_tenant_ids_json, pinned_version, updated_by)
                    values (:policyId, false, 'DISABLED', 'PAUSED', '[]'::jsonb, null, :actor)
                    on conflict (policy_id) do update set available = false, default_selection = 'DISABLED',
                        rollout_stage = 'PAUSED', canary_tenant_ids_json = '[]'::jsonb, pinned_version = null,
                        updated_by = excluded.updated_by, updated_at = now()
                    """, Map.of("policyId", policyId, "actor", actor));
            jdbc.update("""
                    insert into platform.ai_grid_policy_deprecations
                        (id, policy_id, policy_version, reason, successor_policy_id, deprecated_by, idempotency_key)
                    values (:id, :policyId, :version, :reason, :successor, :actor, :idempotencyKey)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("policyId", policyId)
                    .addValue("version", version).addValue("reason", command.reason().trim())
                    .addValue("successor", blank(command.successorPolicyId())).addValue("actor", actor)
                    .addValue("idempotencyKey", command.idempotencyKey().trim()));
            jdbc.update("""
                    insert into platform.ai_grid_policy_deprecation_tasks (id, deprecation_id, tenant_id)
                    select md5(:deprecationId || ':' || t.id::text)::uuid, :id, t.id
                      from platform.tenants t
                     where t.status = 'ACTIVE' and t.deleted_at is null
                    on conflict (deprecation_id, tenant_id) do nothing
                    """, Map.of("id", id, "deprecationId", id.toString()));
            created.set(true);
            return byId(id);
        }));
        if (created.get()) {
            Tenant auditTenant = tenants.getDefaultTenant();
            tenantExecution.run(auditTenant, () -> {
                audit.recordExplicitActor(auditTenant.getId(), actor, "PLATFORM_OWNER", "ai_grid.policy.deprecated",
                        "ai_grid_policy", policyId,
                        "{\"successorPolicyId\":" + jsonString(blank(command.successorPolicyId())) + "}", "SUCCESS");
                return null;
            });
        }
        return deprecation;
    }

    private com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy backgroundPolicy=com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy.allowAll();
    @org.springframework.beans.factory.annotation.Autowired
    void configureBackgroundPolicy(com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy policy) { backgroundPolicy=policy; }

    @Scheduled(fixedDelayString = "${app.ai-grid.policy-deprecation.delay-ms:5000}")
    public void processPendingTasks() {
        if (!backgroundPolicy.allowsBackgroundTask("processPendingTasks")) return;
        for (int index = 0; index < 25; index++) {
            if (!backgroundPolicy.allowsBackgroundTask("policy-deprecation.claim")) return;
            ClaimedTask task = claim();
            if (task == null) return;
            process(task);
        }
    }

    private void process(ClaimedTask task) {
        try {
            Tenant tenant = tenants.requireTenantUuid(task.tenantId());
            tenantExecution.run(tenant, () -> transactions.execute(status -> {
                // The platform task and tenant effects share one transaction. Holding this
                // row prevents another claimant from processing the same retirement.
                Boolean owned = jdbc.query("""
                        select id from platform.ai_grid_policy_deprecation_tasks
                         where id=:id and claim_token=:token and state='PROCESSING'
                           and lease_expires_at>clock_timestamp() for update
                        """, Map.of("id", task.id(), "token", task.token()),
                        (org.springframework.jdbc.core.ResultSetExtractor<Boolean>) rs -> rs.next());
                if (!Boolean.TRUE.equals(owned)) throw new IllegalStateException("Deprecation ownership expired");
                for (Finding finding : findings.findOpenAiFindingsByTenantAndPolicy(tenant, task.policyId())) {
                    workflow.autoCloseFinding(finding, FindingCloseReason.AUTO_POLICY_PLATFORM_DEPRECATED,
                            "Finding closed because its AI Grid policy was deprecated",
                            Map.of("policyId", task.policyId(), "deprecationId", task.deprecationId().toString()), Instant.now());
                    findings.save(finding);
                }
                findings.flush();
                int completed = jdbc.update("""
                        update platform.ai_grid_policy_deprecation_tasks
                           set state='COMPLETED',failure_detail=null,next_retry_at=null,
                               completed_at=now(),updated_at=now(),claim_token=null,lease_expires_at=null
                         where id=:id and claim_token=:token and state='PROCESSING'
                           and lease_expires_at>clock_timestamp()
                        """, Map.of("id", task.id(), "token", task.token()));
                if (completed != 1) throw new IllegalStateException("Deprecation ownership expired");
                return null;
            }));
        } catch (RuntimeException ex) {
            fail(task);
        }
    }

    private ClaimedTask claim() {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> jdbc.query("""
                select task.id, task.tenant_id, task.deprecation_id, deprecation.policy_id
                  from platform.ai_grid_policy_deprecation_tasks task
                  join platform.ai_grid_policy_deprecations deprecation on deprecation.id = task.deprecation_id
                 where (task.state in ('PENDING', 'FAILED')
                        or (task.state='PROCESSING' and task.lease_expires_at<=clock_timestamp()))
                   and (task.next_retry_at is null or task.next_retry_at <= now())
                 order by task.created_at for update of task skip locked limit 1
                """, rs -> {
            if (!rs.next()) return null;
            ClaimedTask task = new ClaimedTask(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                    rs.getObject(3, UUID.class), rs.getString(4), UUID.randomUUID());
            jdbc.update("update platform.ai_grid_policy_deprecation_tasks set state='PROCESSING', attempts=attempts+1, "
                    + "claim_token=:token, lease_expires_at=clock_timestamp()+interval '2 minutes', "
                    + "started_at=coalesce(started_at,now()), updated_at=now() where id=:id", Map.of("id", task.id(), "token", task.token()));
            return task;
        })));
    }

    private void fail(ClaimedTask task) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                update platform.ai_grid_policy_deprecation_tasks
                   set state='FAILED', failure_detail='Policy deprecation execution failed',
                       next_retry_at=now() + interval '1 minute', completed_at=null,
                       claim_token=null,lease_expires_at=null,updated_at=now()
                 where id=:id and claim_token=:token and state='PROCESSING'
                   and lease_expires_at>clock_timestamp()
                """, Map.of("id", task.id(), "token", task.token())));
    }

    private Deprecation byIdempotencyKey(String key) {
        return jdbc.query("select * from platform.ai_grid_policy_deprecations where idempotency_key=:key",
                Map.of("key", key.trim()), rs -> rs.next() ? map(rs) : null);
    }

    private Deprecation byId(UUID id) {
        return jdbc.query("select * from platform.ai_grid_policy_deprecations where id=:id", Map.of("id", id),
                rs -> rs.next() ? map(rs) : null);
    }

    private Deprecation map(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new Deprecation(rs.getObject("id", UUID.class), rs.getString("policy_id"), rs.getString("policy_version"),
                rs.getString("reason"), rs.getString("successor_policy_id"), rs.getString("deprecated_by"),
                rs.getTimestamp("deprecated_at").toInstant(), rs.getString("idempotency_key"));
    }

    private static String blank(String value) { return value == null || value.isBlank() ? null : value.trim(); }
    private static void require(String value, String field) { if (value == null || value.isBlank()) throw badRequest(field + " is required"); }
    private static String jsonString(String value) { return value == null ? "null" : "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }
    private static ResponseStatusException badRequest(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }
    private static ResponseStatusException conflict(String message) { return new ResponseStatusException(HttpStatus.CONFLICT, message); }
    private static ResponseStatusException notFound(String message) { return new ResponseStatusException(HttpStatus.NOT_FOUND, message); }

    private record ClaimedTask(UUID id, UUID tenantId, UUID deprecationId, String policyId, UUID token) {}
    public record DeprecationCommand(String reason, String successorPolicyId, String idempotencyKey) {}
    public record Deprecation(UUID id, String policyId, String policyVersion, String reason, String successorPolicyId,
                              String deprecatedBy, Instant deprecatedAt, String idempotencyKey) {}
}
