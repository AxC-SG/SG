package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.*;
import com.prototype.vulnwatch.support.*;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Real rollout/outbox transactions; assessment execution is deliberately delayed on an API node. */
@PostgresIntegrationTest
class AiGridPolicyRolloutRecoveryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("closure_rollout");

    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
        registry.add("app.runtime.role", () -> "api");
    }

    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired AiGridPolicyRolloutService rollouts;
    @Autowired AiGridAssessmentWorker assessments;
    @Autowired AiGridValidationGovernanceService governance;
    @Autowired JdbcTemplate jdbc;
    Tenant tenant;
    UUID taskId, rolloutId, bindingId, runId;
    String policyId;

    @BeforeEach void setup() {
        TenantContext.clear();
        String slug = "rollout-" + UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        tenant = tenants.resolveTenantUuid(tenant.getId());
        taskId = UUID.randomUUID(); rolloutId = UUID.randomUUID(); bindingId = UUID.randomUUID();
        runId = UUID.randomUUID(); policyId = "CLOSURE_" + UUID.randomUUID();
        UUID approval = UUID.randomUUID();
        String digest = "a".repeat(64);
        jdbc.update("""
                insert into platform.ai_grid_policy_versions
                  (policy_id,version,name,description,severity,lifecycle,workflow_class,default_selection,
                   artifact_types_json,required_resource_families_json,required_facts_json,predicate_json,
                   reason_code,remediation,package_digest)
                values (?,'1.0.0','Closure policy','Controlled static fixture','LOW','VALIDATED',
                        'POSTURE_FINDING','ENABLED','[]','[]','[]','{"always":false}','CLOSURE','Review',?)
                """, policyId, digest);
        jdbc.update("""
                insert into platform.ai_grid_policy_release_decisions
                  (id,policy_id,policy_version,decision,reason,decided_by,package_digest,approved_package_digest)
                values (?,?,'1.0.0','APPROVED','Controlled fixture','test',?,?)
                """, approval, policyId, digest, digest);
        jdbc.update("update platform.ai_grid_policy_versions set lifecycle='PUBLISHED' where policy_id=?", policyId);
        jdbc.update("""
                insert into platform.ai_grid_policy_release_bindings
                  (id,approval_decision_id,policy_id,policy_version,approved_package_digest,
                   distribution_snapshot_json,target_tenant_ids_json,bound_by)
                values (?,?,?,'1.0.0',?,'{}',cast(? as jsonb),'test')
                """, bindingId, approval, policyId, digest, "[\"" + tenant.getId() + "\"]");
        jdbc.update("""
                insert into platform.ai_grid_policy_distribution
                  (policy_id,available,pinned_version,approved_package_digest,release_decision_id)
                values (?,true,'1.0.0',?,?)
                """, policyId, digest, approval);
        jdbc.update("""
                insert into platform.ai_grid_policy_rollouts
                  (id,release_id,release_type,policy_id,new_version,package_digest,
                   approved_package_digest,release_decision_id,distribution_snapshot_json)
                values (?,?,'POLICY_VERSION',?,'1.0.0',?,?,?,'{}')
                """, rolloutId, bindingId.toString(), policyId, digest, digest, approval);
        jdbc.update("""
                insert into platform.ai_grid_policy_rollout_tasks
                  (id,rollout_id,tenant_id,source_snapshot_run_id) values (?,?,?,?)
                """, taskId, rolloutId, tenant.getId(), runId);
        // Drive only the rollout callback; the real assessment worker stays API-role blocked.
        rollouts.configureBackgroundPolicy(BackgroundTaskExecutionPolicy.allowAll());
    }

    @AfterEach void clear() { TenantContext.clear(); }

    @Test void mergedPendingRequestSurvivesDelayedPollingAndCompletesByExactIdentity() {
        UUID existing = assessments.enqueue(tenant, runId, Set.of("OTHER_CONTROLLED_POLICY"));
        rollouts.processPendingTasks();
        assertEquals("WAITING_FOR_ASSESSMENT", state());
        assertEquals(existing, requestId());
        scoped.run(tenant, () -> {
            assertEquals(1, jdbc.queryForObject("select count(*) from ai_grid_outbox", Integer.class));
            assertTrue(jdbc.queryForObject("select payload_json->'policyIds' ?? ? from ai_grid_outbox where id=?",
                    Boolean.class, policyId, existing));
        });
        for (int i = 0; i < 7; i++) { due(); rollouts.processPendingTasks(); }
        assertEquals("WAITING_FOR_ASSESSMENT", state());
        assertEquals(1, attempts());
        // A newer request for the same run must not make the exact accepted one appear complete.
        scoped.run(tenant, () -> jdbc.update("update ai_grid_outbox set attempts=1 where id=?", existing));
        UUID newer = assessments.enqueue(tenant, runId, Set.of(policyId));
        result(newer, "COMPLETE");
        due(); rollouts.processPendingTasks();
        assertEquals("WAITING_FOR_ASSESSMENT", state());
        result(existing, "RUNNING"); due(); rollouts.processPendingTasks();
        assertEquals("WAITING_FOR_ASSESSMENT", state());
        result(existing, "COMPLETE"); due(); rollouts.processPendingTasks();
        assertEquals("COMPLETED", state());
        assertEquals("COMPLETED", jdbc.queryForObject("select status from platform.ai_grid_policy_rollouts where id=?", String.class, rolloutId));
        assertEquals(existing, requestId());
    }

    @Test void expiredClaimRecoversWithoutResettingHealthyClaimOrDuplicatingAcceptedRequest() {
        jdbc.update("""
                update platform.ai_grid_policy_rollout_tasks set status='PROCESSING',claim_token=?,
                  lease_expires_at=clock_timestamp()+interval '2 minutes' where id=?
                """, UUID.randomUUID(), taskId);
        rollouts.processPendingTasks();
        assertNull(requestId());
        jdbc.update("update platform.ai_grid_policy_rollout_tasks set lease_expires_at=clock_timestamp()-interval '1 second' where id=?", taskId);
        rollouts.processPendingTasks();
        assertEquals("WAITING_FOR_ASSESSMENT", state());
        UUID accepted = requestId();
        jdbc.update("""
                update platform.ai_grid_policy_rollout_tasks set status='PROCESSING',claim_token=?,
                  lease_expires_at=clock_timestamp()-interval '1 second',next_retry_at=null where id=?
                """, UUID.randomUUID(), taskId);
        rollouts.processPendingTasks();
        assertEquals(accepted, requestId());
        assertEquals("WAITING_FOR_ASSESSMENT", state());
        scoped.run(tenant, () -> assertEquals(1, jdbc.queryForObject("select count(*) from ai_grid_outbox", Integer.class)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"WAITING_FOR_ASSESSMENT", "PROCESSING"})
    void bindingRevocationCancelsWaitingOrClaimedTaskBeforeAnotherCallback(String state) {
        rollouts.processPendingTasks();
        assertEquals("WAITING_FOR_ASSESSMENT", state());
        UUID accepted = requestId();
        if ("PROCESSING".equals(state)) jdbc.update("""
                update platform.ai_grid_policy_rollout_tasks set status='PROCESSING',claim_token=?,
                  lease_expires_at=clock_timestamp()+interval '2 minutes' where id=?
                """, UUID.randomUUID(), taskId);
        governance.revokeReleaseBinding(bindingId, "Controlled revocation", "test");
        assertEquals("CANCELLED", state());
        assertNull(jdbc.queryForObject("select claim_token from platform.ai_grid_policy_rollout_tasks where id=?", UUID.class, taskId));
        result(accepted, "COMPLETE"); due(); rollouts.processPendingTasks();
        assertEquals("CANCELLED", state());
    }

    @Test void terminalAssessmentFailureHasBoundedRetriesAndExplicitRetryPreservesIdentity() {
        rollouts.processPendingTasks();
        UUID accepted = requestId();
        assertNotNull(accepted);
        result(accepted, "FAILED");
        for (int i = 0; i < 9; i++) { due(); rollouts.processPendingTasks(); }
        assertEquals("FAILED", state());
        assertEquals(5, attempts());
        assertEquals(accepted, requestId());
        result(accepted, "COMPLETE");
        due(); rollouts.processPendingTasks();
        assertEquals("FAILED", state());
        rollouts.retry(rolloutId); rollouts.processPendingTasks();
        assertEquals("COMPLETED", state());
        assertEquals(accepted, requestId());
    }

    @Test void expiredFinalAttemptBeforeAdmissionBecomesVisibleFailureAndCanBeExplicitlyRetried() {
        jdbc.update("""
                update platform.ai_grid_policy_rollout_tasks set status='PROCESSING',attempts=5,claim_token=?,
                  lease_expires_at=clock_timestamp()-interval '1 second' where id=?
                """, UUID.randomUUID(), taskId);
        rollouts.processPendingTasks();
        assertEquals("FAILED", state()); assertEquals(5, attempts()); assertNull(requestId());
        assertTrue(jdbc.queryForObject("select failure_detail from platform.ai_grid_policy_rollout_tasks where id=?", String.class, taskId).contains("attempts exhausted"));
        rollouts.retry(rolloutId); rollouts.processPendingTasks();
        assertEquals("WAITING_FOR_ASSESSMENT", state()); assertEquals(1, attempts());
        assertNotNull(requestId());
    }

    private void result(UUID request, String state) {
        scoped.run(tenant, () -> jdbc.update("update ai_grid_outbox set payload_json=jsonb_set(payload_json,'{assessmentStatus}',to_jsonb(cast(? as text))) where id=?", state, request));
    }
    private void due() { jdbc.update("update platform.ai_grid_policy_rollout_tasks set next_retry_at=null where id=?", taskId); }
    private String state() { return jdbc.queryForObject("select status from platform.ai_grid_policy_rollout_tasks where id=?", String.class, taskId); }
    private UUID requestId() { return jdbc.queryForObject("select assessment_request_id from platform.ai_grid_policy_rollout_tasks where id=?", UUID.class, taskId); }
    private int attempts() { return jdbc.queryForObject("select attempts from platform.ai_grid_policy_rollout_tasks where id=?", Integer.class, taskId); }
}
