package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyDeprecationService;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.*;
import com.prototype.vulnwatch.support.*;
import java.util.UUID;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.ReflectionTestUtils;

@PostgresIntegrationTest
class AiGridPolicyDeprecationRecoveryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("phase3_deprecation_recovery");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }
    @Autowired AiGridPolicyDeprecationService deprecations;
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired FindingRepository findings;
    @Autowired JdbcTemplate jdbc;
    @MockitoSpyBean FindingWorkflowService workflow;
    Tenant tenant;
    UUID taskId;
    UUID findingId;

    @BeforeEach void setup() {
        TenantContext.clear();
        String slug = "retirement-" + UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        tenant = tenants.resolveTenantUuid(tenant.getId());
        UUID deprecationId = UUID.randomUUID();
        String policy = "recovery-" + deprecationId;
        taskId = UUID.randomUUID();
        jdbc.update("""
                insert into platform.ai_grid_policy_deprecations
                    (id,policy_id,policy_version,reason,deprecated_by,idempotency_key)
                values (?,?,'1.0.0','recovery test','test',?)
                """, deprecationId, policy, deprecationId.toString());
        jdbc.update("insert into platform.ai_grid_policy_deprecation_tasks(id,deprecation_id,tenant_id) values (?,?,?)",
                taskId, deprecationId, tenant.getId());
        findingId = scoped.run(tenant, () -> {
            Finding finding = new Finding();
            finding.setTenant(tenant);
            finding.setFindingKind("AI_POSTURE");
            finding.setPolicyId(policy);
            finding.setMatchedBy("retirement-recovery-test");
            return findings.saveAndFlush(finding).getId();
        });
    }
    @AfterEach void clear() { TenantContext.clear(); }

    @Test void expiredTaskRecoversAndClosesFindingOnce() {
        jdbc.update("""
                update platform.ai_grid_policy_deprecation_tasks
                   set state='PROCESSING',claim_token=?,lease_expires_at=clock_timestamp()-interval '1 second'
                 where id=?
                """, UUID.randomUUID(), taskId);
        deprecations.processPendingTasks();
        deprecations.processPendingTasks();
        assertEquals("COMPLETED", state());
        assertEquals(1, jdbc.queryForObject("select attempts from platform.ai_grid_policy_deprecation_tasks where id=?", Integer.class, taskId));
        scoped.run(tenant, () -> {
            assertEquals(FindingStatus.AUTO_CLOSED, findings.findById(findingId).orElseThrow().getStatus());
            assertEquals(1, jdbc.queryForObject("select count(*) from finding_events where finding_id=? and event_type='AUTO_CLOSED'", Integer.class, findingId));
        });
    }

    @Test void healthyOwnerIsNotReclaimedAndOldTokenCannotCompleteNewOwner() {
        Object original = ReflectionTestUtils.invokeMethod(deprecations, "claim");
        assertNotNull(original);
        deprecations.processPendingTasks();
        assertEquals(1, jdbc.queryForObject("select attempts from platform.ai_grid_policy_deprecation_tasks where id=?", Integer.class, taskId));
        UUID replacement = UUID.randomUUID();
        jdbc.update("update platform.ai_grid_policy_deprecation_tasks set claim_token=? where id=?", replacement, taskId);
        ReflectionTestUtils.invokeMethod(deprecations, "process", original);
        assertEquals("PROCESSING", state());
        assertEquals(replacement, jdbc.queryForObject("select claim_token from platform.ai_grid_policy_deprecation_tasks where id=?", UUID.class, taskId));
        scoped.run(tenant, () -> assertEquals(FindingStatus.OPEN, findings.findById(findingId).orElseThrow().getStatus()));
    }

    @Test void expiryDuringClosureRollsBackFindingAndAuditEvent() {
        doAnswer(call -> {
            call.callRealMethod();
            // Simulate expiry at the domain-to-completion boundary, without sleeping.
            jdbc.update("update platform.ai_grid_policy_deprecation_tasks set lease_expires_at=clock_timestamp()-interval '1 second' where id=?", taskId);
            return null;
        }).when(workflow).autoCloseFinding(any(), any(), anyString(), anyMap(), any());
        deprecations.processPendingTasks();
        assertEquals("FAILED", state());
        scoped.run(tenant, () -> {
            assertEquals(FindingStatus.OPEN, findings.findById(findingId).orElseThrow().getStatus());
            assertEquals(0, jdbc.queryForObject("select count(*) from finding_events where finding_id=?", Integer.class, findingId));
        });
    }

    private String state() {
        return jdbc.queryForObject("select state from platform.ai_grid_policy_deprecation_tasks where id=?", String.class, taskId);
    }
}
