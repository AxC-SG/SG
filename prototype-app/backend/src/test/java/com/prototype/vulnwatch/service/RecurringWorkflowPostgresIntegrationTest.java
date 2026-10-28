package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.*;
import com.prototype.vulnwatch.support.*;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@PostgresIntegrationTest
class RecurringWorkflowPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB = LocalPostgresTestDatabase.provision("phase3_recurring_workflows");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) { PostgresITSupport.registerDatabaseProperties(registry, DB); }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired FindingWorkflowService workflow;
    @Autowired AssetLifecycleService assets;
    @Autowired SuppressionRuleService suppression;
    @Autowired FindingListProjectionService projection;
    @Autowired FindingRepository findings;
    @Autowired AssetRepository assetRepository;
    @Autowired InventoryComponentRepository components;
    @Autowired SbomUploadRepository uploads;
    @Autowired VulnerabilityRepository vulnerabilities;
    @Autowired SuppressionRuleRepository rules;
    @Autowired RiskPolicyService riskPolicies;
    @Autowired RiskPolicyRepository policyRepository;
    @Autowired FindingIncidentSyncService incidents;
    @Autowired BomContributionBackfillService backfill;
    @Autowired BomIngestionRecordRepository bomRecords;
    @Autowired BomProjectionReconciliationService bomReconciliation;
    @Autowired VulnerabilityIntelMaintenanceService intelMaintenance;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;
    @MockitoBean FindingsScoreService scores;
    @MockitoBean ServiceNowIncidentService incidentProvider;
    @MockitoBean ServiceNowCmdbConfigService incidentConfig;
    Tenant tenant;
    UUID finding;

    @BeforeEach void setup() {
        TenantContext.clear();
        String slug = "workflow-" + UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        tenant = tenants.resolveTenantUuid(tenant.getId());
        new FindingWorkspaceSeedSupport(assetRepository, uploads, components, vulnerabilities, findings, scoped)
                .seedCriticalWorkspace(tenant, 1, 1);
        finding = scoped.run(tenant, () -> jdbc.queryForObject("select id from findings", UUID.class));
        scoped.run(tenant, () -> new TransactionTemplate(manager).executeWithoutResult(status -> {
            RiskPolicy policy = riskPolicies.getOrCreate(tenant);
            policy.setAutoCloseEnabled(true);
            policy.setAutoCloseNotObservedEnabled(true);
            policy.setAutoCloseAssetRetiredEnabled(true);
            policy.setAutoCloseRequiredConsecutiveMisses(2);
            policyRepository.save(policy);
        }));
    }
    @AfterEach void clear() { TenantContext.clear(); }

    @Test void overlappingSuppressionExpiryReopensOnceAndPublishesCurrentProjection() throws Exception {
        scoped.run(tenant, () -> jdbc.update("update findings set status='SUPPRESSED',suppressed_until=now()-interval '1 day'"));
        overlap(() -> { workflow.reopenExpiredSuppressions(); return 0; });
        scoped.run(tenant, () -> {
            assertEquals("OPEN", state());
            assertEquals(1, events("SUPPRESSION_EXPIRED"));
            assertEquals("OPEN", projectedState());
        });
    }

    @Test void overlappingPolicyClosureCommitsOneEventAndCurrentProjection() throws Exception {
        scoped.run(tenant, () -> jdbc.update("update findings set auto_close_eligible_at=now()-interval '1 day',consecutive_misses=3"));
        overlap(() -> { workflow.autoCloseFindingsByPolicy(); return 0; });
        scoped.run(tenant, () -> {
            assertEquals("AUTO_CLOSED", state());
            assertEquals(1, events("AUTO_CLOSED"));
            assertEquals("AUTO_CLOSED", projectedState());
        });
    }

    @Test void staleAssetSweepsCloseOnceAndLeaveFreshAssetsActive() throws Exception {
        scoped.run(tenant, () -> jdbc.update("update assets set last_inventory_at=now()-interval '400 days'"));
        overlap(() -> { assets.markStaleAssetsInactive(); return 0; });
        scoped.run(tenant, () -> {
            assertEquals("INACTIVE", jdbc.queryForObject("select state from assets", String.class));
            assertEquals(1, events("AUTO_CLOSED"));
            jdbc.update("update assets set state='ACTIVE',last_inventory_at=now()");
        });
        assets.markStaleAssetsInactive();
        scoped.run(tenant, () -> assertEquals("ACTIVE", jdbc.queryForObject("select state from assets", String.class)));
    }

    @Test void overlappingRuleExecutionsReportOnlyOneEffectiveSuppression() throws Exception {
        UUID rule = scoped.run(tenant, () -> {
            SuppressionRule value = new SuppressionRule();
            value.setTenant(tenant); value.setName("Offline overlap rule");
            value.setState(SuppressionRule.State.APPROVED); value.setReason("test fixture");
            return rules.save(value).getId();
        });
        when(scores.matchesSuppressionConditions(anyString(), anyString(), any())).thenReturn(true);
        List<Integer> counts = overlap(() -> suppression.execute(tenant, rule));
        assertEquals(1, counts.stream().mapToInt(Integer::intValue).sum());
        scoped.run(tenant, () -> {
            assertEquals("SUPPRESSED", state());
            assertEquals(rule, jdbc.queryForObject("select suppressed_by_rule_id from findings", UUID.class));
        });
    }

    @Test void workflowAndProjectionRemainInvisibleBeforeCommitAndRollbackTogether() {
        projection.refreshTenant(tenant);
        assertThrows(IllegalStateException.class, () -> scoped.run(tenant, () -> new TransactionTemplate(manager).execute(status -> {
            workflow.updateWorkflow(finding, new FindingWorkflowUpdateRequest("RESOLVED", null, null, null, null, null, "offline-test"));
            assertEquals("RESOLVED", projectedState());
            assertEquals("OPEN", independentProjectedState());
            throw new IllegalStateException("injected rollback");
        })));
        scoped.run(tenant, () -> { assertEquals("OPEN", state()); assertEquals("OPEN", projectedState()); });
    }

    @Test void concurrentProjectionRepairsPreserveRowsAndStatus() throws Exception {
        overlap(() -> projection.refreshTenant(tenant));
        scoped.run(tenant, () -> {
            assertEquals(1, jdbc.queryForObject("select count(*) from finding_list_projection", Integer.class));
            assertEquals("OPEN", projectedState());
            assertEquals(1L, jdbc.queryForObject("select finding_count from finding_workspace_projection_status", Long.class));
        });
    }

    @Test void overlappingVexStalenessCallbacksPublishOnePendingIntentAndRepeatAfterCompletion() throws Exception {
        scoped.run(tenant, () -> jdbc.update("""
                insert into component_vulnerability_states(id,tenant_id,component_id,vulnerability_id,
                  applicability_state,impact_state,eligible_for_finding,vex_freshness,
                  last_evaluated_at,state_changed_at,created_at,updated_at)
                select gen_random_uuid(),tenant_id,component_id,vulnerability_id,'APPLICABLE','AFFECTED',true,'FRESH',
                  now()-interval '40 days',now(),now(),now() from findings where id=?
                """, finding));
        overlap(() -> { intelMaintenance.scheduledVexStalenessRecompute(); return 0; });
        scoped.run(tenant, () -> {
            assertEquals(1, jdbc.queryForObject("select count(*) from finding_delta_queue where source_tag='vex-staleness-sweep' and status='PENDING'", Integer.class));
            jdbc.update("update finding_delta_queue set status='DONE' where source_tag='vex-staleness-sweep'");
        });
        intelMaintenance.scheduledVexStalenessRecompute();
        scoped.run(tenant, () -> assertEquals(1, jdbc.queryForObject("select count(*) from finding_delta_queue where source_tag='vex-staleness-sweep' and status='PENDING'", Integer.class)));
    }

    @Test void incidentSweepsApplyOneEffectiveStatusChange() throws Exception {
        scoped.run(tenant, () -> jdbc.update("update findings set incident_id='INC-OFFLINE',incident_status='OPEN'"));
        var config = new ServiceNowCmdbConfigService.ServiceNowRuntimeConfig("https://example.test", ServiceNowAuthType.BASIC,
                "offline", "offline", null, null, null, null, null, null, null, 10, true, false, 60);
        when(incidentConfig.resolveRuntimeConfig(any())).thenReturn(Optional.of(config));
        // The ticketing provider reads the raw state code; 7 is ServiceNow's "Closed".
        when(incidentProvider.fetchIncidentStateCode(config, "INC-OFFLINE")).thenReturn(Optional.of("7"));
        List<Integer> changed = overlap(() -> incidents.syncAll().updated());
        assertEquals(1, changed.stream().mapToInt(Integer::intValue).sum());
        scoped.run(tenant, () -> assertEquals("Closed", jdbc.queryForObject("select incident_status from findings", String.class)));
    }

    @Test void overlappingLegacyBackfillCreatesOneSourceAndReconciliationOnlyObserves() throws Exception {
        UUID asset = scoped.run(tenant, () -> jdbc.queryForObject("select id from assets", UUID.class));
        scoped.run(tenant, () -> {
            BomIngestionRecord record = new BomIngestionRecord();
            record.setTenant(tenant); record.setAssetId(asset); record.setBomType(BomType.SBOM);
            record.setSbomUploadId(jdbc.queryForObject("select id from sbom_uploads", UUID.class));
            bomRecords.save(record);
        });
        List<Integer> counts = overlap(() -> scoped.run(tenant, () -> new TransactionTemplate(manager).execute(
                status -> backfill.backfillAsset(tenant.getId(), asset).sourcesCreated())));
        assertEquals(1, counts.stream().mapToInt(Integer::intValue).sum());
        overlap(() -> { bomReconciliation.reconcileProjectionDrift(); return 0; });
        scoped.run(tenant, () -> {
            assertEquals(1, jdbc.queryForObject("select count(*) from bom_sources", Integer.class));
            assertEquals(1, jdbc.queryForObject("select count(*) from bom_ingestion_records where source_id is not null", Integer.class));
            assertEquals("OPEN", state());
        });
    }

    private String state() { return jdbc.queryForObject("select status from findings where id=?", String.class, finding); }
    private String projectedState() { return jdbc.queryForObject("select status from finding_list_projection where finding_id=?", String.class, finding); }
    private int events(String type) { return jdbc.queryForObject("select count(*) from finding_events where finding_id=? and event_type=?", Integer.class, finding, type); }
    private String independentProjectedState() {
        try (var c = DriverManager.getConnection(DB.url(), DB.username(), DB.password()); var s = c.createStatement();
             var rows = s.executeQuery("select status from \"" + tenant.getSchemaName() + "\".finding_list_projection")) {
            assertTrue(rows.next()); return rows.getString(1);
        } catch (Exception error) { throw new AssertionError(error); }
    }
    private static List<Integer> overlap(Callable<Integer> work) throws Exception {
        CyclicBarrier start = new CyclicBarrier(2);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Callable<Integer> task = () -> { start.await(10, TimeUnit.SECONDS); return work.call(); };
            Future<Integer> first = pool.submit(task), second = pool.submit(task);
            return List.of(first.get(40, TimeUnit.SECONDS), second.get(40, TimeUnit.SECONDS));
        } finally { pool.shutdownNow(); }
    }
}
