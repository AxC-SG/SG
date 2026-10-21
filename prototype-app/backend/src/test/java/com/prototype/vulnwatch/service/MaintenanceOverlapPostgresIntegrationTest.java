package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureMetrics;
import com.prototype.vulnwatch.client.AzureDiscoveryClient;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.support.*;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@PostgresIntegrationTest
class MaintenanceOverlapPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("phase3_maintenance_overlap");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired AuditEventService audit;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;
    @Autowired IngestionJobService jobs;
    Tenant tenant;
    UUID profile;

    @BeforeEach void setup() {
        TenantContext.clear();
        String slug = "maintenance-" + UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        tenant = tenants.resolveTenantUuid(tenant.getId());
        profile = UUID.randomUUID();
    }
    @AfterEach void clear() { TenantContext.clear(); }

    @ParameterizedTest
    @ValueSource(ints = {-1, 5})
    void overlappingCredentialSweepsCommitOneTransitionAndAudit(int days) throws Exception {
        insertProfile(days);
        CyclicBarrier scanned = new CyclicBarrier(2);
        var service = credentials(afterScan(() -> await(scanned)), audit);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> first = pool.submit(() -> service.processExpiryWarnings(tenant));
            Future<?> second = pool.submit(() -> service.processExpiryWarnings(tenant));
            first.get(20, TimeUnit.SECONDS);
            second.get(20, TimeUnit.SECONDS);
        } finally { pool.shutdownNow(); }
        credentials(new NamedParameterJdbcTemplate(jdbc), audit).processExpiryWarnings(tenant);
        scoped.run(tenant, () -> {
            assertEquals(days < 0 ? "EXPIRED" : "ACTIVE", state());
            assertEquals(days < 0 ? 0 : 7, jdbc.queryForObject(
                    "select expiry_warning_days from ai_security_azure_credential_profiles where id=?",
                    Integer.class, profile));
            assertEquals(1, events());
        });
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 5})
    void rotationAfterScanCannotExpireOrWarnTheReplacementSecret(int days) {
        insertProfile(days);
        Instant replacementExpiry = Instant.now().plus(90, ChronoUnit.DAYS);
        var service = credentials(afterScan(() -> {
            // A separate committed rotation lands after the sweep's candidate read.
            var independent = new TransactionTemplate(manager);
            independent.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            independent.executeWithoutResult(status -> jdbc.update("""
                    update ai_security_azure_credential_profiles
                       set active_secret_expires_at=?, expiry_warning_days=null where id=?
                    """, Timestamp.from(replacementExpiry), profile));
        }), audit);
        service.processExpiryWarnings(tenant);
        scoped.run(tenant, () -> {
            assertEquals("ACTIVE", state());
            assertNull(jdbc.queryForObject("select expiry_warning_days from ai_security_azure_credential_profiles where id=?",
                    Integer.class, profile));
            assertEquals(0, events());
        });
    }

    @Test void auditFailureRollsBackExpiryAndNextSweepRetries() {
        insertProfile(-1);
        AuditEventService failedAudit = mock(AuditEventService.class);
        doThrow(new IllegalStateException("injected audit failure")).when(failedAudit)
                .record(anyString(), anyString(), anyString(), any());
        assertThrows(IllegalStateException.class, () ->
                credentials(new NamedParameterJdbcTemplate(jdbc), failedAudit).processExpiryWarnings(tenant));
        scoped.run(tenant, () -> { assertEquals("ACTIVE", state()); assertEquals(0, events()); });
        credentials(new NamedParameterJdbcTemplate(jdbc), audit).processExpiryWarnings(tenant);
        scoped.run(tenant, () -> { assertEquals("EXPIRED", state()); assertEquals(1, events()); });
    }

    @Test void shutdownBetweenClaimAndDispatchPreservesAcceptedJobForAnotherWorker() {
        var request = new com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest(
                com.prototype.vulnwatch.domain.AssetType.APPLICATION, "offline", "shutdown-fixture",
                "https://example.test/bom.json", "test", null);
        UUID id = jobs.enqueueEndpointJob(tenant, request, "test").jobId();
        BackgroundTaskExecutionPolicy policy = BackgroundTaskExecutionPolicy.allowAll();
        IngestionJobService observedJobs = spy(jobs);
        doAnswer(call -> {
            var claimed = jobs.claimPendingJobs(tenant, 10, 1);
            policy.stopAcceptingWork();
            return claimed;
        }).when(observedJobs).claimPendingJobs(tenant, 10, 1);
        TenantService catalog = mock(TenantService.class);
        when(catalog.listActiveTenants()).thenReturn(List.of(tenant));
        org.springframework.core.task.TaskExecutor executor = mock(org.springframework.core.task.TaskExecutor.class);
        var worker = new IngestionJobWorkerService(observedJobs, mock(IngestionJobExecutionService.class),
                mock(IngestionJobLockService.class), catalog, scoped, executor, new TransactionTemplate(manager), 10, 1, 5000);
        worker.setBackgroundTaskExecutionPolicy(policy);
        worker.pollJobs();
        verifyNoInteractions(executor);
        var queued = jobs.loadJob(tenant.getId(), id);
        assertEquals("QUEUED", queued.getStatus());
        assertEquals("WORKER_STOPPING", queued.getFailureCode());
        var replacement = jobs.claimPendingJobs(tenant, 1, 1);
        assertEquals(1, replacement.size());
        assertEquals(id, replacement.get(0).jobId());
    }

    private NamedParameterJdbcTemplate afterScan(Runnable boundary) {
        return new NamedParameterJdbcTemplate(jdbc) {
            @Override public <T> List<T> query(String sql, RowMapper<T> mapper) {
                List<T> rows = super.query(sql, mapper);
                if (sql.contains("select id, active_secret_expires_at, expiry_warning_days")) boundary.run();
                return rows;
            }
        };
    }
    private AiSecurityAzureCredentialService credentials(NamedParameterJdbcTemplate queries, AuditEventService recorder) {
        return new AiSecurityAzureCredentialService(queries, scoped, new TransactionTemplate(manager),
                mock(CredentialEncryptionService.class), mock(AzureDiscoveryClient.class), recorder,
                mock(AiSecurityAzureMetrics.class));
    }
    private void insertProfile(int days) {
        scoped.run(tenant, () -> jdbc.update("""
                insert into ai_security_azure_credential_profiles
                    (id,tenant_id,name,auth_type,azure_tenant_id,active_secret_expires_at,created_by,updated_by)
                values (?,?,'offline profile','CLIENT_SECRET','offline-directory',?,'test','test')
                """, profile, tenant.getId(), Timestamp.from(Instant.now().plus(days, ChronoUnit.DAYS))));
    }
    private String state() {
        return jdbc.queryForObject("select status from ai_security_azure_credential_profiles where id=?", String.class, profile);
    }
    private int events() {
        return jdbc.queryForObject("select count(*) from audit_events where target_id=? and action in "
                + "('ai_security.azure_credential.expired','ai_security.azure_credential.expiry_warning')",
                Integer.class, profile.toString());
    }
    private static void await(CyclicBarrier barrier) {
        try { barrier.await(10, TimeUnit.SECONDS); }
        catch (Exception failure) { throw new AssertionError(failure); }
    }
}
