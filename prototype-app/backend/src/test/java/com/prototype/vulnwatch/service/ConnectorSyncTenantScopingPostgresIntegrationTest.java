package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.controller.AwsDiscoveryController;
import com.prototype.vulnwatch.controller.AzureDiscoveryController;
import com.prototype.vulnwatch.controller.SccmCmdbController;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.AwsDiscoveryTarget;
import com.prototype.vulnwatch.domain.AzureAuthType;
import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import com.prototype.vulnwatch.domain.AzureDiscoveryTarget;
import com.prototype.vulnwatch.domain.GithubIngestionFrequency;
import com.prototype.vulnwatch.domain.GithubSbomSource;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.AzureDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AzureDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.core.task.TaskExecutor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.support.TransactionTemplate;

/** Real PostgreSQL admission locks; queued work is captured and never contacts providers. */
@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
class ConnectorSyncTenantScopingPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("connector_sync_tenant_scoping");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private TransactionTemplate transactions;
    @Autowired private SyncRunRepository runs;
    @Autowired private AwsDiscoveryConfigRepository awsConfigs;
    @Autowired private AzureDiscoveryConfigRepository azureConfigs;
    @Autowired private ServiceNowCmdbConfigRepository serviceNowConfigs;
    @Autowired private SccmCmdbConfigRepository sccmConfigs;
    @Autowired private AwsDiscoveryTargetRepository awsTargets;
    @Autowired private AzureDiscoveryTargetRepository azureTargets;
    @Autowired private AwsDiscoverySyncService aws;
    @Autowired private AzureDiscoverySyncService azure;
    @Autowired private ServiceNowCmdbSyncService serviceNow;
    @Autowired private SccmCmdbSyncService sccm;
    @Autowired private com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository gcpConfigs;
    @Autowired private com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository gcpTargets;
    @Autowired private GcpDiscoverySyncService gcp;
    @Autowired private com.prototype.vulnwatch.repo.IngestionJobRepository jobs;
    @Autowired private IngestionJobWorkerService worker;
    @Autowired private GithubSbomSourceService github;
    @Autowired private com.prototype.vulnwatch.repo.GithubSbomSourceRepository githubSources;
    @Autowired private JdbcTemplate jdbc;

    @MockitoBean private WorkspaceService workspace;
    @MockitoBean(name = "integrationQueueExecutor") private TaskExecutor queue;

    @BeforeEach
    void captureOnly() {
        reset(queue);
        when(workspace.getWorkspace()).thenAnswer(invocation -> tenants.resolveTenantUuid(TenantContext.getCurrentTenantId()));
    }

    @org.junit.jupiter.api.Test
    void disabledGenericAzureNeverAdmitsOrSchedulesExistingConfigurations() {
        Tenant first=configuredTenant(Connector.AZURE_DISCOVERY,true);
        Tenant second=configuredTenant(Connector.AZURE_DISCOVERY,true);
        assertEquals(410,assertThrows(org.springframework.web.server.ResponseStatusException.class,() -> trigger(first,Connector.AZURE_DISCOVERY)).getStatusCode().value());
        scheduled(Connector.AZURE_DISCOVERY);
        assertTrue(tenantRuns(first,Connector.AZURE_DISCOVERY).isEmpty());
        assertTrue(tenantRuns(second,Connector.AZURE_DISCOVERY).isEmpty());
        assertEquals(0L,tenantExecution.run(first,() -> jobs.count()));
        assertEquals(0L,tenantExecution.run(second,() -> jobs.count()));
        org.mockito.Mockito.verifyNoInteractions(queue);
        setAutoSync(first,Connector.AZURE_DISCOVERY,false);setAutoSync(second,Connector.AZURE_DISCOVERY,false);
    }

    @ParameterizedTest
    @EnumSource(value = Connector.class, names = {"AZURE_DISCOVERY"}, mode = EnumSource.Mode.EXCLUDE)
    void tenantsHaveIndependentAdmissionAndStatus(Connector connector) throws Exception {
        Tenant first = configuredTenant(connector, false);
        Tenant second = configuredTenant(connector, false);
        SyncTriggerResponse firstRun = trigger(first, connector);

        assertTrue(active(first, connector));
        assertFalse(active(second, connector), "another tenant's active run must not appear in status");
        assertEndpointStatus(second, connector, false);

        SyncTriggerResponse secondRun = trigger(second, connector);
        assertNotEquals(firstRun.runId(), secondRun.runId());
        assertEquals(firstRun.runId(), trigger(first, connector).runId());
        assertEquals(secondRun.runId(), trigger(second, connector).runId());
        assertEquals(first.getId(), runs.findById(firstRun.runId()).orElseThrow().getTenant().getId());
        assertEquals(second.getId(), runs.findById(secondRun.runId()).orElseThrow().getTenant().getId());
        assertEndpointStatus(second, connector, true);
        org.mockito.Mockito.verifyNoInteractions(queue);
        assertEquals(1L,tenantExecution.run(first,() -> jobs.count()));
        assertEquals(1L,tenantExecution.run(second,() -> jobs.count()));
    }

    @ParameterizedTest
    @EnumSource(value = Connector.class, names = {"AZURE_DISCOVERY"}, mode = EnumSource.Mode.EXCLUDE)
    void sameConfigurationWaitsForUncommittedAdmissionAndReusesOneRun(Connector connector) throws Exception {
        Tenant tenant = configuredTenant(connector, false);
        Tenant independentTenant = configuredTenant(connector, false);
        var executor = Executors.newFixedThreadPool(2);
        CountDownLatch admitted = new CountDownLatch(1);
        CountDownLatch commit = new CountDownLatch(1);
        CountDownLatch competing = new CountDownLatch(1);
        try {
            var first = executor.submit(() -> tenantExecution.run(tenant, () -> transactions.execute(status -> {
                SyncTriggerResponse response = trigger(tenant, connector);
                admitted.countDown();
                await(commit);
                return response;
            })));
            assertTrue(admitted.await(10, TimeUnit.SECONDS));
            var second = executor.submit(() -> {
                competing.countDown();
                return trigger(tenant, connector);
            });
            assertTrue(competing.await(10, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> second.get(300, TimeUnit.MILLISECONDS),
                    "a competing admission must wait until the first transaction commits");
            SyncTriggerResponse independent = trigger(independentTenant, connector);
            commit.countDown();
            UUID firstRunId = first.get(10, TimeUnit.SECONDS).runId();
            assertEquals(firstRunId, second.get(10, TimeUnit.SECONDS).runId());
            assertNotEquals(firstRunId, independent.runId(), "another tenant must progress while this configuration is locked");
            assertEquals(1, tenantRuns(tenant, connector).size());
            org.mockito.Mockito.verifyNoInteractions(queue);
            assertEquals(1L,tenantExecution.run(tenant,() -> jobs.count()));
            assertEquals(1L,tenantExecution.run(independentTenant,() -> jobs.count()));
        } finally {
            commit.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    @ParameterizedTest
    @EnumSource(value = Connector.class, names = {"AZURE_DISCOVERY"}, mode = EnumSource.Mode.EXCLUDE)
    void scheduledDueTimeAndActiveRunsAreIndependentPerTenant(Connector connector) {
        Tenant recent = configuredTenant(connector, true);
        Tenant due = configuredTenant(connector, true);
        try {
            SyncRun latest = new SyncRun();
            latest.setTenant(recent);
            latest.setSyncType(connector.name());
            latest.setRunScope("TENANT_INVENTORY");
            latest.setStatus("completed");
            latest.setCompletedAt(Instant.now());
            runs.saveAndFlush(latest);

            scheduled(connector);
            assertEquals(List.of("completed"), tenantRuns(recent, connector).stream().map(SyncRun::getStatus).toList());
            assertEquals(List.of("queued"), tenantRuns(due, connector).stream().map(SyncRun::getStatus).toList(),
                    "recent execution in another tenant must not postpone a due configuration");
            scheduled(connector);
            assertEquals(1, tenantRuns(due, connector).size());
            org.mockito.Mockito.verifyNoInteractions(queue);
            assertEquals(1L,tenantExecution.run(due,() -> jobs.count()));
            assertEquals(0L,tenantExecution.run(recent,() -> jobs.count()));
        } finally {
            setAutoSync(recent, connector, false);
            setAutoSync(due, connector, false);
        }
    }

    @ParameterizedTest
    @EnumSource(ConnectorScheduleProgress.Kind.class)
    void overlappingSchedulesRememberTheAcceptedWindowAfterCompletion(ConnectorScheduleProgress.Kind kind)
            throws Exception {
        boolean awsSchedule = kind == ConnectorScheduleProgress.Kind.AWS_DISCOVERY;
        Tenant tenant = configuredTenant(Connector.AWS_DISCOVERY, awsSchedule);
        UUID sourceId = tenantExecution.run(tenant, () -> {
            if (awsSchedule) {
                return awsConfigs.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws").orElseThrow().getId();
            }
            GithubSbomSource source = new GithubSbomSource();
            source.setTenant(tenant);
            source.setName("Scheduled source");
            source.setOwner("offline");
            source.setRepo("repository");
            source.setAssetName("Scheduled source");
            source.setAssetIdentifier("scheduled-source");
            source.setFrequency(GithubIngestionFrequency.INTERVAL);
            source.setIntervalMinutes(5);
            return githubSources.saveAndFlush(source).getId();
        });
        Instant window = Instant.parse("2026-11-07T10:00:00Z");
        Consumer<Instant> sweep = awsSchedule ? aws::runScheduledSyncs : github::runScheduledSources;
        var executor = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            var first = executor.submit(() -> { await(start); sweep.accept(window); });
            var second = executor.submit(() -> { await(start); sweep.accept(window.plusSeconds(12)); });
            start.countDown();
            first.get(30, TimeUnit.SECONDS);
            second.get(30, TimeUnit.SECONDS);
            assertEquals(1, runs.findByTenant_IdOrderByStartedAtDesc(tenant.getId()).size());
            assertEquals(1L, tenantExecution.run(tenant, () -> jobs.count()));
            assertEquals(window, jdbc.queryForObject("""
                    select last_occurrence_at from platform.connector_schedule_progress
                    where tenant_id = ? and schedule_kind = ? and source_id = ?
                    """, java.sql.Timestamp.class, tenant.getId(), kind.name(), sourceId).toInstant());

            // Make the source due again so the repeat tests the durable cursor, not the interval or active-run check.
            jdbc.update("update platform.sync_runs set status = 'completed', completed_at = ? where tenant_id = ?",
                    java.sql.Timestamp.from(window.minusSeconds(172800)), tenant.getId());
            tenantExecution.run(tenant, () -> {
                jdbc.update("update ingestion_jobs set status = 'SUCCEEDED', completed_at = now()");
                if (!awsSchedule) {
                    jdbc.update("update github_sbom_sources set last_run_status = 'SUCCESS', last_run_at = ? where id = ?",
                            java.sql.Timestamp.from(window.minusSeconds(86400)), sourceId);
                }
            });
            sweep.accept(window.plusSeconds(30));
            sweep.accept(window.minusSeconds(300));
            assertEquals(1L, tenantExecution.run(tenant, () -> jobs.count()));

            sweep.accept(window.plusSeconds(300));
            assertEquals(2L, tenantExecution.run(tenant, () -> jobs.count()));
            org.mockito.Mockito.verifyNoInteractions(queue);
        } finally {
            executor.shutdownNow();
            if (awsSchedule) {
                setAutoSync(tenant, Connector.AWS_DISCOVERY, false);
            } else {
                tenantExecution.run(tenant, () -> { jdbc.update("update github_sbom_sources set enabled = false where id = ?", sourceId); });
            }
        }
    }

    @org.junit.jupiter.api.Test
    void unavailableWorkspaceDoesNotStopAwsSchedulingForItsPeer() {
        Tenant unavailable = configuredTenant(Connector.AWS_DISCOVERY, true);
        Tenant due = configuredTenant(Connector.AWS_DISCOVERY, true);
        String schema = unavailable.getSchemaName();
        jdbc.execute("alter schema " + schema + " rename to " + schema + "_offline");
        try {
            aws.runScheduledSyncs();
            assertTrue(tenantRuns(unavailable, Connector.AWS_DISCOVERY).isEmpty());
            assertEquals(1L, tenantExecution.run(due, () -> jobs.count()));
        } finally {
            jdbc.execute("alter schema " + schema + "_offline rename to " + schema);
            setAutoSync(unavailable, Connector.AWS_DISCOVERY, false);
            setAutoSync(due, Connector.AWS_DISCOVERY, false);
        }
    }

    @ParameterizedTest
    @EnumSource(value = Connector.class, names = {"AWS_DISCOVERY"})
    void targetAdmissionUsesOwningTenantAndConfiguration(Connector connector) {
        Tenant first = configuredTenant(connector, false);
        Tenant second = configuredTenant(connector, false);
        UUID targetId = tenantExecution.run(second, () -> {
            if (connector == Connector.AWS_DISCOVERY) {
                AwsDiscoveryTarget target = new AwsDiscoveryTarget();
                target.setTenant(second);
                target.setConfig(awsConfigs.findByTenant_IdAndSourceSystemIgnoreCase(second.getId(), "aws").orElseThrow());
                target.setAccountId("123456789012");
                return awsTargets.saveAndFlush(target).getId();
            }
            AzureDiscoveryTarget target = new AzureDiscoveryTarget();
            target.setTenant(second);
            target.setConfig(azureConfigs.findByTenant_IdAndSourceSystemIgnoreCase(second.getId(), "azure").orElseThrow());
            target.setSubscriptionId(UUID.randomUUID().toString());
            return azureTargets.saveAndFlush(target).getId();
        });
        SyncTriggerResponse firstRun = trigger(first, connector);
        SyncTriggerResponse targetRun = tenantExecution.run(second, () -> connector == Connector.AWS_DISCOVERY
                ? aws.triggerTarget(second, targetId) : azure.triggerTarget(second, targetId));

        assertNotEquals(firstRun.runId(), targetRun.runId());
        assertEquals(targetRun.runId(), trigger(second, connector).runId(),
                "target and whole-configuration requests share one effective run");
        assertEquals(second.getId(), runs.findById(targetRun.runId()).orElseThrow().getTenant().getId());
        org.mockito.Mockito.verifyNoInteractions(queue);
        assertEquals(1L,tenantExecution.run(first,() -> jobs.count()));
        assertEquals(1L,tenantExecution.run(second,() -> jobs.count()));
    }

    @ParameterizedTest
    @EnumSource(value=Connector.class,names={"AWS_DISCOVERY","SERVICENOW_CMDB","SCCM_CMDB","GCP_DISCOVERY"})
    void exhaustedAttemptTerminatesLinkedRunAndAllowsNewAdmission(Connector connector) {
        Tenant tenant=configuredTenant(connector,false);
        UUID prior=trigger(tenant,connector).runId();
        expireFinalAttempt(tenant);
        worker.recoverInterruptedJobs();
        assertEquals("failed",runs.findById(prior).orElseThrow().getStatus());
        assertNotEquals(prior,trigger(tenant,connector).runId());
        assertEquals(2L,tenantExecution.run(tenant,() -> jobs.count()));
    }

    @org.junit.jupiter.api.Test
    void exhaustedGithubAttemptReleasesSavedSourceForNewAdmission() {
        Tenant tenant=configuredTenant(Connector.AWS_DISCOVERY,false);
        UUID source=tenantExecution.run(tenant,() -> {
            var value=new com.prototype.vulnwatch.domain.GithubSbomSource();value.setTenant(tenant);
            value.setName("Recovery source");value.setOwner("offline");value.setRepo("repository");
            value.setAssetName("Recovery source");value.setAssetIdentifier("recovery-source");
            return githubSources.saveAndFlush(value).getId();
        });
        UUID prior=tenantExecution.run(tenant,() -> github.trigger(source).runId());
        expireFinalAttempt(tenant);worker.recoverInterruptedJobs();
        assertEquals("failed",runs.findById(prior).orElseThrow().getStatus());
        assertNotEquals(prior,tenantExecution.run(tenant,() -> github.trigger(source).runId()));
    }

    private void expireFinalAttempt(Tenant tenant) {
        tenantExecution.run(tenant,() -> transactions.executeWithoutResult(status -> {
            var job=jobs.findAll().get(0);job.setStatus("RUNNING");job.setClaimToken(UUID.randomUUID());
            job.setAttemptCount(3);job.setLeaseExpiresAt(Instant.now().minusSeconds(1));jobs.saveAndFlush(job);
        }));
    }

    private Tenant configuredTenant(Connector connector, boolean autoSync) {
        String slug = "p03-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        tenant = tenants.resolveTenantUuid(tenant.getId());
        Tenant configured = tenant;
        tenantExecution.run(configured, () -> {
            switch (connector) {
                case AWS_DISCOVERY -> {
                    AwsDiscoveryConfig config = new AwsDiscoveryConfig();
                    config.setAuthType(com.prototype.vulnwatch.domain.AwsAuthType.CROSS_ACCOUNT_ROLE);
                    config.setAwsAccountId("123456789012");
                    config.setCrossAccountRoleArn("arn:aws:iam::123456789012:role/Discovery");
                    config.setExternalId(com.prototype.vulnwatch.client.AwsCustomerBinding.externalId(configured.getId(), null, 0, null));
                    config.setCredentialBindingVersion(1);
                    config.setTenant(configured);
                    config.setAutoSyncEnabled(autoSync);
                    awsConfigs.saveAndFlush(config);
                }
                case AZURE_DISCOVERY -> {
                    AzureDiscoveryConfig config = new AzureDiscoveryConfig();
                    config.setTenant(configured);
                    config.setAuthType(AzureAuthType.MANAGED_IDENTITY);
                    config.setSubscriptionIdsJson("[\"test-subscription\"]");
                    config.setAutoSyncEnabled(autoSync);
                    azureConfigs.saveAndFlush(config);
                }
                case SERVICENOW_CMDB -> {
                    ServiceNowCmdbConfig config = new ServiceNowCmdbConfig();
                    config.setTenant(configured);
                    config.setBaseUrl("https://example.invalid");
                    config.setCredentialSecret("controlled-test-double");
                    config.setAutoSyncEnabled(autoSync);
                    serviceNowConfigs.saveAndFlush(config);
                }
                case SCCM_CMDB -> {
                    SccmCmdbConfig config = new SccmCmdbConfig();
                    config.setTenant(configured);
                    config.setJdbcUrl("jdbc:sqlserver://example.invalid");
                    config.setUsername("controlled-test-login");
                    config.setCredentialSecret("controlled-test-double");
                    config.setAutoSyncEnabled(autoSync);
                    sccmConfigs.saveAndFlush(config);
                }
                case GCP_DISCOVERY -> {
                    var config = new com.prototype.vulnwatch.domain.GcpDiscoveryConfig();
                    config.setTenant(configured);
                    config.setServiceAccountEmail("reader@controlled-project.iam.gserviceaccount.com");
                    config.setCredentialSecret("controlled-test-double");
                    config.setAutoSyncEnabled(autoSync);
                    config = gcpConfigs.saveAndFlush(config);
                    var target = new com.prototype.vulnwatch.domain.GcpDiscoveryTarget();
                    target.setTenant(configured);
                    target.setConfig(config);
                    target.setProjectId("controlled-project");
                    target.setResourceTypesJson("[\"COMPUTE_INSTANCE\"]");
                    gcpTargets.saveAndFlush(target);
                }
            }
        });
        return configured;
    }

    private SyncTriggerResponse trigger(Tenant tenant, Connector connector) {
        return tenantExecution.run(tenant, () -> switch (connector) {
            case AWS_DISCOVERY -> aws.trigger();
            case AZURE_DISCOVERY -> azure.trigger();
            case SERVICENOW_CMDB -> serviceNow.trigger();
            case SCCM_CMDB -> sccm.trigger();
            case GCP_DISCOVERY -> gcp.trigger();
        });
    }

    private boolean active(Tenant tenant, Connector connector) {
        return tenantExecution.run(tenant, () -> switch (connector) {
            case AWS_DISCOVERY -> aws.hasActiveRun();
            case AZURE_DISCOVERY -> azure.hasActiveRun();
            case SERVICENOW_CMDB -> serviceNow.hasActiveRun();
            case SCCM_CMDB -> sccm.hasActiveRun();
            case GCP_DISCOVERY -> gcp.hasActiveRun();
        });
    }

    private void scheduled(Connector connector) {
        switch (connector) {
            case AWS_DISCOVERY -> aws.runScheduledSyncs();
            case AZURE_DISCOVERY -> azure.runScheduledSyncs();
            case SERVICENOW_CMDB -> serviceNow.runScheduledSyncs();
            case SCCM_CMDB -> sccm.runScheduledSyncs();
            case GCP_DISCOVERY -> gcp.runScheduledSyncs();
        }
    }

    private List<SyncRun> tenantRuns(Tenant tenant, Connector connector) {
        return runs.findByTenant_IdOrderByStartedAtDesc(tenant.getId()).stream()
                .filter(run -> connector.name().equals(run.getSyncType())).toList();
    }

    private void setAutoSync(Tenant tenant, Connector connector, boolean enabled) {
        tenantExecution.run(tenant, () -> transactions.executeWithoutResult(status -> {
            switch (connector) {
                case AWS_DISCOVERY -> awsConfigs.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")
                        .ifPresent(config -> config.setAutoSyncEnabled(enabled));
                case AZURE_DISCOVERY -> azureConfigs.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "azure")
                        .ifPresent(config -> config.setAutoSyncEnabled(enabled));
                case SERVICENOW_CMDB -> serviceNowConfigs.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow")
                        .ifPresent(config -> config.setAutoSyncEnabled(enabled));
                case SCCM_CMDB -> sccmConfigs.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")
                        .ifPresent(config -> config.setAutoSyncEnabled(enabled));
                case GCP_DISCOVERY -> gcpConfigs.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "gcp")
                        .ifPresent(config -> config.setAutoSyncEnabled(enabled));
            }
        }));
    }

    private void assertEndpointStatus(Tenant tenant, Connector connector, boolean expected) throws Exception {
        if (connector == Connector.SERVICENOW_CMDB) {
            return; // ServiceNow has no separate sync/status controller route.
        }
        Object controller = switch (connector) {
            case AWS_DISCOVERY -> new AwsDiscoveryController(workspace, null, aws, null, null, null);
            case AZURE_DISCOVERY -> new AzureDiscoveryController(workspace, null, null, azure, null, null);
            case SCCM_CMDB -> new SccmCmdbController(workspace, null, sccm, null, null);
            case GCP_DISCOVERY -> new com.prototype.vulnwatch.controller.GcpDiscoveryController(workspace, null, gcp, null, null, null);
            default -> throw new IllegalStateException();
        };
        String path = switch (connector) {
            case AWS_DISCOVERY -> "aws-discovery";
            case AZURE_DISCOVERY -> "azure-discovery";
            case SCCM_CMDB -> "sccm-cmdb";
            case GCP_DISCOVERY -> "gcp-discovery";
            default -> throw new IllegalStateException();
        };
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller).build();
        tenantExecution.run(tenant, () -> {
            try {
                mvc.perform(get("/api/connectors/" + path + "/sync/status"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.active").value(expected))
                        .andExpect(jsonPath("$.status").value(expected ? "running" : "idle"));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for admission test transaction");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private enum Connector { AWS_DISCOVERY, AZURE_DISCOVERY, SERVICENOW_CMDB, SCCM_CMDB, GCP_DISCOVERY }
}
