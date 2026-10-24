package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioConnectorService;
import com.prototype.vulnwatch.client.EolApiClient;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.vulningestion.*;
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
class SchedulerOverlapPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB = LocalPostgresTestDatabase.provision("schedule_overlap");
    private static final Instant DUE = Instant.parse("2026-10-18T02:00:00Z");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }
    @Autowired VulnerabilitySyncRunService runs;
    @Autowired VulnerabilityQueuedRunWorkerService worker;
    @Autowired EolRefreshService eol;
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired DemoDatasetProvisioningService demos;
    @Autowired CopilotStudioConnectorService copilot;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;
    @MockitoBean CustomerDemoDatasetService dataset;
    @MockitoBean EolApiClient eolApi;
    @MockitoBean AiSecurityAzureCredentialService credentials;
    @MockitoBean com.prototype.vulnwatch.client.http.OsvApiClient osvApi;
    @MockitoBean com.prototype.vulnwatch.client.http.OutboundHttpClient transport;
    @MockitoBean(name="integrationQueueExecutor") org.springframework.core.task.TaskExecutor executor;
    Tenant tenant;

    @BeforeEach void setup() {
        TenantContext.clear();
        for(String type:VulnerabilitySyncRunService.SUPPORTED_TYPES) jdbc.update("insert into platform.intelligence_feed_schedules(sync_type,enabled,next_due_at) values (?,true,now()-interval '1 hour') on conflict(sync_type) do update set enabled=true,next_due_at=now()-interval '1 hour'",type);
        jdbc.update("delete from platform.sync_runs where tenant_id is null and run_scope='PLATFORM_VULNERABILITY'");
        String slug = "schedule-" + UUID.randomUUID().toString().substring(0,8);
        tenant = tenants.createTenant(slug,slug,"ENTERPRISE",null);
        migrations.provisionNewTenant(tenant);
        tenant = tenants.resolveTenantUuid(tenant.getId());
    }
    @AfterEach void clear() { TenantContext.clear(); }

    @Test void twoCallersAdmitOneOccurrenceAndCompletionDoesNotForgetIt() throws Exception {
        List<UUID> ids = race(() -> runs.prepareScheduledRun("OSV",DUE).run().getId());
        assertEquals(ids.get(0), ids.get(1));
        jdbc.update("update platform.sync_runs set status='completed' where id=?",ids.get(0));
        assertEquals(ids.get(0), runs.prepareScheduledRun("OSV",DUE).run().getId());
        assertEquals(1, jdbc.queryForObject("select count(*) from platform.sync_runs where sync_type='OSV'",Integer.class));
        jdbc.update("update platform.intelligence_feed_schedules set next_due_at=now()-interval '1 hour' where sync_type='OSV'");
        assertNotEquals(ids.get(0),runs.prepareScheduledRun("OSV",DUE.plusSeconds(86400)).run().getId());
        assertNotEquals(ids.get(0),runs.prepareScheduledRun("EPSS",DUE).run().getId());
    }

    @Test void rollbackLeavesNeitherOccurrenceNorExecutableIntent() {
        UUID[] id = new UUID[1];
        assertThrows(IllegalStateException.class, () -> new TransactionTemplate(manager).execute(status -> {
            id[0] = runs.prepareScheduledRun("OSV",DUE).run().getId();
            try(var connection = DriverManager.getConnection(DB.url(),DB.username(),DB.password());
                var query = connection.prepareStatement("select count(*) from platform.sync_runs where id=?")) {
                query.setObject(1,id[0]);
                try(var rows=query.executeQuery()) { rows.next(); assertEquals(0,rows.getInt(1)); }
            } catch(Exception failure) { throw new AssertionError(failure); }
            throw new IllegalStateException("abort producer");
        }));
        assertEquals(0,jdbc.queryForObject("select count(*) from platform.sync_runs where id=?",Integer.class,id[0]));
        assertNotEquals(id[0],runs.prepareScheduledRun("OSV",DUE).run().getId());
    }

    @Test void conflictingEolStagesWaitWhileIndependentFeedsProgress() {
        var catalog=runs.prepareScheduledRun("EOL_CATALOG_REFRESH",DUE).run();
        var releases=runs.prepareScheduledRun("EOL_RELEASE_REFRESH",DUE).run();
        var osv=runs.prepareScheduledRun("OSV",DUE).run();
        var owner=runs.markRunningIfQueued(catalog.getId()).orElseThrow();
        assertNotNull(owner.getClaimToken());
        assertTrue(runs.markRunningIfQueued(releases.getId()).isEmpty());
        assertTrue(runs.markRunningIfQueued(osv.getId()).isPresent());
        runs.recoverStaleRuns();
        assertEquals(owner.getClaimToken(),runs.requireRun(catalog.getId()).getClaimToken());
        jdbc.update("update platform.sync_runs set lease_expires_at=clock_timestamp()-interval '1 second' where id=?",catalog.getId());
        runs.recoverStaleRuns();
        assertEquals("queued",runs.requireRun(catalog.getId()).getStatus());
        assertTrue(runs.markRunningIfQueued(releases.getId()).isPresent());
    }

    @Test void blockedFamilyCannotHideAnIndependentFeedBeyondThePollBound() {
        var busy=runs.prepareScheduledRun("EOL_CATALOG_REFRESH",DUE).run();
        runs.markRunningIfQueued(busy.getId()).orElseThrow();
        jdbc.update("""
                insert into platform.sync_runs(id,sync_type,run_scope,status,started_at,
                    records_failed,records_fetched,records_inserted,records_updated)
                select gen_random_uuid(),'EOL_RELEASE_REFRESH','PLATFORM_VULNERABILITY','queued',
                    clock_timestamp()-interval '1 minute',0,0,0,0 from generate_series(1,101)
                """);
        var independent=runs.prepareScheduledRun("OSV",DUE).run();
        doAnswer(call -> { ((Runnable)call.getArgument(0)).run(); return null; }).when(executor).execute(any(Runnable.class));
        worker.pollQueuedRuns();
        assertEquals("completed",runs.requireRun(independent.getId()).getStatus());
        assertEquals("running",runs.requireRun(busy.getId()).getStatus());
        assertEquals(101,jdbc.queryForObject("select count(*) from platform.sync_runs where sync_type='EOL_RELEASE_REFRESH' and status='queued'",Integer.class));
    }

    @Test void manualEolOnApiOnlyQueuesAndRejectedDispatchRemainsRecoverable() {
        eol.setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy.forRole("api"));
        UUID id;
        try {
            id=eol.triggerCatalogRefresh().runId();
            verifyNoInteractions(eolApi,executor);
            assertEquals("queued",runs.requireRun(id).getStatus());
        } finally { eol.setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy.allowAll()); }
        doThrow(new RejectedExecutionException("offline capacity")).when(executor).execute(any(Runnable.class));
        worker.pollQueuedRuns();
        assertEquals("queued",runs.requireRun(id).getStatus());
        when(eolApi.fetchAllProducts()).thenReturn(List.of(new EolApiClient.EolProductSummary("offline-product","Offline product",null,null,List.of())));
        doAnswer(call -> { ((Runnable)call.getArgument(0)).run(); return null; }).when(executor).execute(any(Runnable.class));
        worker.pollQueuedRuns();
        assertEquals("completed",runs.requireRun(id).getStatus());
        assertEquals(1,jdbc.queryForObject("select count(*) from platform.eol_product_catalog where slug='offline-product'",Integer.class));
    }

    @Test void differentManualEolStagesRetainTheirOwnAcceptedIntent() {
        UUID catalog=eol.triggerCatalogRefresh().runId();
        UUID denormalize=eol.triggerDenormalize().runId();
        assertNotEquals(catalog,denormalize);
        assertEquals("EOL_CATALOG_REFRESH",runs.requireRun(catalog).getSyncType());
        assertEquals("EOL_DENORMALIZE",runs.requireRun(denormalize).getSyncType());
        assertEquals(catalog,eol.triggerCatalogRefresh().runId());
        verifyNoInteractions(eolApi,executor);
    }

    @Test void replacedEolOwnerCannotCommitCatalogBatch() {
        UUID id=eol.triggerCatalogRefresh().runId();
        when(eolApi.fetchAllProducts()).thenAnswer(call -> {
            try(var connection=DriverManager.getConnection(DB.url(),DB.username(),DB.password());
                var update=connection.prepareStatement("update platform.sync_runs set claim_token=? where id=?")) {
                update.setObject(1,UUID.randomUUID());update.setObject(2,id);update.executeUpdate();
            }
            return List.of(new EolApiClient.EolProductSummary("stale-owner-product","Stale owner",null,null,List.of()));
        });
        doAnswer(call -> { ((Runnable)call.getArgument(0)).run(); return null; }).when(executor).execute(any(Runnable.class));
        worker.pollQueuedRuns();
        assertEquals(0,jdbc.queryForObject("select count(*) from platform.eol_product_catalog where slug='stale-owner-product'",Integer.class));
        assertEquals("running",runs.requireRun(id).getStatus());
    }

    @Test void osvAndEpssIntentsExecuteThroughTheOwnedWorker() {
        var osv=runs.prepareScheduledRun("OSV",DUE).run();
        var epss=runs.prepareScheduledRun("EPSS",DUE).run();
        doAnswer(call -> { ((Runnable)call.getArgument(0)).run(); return null; }).when(executor).execute(any(Runnable.class));
        worker.pollQueuedRuns();
        assertEquals("completed",runs.requireRun(osv.getId()).getStatus());
        assertEquals("completed",runs.requireRun(epss.getId()).getStatus());
    }

    @Test void copilotCursorCommitsWithOneJobAndSurvivesJobCompletion() throws Exception {
        UUID connector=createCopilot(tenant);
        race(() -> {copilot.triggerScheduled(tenant,connector,"0 0 * * * *",DUE);return connector;});
        scoped.run(tenant, () -> {
            assertEquals(1,jdbc.queryForObject("select count(*) from ingestion_jobs where job_type='AI_SECURITY_COPILOT_STUDIO'",Integer.class));
            jdbc.update("update ingestion_jobs set status='SUCCEEDED' where job_type='AI_SECURITY_COPILOT_STUDIO'");
        });
        copilot.triggerScheduled(tenant,connector,"0 0 * * * *",DUE);
        scoped.run(tenant, () -> assertEquals(1,jdbc.queryForObject("select count(*) from ingestion_jobs",Integer.class)));
        copilot.triggerScheduled(tenant,connector,"0 0 * * * *",DUE.plusSeconds(3600));
        scoped.run(tenant, () -> assertEquals(2,jdbc.queryForObject("select count(*) from ingestion_jobs",Integer.class)));
    }

    @Test void copilotSchedulesProgressForIndependentTenants() throws Exception {
        String slug="schedule-peer-"+UUID.randomUUID().toString().substring(0,8);
        Tenant peer=tenants.createTenant(slug,slug,"ENTERPRISE",null);
        migrations.provisionNewTenant(peer);
        Tenant readyPeer=tenants.resolveTenantUuid(peer.getId());
        UUID first=createCopilot(tenant),second=createCopilot(readyPeer);
        ExecutorService pool=Executors.newFixedThreadPool(2);
        CyclicBarrier start=new CyclicBarrier(2);
        try {
            Future<?> a=pool.submit(() -> {await(start);copilot.triggerScheduled(tenant,first,"0 0 * * * *",DUE);});
            Future<?> b=pool.submit(() -> {await(start);copilot.triggerScheduled(readyPeer,second,"0 0 * * * *",DUE);});
            a.get(30,TimeUnit.SECONDS);b.get(30,TimeUnit.SECONDS);
        } finally {pool.shutdownNow();}
        for (Tenant target:List.of(tenant,readyPeer)) scoped.run(target,() ->
                assertEquals(1,jdbc.queryForObject("select count(*) from ingestion_jobs",Integer.class)));
    }

    static void await(CyclicBarrier barrier) {
        try {barrier.await(10,TimeUnit.SECONDS);}
        catch(Exception failure) {throw new AssertionError(failure);}
    }

    @Test void copilotFailedAdmissionDoesNotAdvanceCursorOrLeaveAJob() {
        UUID connector=createCopilot(tenant);
        doThrow(new IllegalStateException("offline credential unavailable")).when(credentials).secret(any(),any());
        assertThrows(IllegalStateException.class, () -> copilot.triggerScheduled(tenant,connector,"0 0 * * * *",DUE));
        assertEquals(0,jdbc.queryForObject("select count(*) from platform.copilot_schedule_progress where tenant_id=?",Integer.class,tenant.getId()));
        scoped.run(tenant, () -> assertEquals(0,jdbc.queryForObject("select count(*) from ingestion_jobs",Integer.class)));
        reset(credentials);
        copilot.triggerScheduled(tenant,connector,"0 0 * * * *",DUE);
        assertEquals(DUE,jdbc.queryForObject("select last_occurrence_at from platform.copilot_schedule_progress where tenant_id=?",java.sql.Timestamp.class,tenant.getId()).toInstant());
    }

    @Test void interruptedDemoSeedRollsBackDataAndLegacySeedingMarkerCanResume() {
        jdbc.update("update platform.tenants set demo_source=? where id=?",DemoDatasetProvisioningService.SEEDING_MARKER,tenant.getId());
        scoped.run(tenant, () -> jdbc.execute("create table seed_effect(value text)"));
        doAnswer(call -> {jdbc.update("insert into seed_effect values ('uncommitted')");throw new IllegalStateException("process lost before commit");}).when(dataset).seed(any());
        assertThrows(IllegalStateException.class, () -> demos.seedIfReady(tenant.getId()));
        scoped.run(tenant, () -> assertEquals(0,jdbc.queryForObject("select count(*) from seed_effect",Integer.class)));
        assertEquals(DemoDatasetProvisioningService.SEEDING_MARKER,jdbc.queryForObject("select demo_source from platform.tenants where id=?",String.class,tenant.getId()));
        doAnswer(call -> {jdbc.update("insert into seed_effect values ('committed')");return null;}).when(dataset).seed(any());
        demos.seedIfReady(tenant.getId());
        scoped.run(tenant, () -> assertEquals(1,jdbc.queryForObject("select count(*) from seed_effect",Integer.class)));
        assertEquals(DemoDatasetProvisioningService.SEEDED_MARKER,jdbc.queryForObject("select demo_source from platform.tenants where id=?",String.class,tenant.getId()));
    }

    @Test void overlappingDemoSeedPreservesTheHealthyOwner() throws Exception {
        CountDownLatch entered=new CountDownLatch(1),finish=new CountDownLatch(1);
        doAnswer(call -> {entered.countDown();assertTrue(finish.await(15,TimeUnit.SECONDS));return null;}).when(dataset).seed(any());
        ExecutorService pool=Executors.newSingleThreadExecutor();
        try {
            Future<?> owner=pool.submit(() -> demos.seedIfReady(tenant.getId()));
            assertTrue(entered.await(15,TimeUnit.SECONDS));
            assertEquals("Demo data seed is already running",assertThrows(IllegalStateException.class,() -> demos.seedIfReady(tenant.getId())).getMessage());
            finish.countDown();owner.get(20,TimeUnit.SECONDS);
            verify(dataset,times(1)).seed(any());
        } finally {finish.countDown();pool.shutdownNow();}
    }

    @Autowired org.springframework.context.ApplicationContext application;
    @Test void everyCronCallbackDeclaresUtc() {
        int callbacks=0;
        for (String bean : application.getBeanDefinitionNames()) {
            Class<?> type=application.getType(bean);
            if (type == null || !type.getName().startsWith("com.prototype.vulnwatch")) continue;
            for (var method : org.springframework.aop.support.AopUtils.getTargetClass(application.getBean(bean)).getDeclaredMethods()) {
                var schedule=method.getAnnotation(org.springframework.scheduling.annotation.Scheduled.class);
                if (schedule != null && !schedule.cron().isBlank()) {
                    assertEquals("UTC",schedule.zone(),method.toString());
                    callbacks++;
                }
            }
        }
        assertTrue(callbacks>=20);
    }

    UUID createCopilot(Tenant target) {
        UUID id=UUID.randomUUID();
        UUID profile=UUID.randomUUID();
        scoped.run(target, () -> {
            jdbc.update("""
                    insert into ai_security_azure_credential_profiles(id,tenant_id,name,auth_type,azure_tenant_id,created_by,updated_by)
                    values (?,?,'Offline profile','MANAGED_IDENTITY','offline-tenant','test','test')
                    """,profile,target.getId());
            jdbc.update("""
                    insert into ai_security_copilot_studio_configs(id,tenant_id,organization_url,credential_profile_id,discovery_enabled,schedule_cron)
                    values (?,?,?, ?,true,'0 0 * * * *')
                    """,id,target.getId(),"https://offline.dynamics.com",profile);
        });
        return id;
    }
    <T> List<T> race(Callable<T> operation) throws Exception {
        ExecutorService pool=Executors.newFixedThreadPool(2);
        CyclicBarrier start=new CyclicBarrier(2);
        try {
            Callable<T> callback=() -> { start.await(10,TimeUnit.SECONDS);return operation.call(); };
            Future<T> first=pool.submit(callback),second=pool.submit(callback);
            return List.of(first.get(30,TimeUnit.SECONDS),second.get(30,TimeUnit.SECONDS));
        } finally {pool.shutdownNow();}
    }
}
