package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.support.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@PostgresIntegrationTest
@TestPropertySource(properties = {
        "app.correlation.delta-queue-sweep-budget-ms=500",
        "app.correlation.delta-queue-transaction-timeout-seconds=2"
})
class DeltaQueueOwnershipPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB=LocalPostgresTestDatabase.provision("phase3_delta_ownership");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry){PostgresITSupport.registerDatabaseProperties(registry,DB);}
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired FindingDeltaQueueService queue;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;
    @MockitoBean DashboardNoiseReductionProjectionService projection;
    Tenant tenant;

    @BeforeEach void setup(){
        TenantContext.clear();String slug="delta-owner-"+UUID.randomUUID().toString().substring(0,8);
        tenant=tenants.createTenant(slug,slug,"ENTERPRISE",null);migrations.provisionNewTenant(tenant);tenant=tenants.resolveTenantUuid(tenant.getId());
        scoped.run(tenant,()->jdbc.execute("create table delta_effect(id integer primary key)"));
    }
    @AfterEach void clear(){TenantContext.clear();}

    @Test void lateAttemptCannotProcessOrAcknowledgeAReplacement(){
        var old=claim();
        stale();assertEquals(1,queue.recoverStaleProcessingEntries());
        var replacement=scoped.run(tenant,()->queue.claimBatch());
        assertEquals(2,replacement.get(0).getAttemptCount());
        scoped.run(tenant,()->queue.processClaimedBatch(old));
        scoped.run(tenant,()->queue.markFailedOrRetry(old.get(0).getId(),old.get(0).getAttemptCount(),3,"late failure"));
        scoped.run(tenant,()->assertEquals("PROCESSING",state()));
        verify(projection,never()).refreshTenant(any());
        when(projection.refreshTenant(tenant.getId())).thenReturn(1);
        scoped.run(tenant,()->queue.processClaimedBatch(replacement));
        scoped.run(tenant,()->assertEquals("DONE",state()));
    }

    @Test void recoverySkipsHealthyOwnerPastStaleThreshold()throws Exception{
        var claimed=claim();stale();
        CountDownLatch running=new CountDownLatch(1),finish=new CountDownLatch(1);
        when(projection.refreshTenant(tenant.getId())).thenAnswer(call->{running.countDown();assertTrue(finish.await(10,TimeUnit.SECONDS));return 1;});
        var pool=Executors.newSingleThreadExecutor();
        try{
            var work=pool.submit(()->scoped.run(tenant,()->queue.processClaimedBatch(claimed)));
            assertTrue(running.await(10,TimeUnit.SECONDS));
            assertEquals(0,queue.recoverStaleProcessingEntries());
            scoped.run(tenant,()->assertEquals("PROCESSING",state()));
            finish.countDown();work.get(15,TimeUnit.SECONDS);
        }finally{finish.countDown();pool.shutdownNow();}
        scoped.run(tenant,()->assertEquals("DONE",state()));
    }

    @Test void joinedDomainFailureRollsBackEffectsAndPersistsRetryAfterReleasingOwnership(){
        var claimed=claim();
        when(projection.refreshTenant(tenant.getId())).thenAnswer(call->new TransactionTemplate(manager).execute(status->{
            jdbc.update("insert into delta_effect values (1)");throw new IllegalStateException("injected domain rollback");
        }));
        scoped.run(tenant,()->queue.processClaimedBatch(claimed));
        scoped.run(tenant,()->{
            assertEquals("PENDING",state());assertEquals(0,jdbc.queryForObject("select count(*) from delta_effect",Integer.class));
            jdbc.update("update finding_delta_queue set visible_after=now()-interval '1 second'");
        });
        doAnswer(call->{jdbc.update("insert into delta_effect values (1)");return 1;}).when(projection).refreshTenant(tenant.getId());
        var retry=scoped.run(tenant,()->queue.claimBatch());
        scoped.run(tenant,()->queue.processClaimedBatch(retry));
        scoped.run(tenant,()->{assertEquals("DONE",state());assertEquals(1,jdbc.queryForObject("select count(*) from delta_effect",Integer.class));});
    }
    @Test void pendingReplacementRetainsIntentWhenFailedAttemptCannotReuseItsDedupeKey(){
        var first=claim();
        scoped.run(tenant,()->queue.enqueueNoiseReductionRefresh(tenant.getId(),"newer-source-change"));
        when(projection.refreshTenant(tenant.getId())).thenThrow(new IllegalStateException("offline failure"));
        scoped.run(tenant,()->queue.processClaimedBatch(first));
        scoped.run(tenant,()->{
            assertEquals(1,jdbc.queryForObject("select count(*) from finding_delta_queue where status='FAILED'",Integer.class));
            assertEquals(1,jdbc.queryForObject("select count(*) from finding_delta_queue where status='PENDING'",Integer.class));
        });
        doReturn(1).when(projection).refreshTenant(tenant.getId());
        var replacement=scoped.run(tenant,()->queue.claimBatch());
        scoped.run(tenant,()->queue.processClaimedBatch(replacement));
        scoped.run(tenant,()->assertEquals(1,jdbc.queryForObject("select count(*) from finding_delta_queue where status='DONE'",Integer.class)));
    }

    @Test
    void slowFindingBatchRollsBackAndNextPollStartsAtTheUnvisitedWorkspace() throws Exception {
        String slug = "delta-peer-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant peer = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(peer);
        scoped.run(tenant, () -> queue.enqueueNoiseReductionRefresh(tenant.getId(), "slow-fixture"));
        scoped.run(peer, () -> queue.enqueueNoiseReductionRefresh(peer.getId(), "peer-fixture"));
        var orderedTenants = tenants.listActiveTenants().stream().map(Tenant::getId).toList();
        org.springframework.test.util.ReflectionTestUtils.setField(
                queue, "nextTenantOffset", orderedTenants.indexOf(tenant.getId()));
        when(projection.refreshTenant(tenant.getId())).thenAnswer(call -> {
            jdbc.update("insert into delta_effect values (1)");
            return jdbc.queryForObject("select 1 from pg_sleep(15)", Integer.class);
        });
        when(projection.refreshTenant(peer.getId())).thenReturn(1);

        var executor = Executors.newSingleThreadExecutor();
        try {
            executor.submit(queue::processPendingDeltas).get(8, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
        scoped.run(tenant, () -> {
            assertEquals("PENDING", state());
            assertEquals(0, jdbc.queryForObject("select count(*) from delta_effect", Integer.class));
            assertEquals(1, jdbc.queryForObject("select attempt_count from finding_delta_queue", Integer.class));
        });
        scoped.run(peer, () -> assertEquals("PENDING", state()));

        queue.processPendingDeltas();

        scoped.run(peer, () -> assertEquals("DONE", state()));
        verify(projection, times(1)).refreshTenant(tenant.getId());
    }

    private List<FindingDeltaQueueEntry> claim(){return scoped.run(tenant,()->{queue.enqueueNoiseReductionRefresh(tenant.getId(),"ownership-test");return queue.claimBatch();});}
    private void stale(){scoped.run(tenant,()->jdbc.update("update finding_delta_queue set processing_started_at=now()-interval '2 hours'"));}
    private String state(){return jdbc.queryForObject("select status from finding_delta_queue",String.class);}
}
