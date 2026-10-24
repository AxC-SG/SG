package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.support.*;
import java.sql.DriverManager;
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
class PhaseThreeDurableWorkPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB=LocalPostgresTestDatabase.provision("phase3_durable_work");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) { PostgresITSupport.registerDatabaseProperties(registry,DB); }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired IngestionJobService jobs;
    @Autowired IngestionJobWorkerService worker;
    @Autowired FindingDeltaQueueService deltas;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;
    @Autowired InvitationEmailOutboxService invitations;
    @Autowired com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService retention;
    @MockitoBean ResendEmailClient email;
    @MockitoBean com.prototype.vulnwatch.client.http.OutboundHttpClient transport;
    @MockitoBean(name="integrationQueueExecutor") org.springframework.core.task.TaskExecutor integrationExecutor;
    @Autowired com.prototype.vulnwatch.service.vulningestion.KevSyncService kev;
    @Autowired com.prototype.vulnwatch.service.vulningestion.VulnerabilityQueuedRunWorkerService feedWorker;
    @Autowired com.prototype.vulnwatch.repo.SyncRunRepository syncRuns;
    Tenant tenant;
    @BeforeEach void tenant() {
        TenantContext.clear();
        String slug="phase3-"+UUID.randomUUID().toString().substring(0,8);
        tenant=tenants.createTenant(slug,slug,"ENTERPRISE",null);
        migrations.provisionNewTenant(tenant);
        tenant=tenants.resolveTenantUuid(tenant.getId());
    }
    @AfterEach void clear() { TenantContext.clear(); }
    SbomEndpointIngestionRequest request(String identity) {
        return new SbomEndpointIngestionRequest(AssetType.APPLICATION,"phase3",identity,"https://example.test/bom.json","test",null);
    }
    long independentCount(String table) throws Exception {
        try(var connection=DriverManager.getConnection(DB.url(),DB.username(),DB.password());var statement=connection.createStatement();var rows=statement.executeQuery("select count(*) from \""+tenant.getSchemaName()+"\"."+table)) { rows.next();return rows.getLong(1); }
    }
    @Test void sourceAndDeltaAreInvisibleBeforeCommitAndAbsentAfterRollback() {
        assertThrows(IllegalStateException.class,() -> scoped.run(tenant,() -> new TransactionTemplate(manager).execute(status -> {
            jobs.enqueueEndpointJob(tenant,request("atomic"),"test");
            deltas.enqueueNoiseReductionRefresh(tenant.getId(),"phase3");
            try { assertEquals(0,independentCount("ingestion_jobs"));assertEquals(0,independentCount("finding_delta_queue")); }
            catch(Exception failure) { throw new AssertionError(failure); }
            throw new IllegalStateException("producer rollback");
        })));
        scoped.run(tenant,() -> {assertEquals(0,jdbc.queryForObject("select count(*) from ingestion_jobs",Integer.class));assertEquals(0,jdbc.queryForObject("select count(*) from finding_delta_queue",Integer.class));});
    }
    @Test void concurrentDuplicateAdmissionReturnsOneDurableIdentity() throws Exception {
        ExecutorService pool=Executors.newFixedThreadPool(2);
        CyclicBarrier start=new CyclicBarrier(2);
        try {
            Callable<UUID> admit=() -> {start.await(10,TimeUnit.SECONDS);return jobs.enqueueEndpointJob(tenant,request("same-source"),"test").jobId();};
            Future<UUID> first=pool.submit(admit),second=pool.submit(admit);
            assertEquals(first.get(30,TimeUnit.SECONDS),second.get(30,TimeUnit.SECONDS));
            assertEquals(1,independentCount("ingestion_jobs"));
        } finally {pool.shutdownNow();}
    }
    @Test void expiredOriginalAttemptCannotCommitDomainWritesOrCompletion() throws Exception {
        UUID id=jobs.enqueueEndpointJob(tenant,request("stale"),"test").jobId();
        var claim=jobs.claimPendingJobs(tenant,1,1).get(0);
        scoped.run(tenant,() -> jdbc.execute("create table phase3_attempt_effect(value text)"));
        try(var ownership=jobs.openAttempt(tenant.getId(),id,claim.claimToken())) {
            assertThrows(IngestionAttemptService.StaleAttemptException.class,() -> scoped.run(tenant,() -> new TransactionTemplate(manager).execute(status -> {
                jdbc.update("insert into phase3_attempt_effect values ('late worker')");
                try(var c=DriverManager.getConnection(DB.url(),DB.username(),DB.password());var p=c.prepareStatement("update \""+tenant.getSchemaName()+"\".ingestion_jobs set claim_token=?,lease_expires_at=clock_timestamp()+interval '2 minutes' where id=?")) {
                    p.setObject(1,UUID.randomUUID());p.setObject(2,id);p.executeUpdate();
                } catch(Exception failure) {throw new AssertionError(failure);}
                return null;
            })));
            assertThrows(IngestionAttemptService.StaleAttemptException.class,() -> jobs.markSucceeded(tenant.getId(),id,null,"{}"));
        }
        assertEquals(0,independentCount("phase3_attempt_effect"));
    }
    @Test void healthyWorkerSurvivesOtherWorkersRecovery() {
        UUID id=jobs.enqueueEndpointJob(tenant,request("healthy"),"test").jobId();
        var claim=jobs.claimPendingJobs(tenant,1,1).get(0);
        jobs.recoverInterruptedRunningJobs();
        assertEquals("RUNNING",jobs.loadJob(tenant.getId(),id).getStatus());
        assertEquals(claim.claimToken(),jobs.loadJob(tenant.getId(),id).getClaimToken());
        try(var ownership=jobs.openAttempt(tenant.getId(),id,claim.claimToken())) {jobs.markSucceeded(tenant.getId(),id,null,"{}");}
        assertEquals("SUCCEEDED",jobs.loadJob(tenant.getId(),id).getStatus());
    }
    @Test void rolledBackInvitationDoesNotLeaveDeliveryIntentOrContactProvider() {
        when(email.freeze(any(),any())).thenAnswer(call -> call.getArgument(0));
        UUID related=UUID.randomUUID();
        assertThrows(IllegalStateException.class,() -> new TransactionTemplate(manager).execute(status -> {
            invitations.enqueue(tenant.getId(),"TENANT_INVITE",related,InvitationTokens.hash("test-token"),new ResendEmailClient.EmailMessage("offline@example.test","test","<p>test</p>","test",Map.of(),"test"));
            throw new IllegalStateException("invite rollback");
        }));
        assertEquals(0,jdbc.queryForObject("select count(*) from platform.invitation_email_outbox where related_id=?",Integer.class,related));
        verify(email,never()).send(any());
    }
    @Test void invitationRetryReusesImmutableMessageAndStopsBeforeProviderWindowExpires() {
        when(email.isConfigured()).thenReturn(true);
        when(email.freeze(any(),any())).thenAnswer(call -> {
            ResendEmailClient.EmailMessage m=call.getArgument(0);
            return new ResendEmailClient.EmailMessage(m.to(),m.subject(),m.html(),m.text(),m.tags(),call.getArgument(1),"sender@example.test");
        });
        UUID invite=UUID.randomUUID();String hash=InvitationTokens.hash("private-test-link");
        jdbc.update("""
                insert into platform.tenant_user_invites(id,tenant_id,email,external_subject,role,status,token_hash,expires_at,created_at,updated_at)
                values (?,?,?,?,'READ_ONLY_AUDITOR','QUEUED',?,now()+interval '7 days',now(),now())
                """,invite,tenant.getId(),"offline@example.test","offline@example.test",hash);
        var message=new ResendEmailClient.EmailMessage("offline@example.test","invite","<p>private-test-link</p>","private-test-link",Map.of(),null);
        invitations.enqueue(tenant.getId(),"TENANT_INVITE",invite,hash,message);
        invitations.enqueue(tenant.getId(),"TENANT_INVITE",invite,hash,message);
        assertEquals(1,jdbc.queryForObject("select count(*) from platform.invitation_email_outbox where related_id=?",Integer.class,invite));
        assertFalse(jdbc.queryForObject("select encrypted_payload from platform.invitation_email_outbox where related_id=?",String.class,invite).contains("private-test-link"));
        when(email.send(any())).thenReturn(new ResendEmailClient.DeliveryResult(ResendEmailClient.DeliveryState.RETRYABLE,null,"PROVIDER_OUTCOME_UNKNOWN"));
        invitations.poll();
        assertEquals("PENDING",jdbc.queryForObject("select status from platform.invitation_email_outbox where related_id=?",String.class,invite));
        jdbc.update("update platform.invitation_email_outbox set visible_at=now()-interval '1 minute' where related_id=?",invite);
        when(email.send(any())).thenReturn(ResendEmailClient.DeliveryResult.sent("provider-accepted"));
        invitations.poll();
        var sent=org.mockito.ArgumentCaptor.forClass(ResendEmailClient.EmailMessage.class);
        verify(email,times(2)).send(sent.capture());
        assertEquals(sent.getAllValues().get(0),sent.getAllValues().get(1));
        assertEquals("ACCEPTED",jdbc.queryForObject("select status from platform.invitation_email_outbox where related_id=?",String.class,invite));
        assertEquals("",jdbc.queryForObject("select encrypted_payload from platform.invitation_email_outbox where related_id=?",String.class,invite));
        // A rotated link creates a new delivery identity. An uncertain old send is never replayed after 23 hours.
        String rotated=InvitationTokens.hash("rotated-test-link");
        jdbc.update("update platform.tenant_user_invites set token_hash=? where id=?",rotated,invite);
        invitations.enqueue(tenant.getId(),"TENANT_INVITE",invite,rotated,message);
        jdbc.update("update platform.invitation_email_outbox set first_attempt_at=now()-interval '23 hours' where related_id=? and status='PENDING'",invite);
        invitations.poll();
        verify(email,times(2)).send(any());
        assertEquals(1,jdbc.queryForObject("select count(*) from platform.invitation_email_outbox where related_id=? and status='UNKNOWN'",Integer.class,invite));
        UUID unknown=jdbc.queryForObject("select id from platform.invitation_email_outbox where related_id=? and status='UNKNOWN'",UUID.class,invite);
        assertThrows(org.springframework.web.server.ResponseStatusException.class,() -> invitations.reconcile(UUID.randomUUID(),unknown,"ACCEPTED","provider-found","operator","Provider lookup confirmed acceptance"));
        invitations.reconcile(tenant.getId(),unknown,"ACCEPTED","provider-found","operator","Provider lookup confirmed acceptance");
        assertEquals("operator",jdbc.queryForObject("select reconciled_by from platform.invitation_email_outbox where id=?",String.class,unknown));
        assertEquals("SENT",jdbc.queryForObject("select status from platform.tenant_user_invites where id=?",String.class,invite));
        assertThrows(org.springframework.web.server.ResponseStatusException.class,() -> invitations.reconcile(tenant.getId(),unknown,"FAILED",null,"operator","Cannot overwrite an accepted reconciliation"));
    }

    @Test void retentionResumesBoundedBatchesWithoutPurgingLegalHold() {
        scoped.run(tenant,() -> {
            for (int n=1;n<=7;n++) jdbc.update("""
                    insert into ai_grid_snapshot_bodies(id,tenant_id,content_hash,content_json,byte_size,redaction_profile,created_at,retain_until,legal_hold)
                    values (?,?,?,'{}'::jsonb,2,'TEST',now()-interval '5000 days',now()-interval '1 day',?)
                    """,new UUID(0,n),tenant.getId(),String.format("%064d",n),n==3);
        });
        org.springframework.test.util.ReflectionTestUtils.setField(retention,"batchSize",2);
        org.springframework.test.util.ReflectionTestUtils.setField(retention,"maxBatches",1);
        try {
            int evaluated=0,purged=0;
            boolean complete=false;
            for (int run=0;run<5;run++) {
                var result=retention.sweep(tenant);
                assertTrue(result.evaluated()<=2);assertEquals(1,result.batches());
                evaluated+=result.evaluated();purged+=result.purged();
                if ("COMPLETED".equals(result.status())) {complete=true;break;}
            }
            assertTrue(complete);assertEquals(7,evaluated);assertEquals(6,purged);
            scoped.run(tenant,() -> {
                assertEquals(1,jdbc.queryForObject("select count(*) from ai_grid_snapshot_bodies where legal_hold=true",Integer.class));
                assertEquals(6,jdbc.queryForObject("select count(*) from ai_grid_retention_purge_audit",Integer.class));
                assertEquals("COMPLETED",jdbc.queryForObject("select state from ai_grid_retention_progress where tenant_id=?",String.class,tenant.getId()));
            });
        } finally {
            org.springframework.test.util.ReflectionTestUtils.setField(retention,"batchSize",100);
            org.springframework.test.util.ReflectionTestUtils.setField(retention,"maxBatches",10);
        }
    }

    @Test void scheduledRecoveryRequeuesLeaseThatExpiresAfterStartup() {
        UUID id=jobs.enqueueEndpointJob(tenant,request("expiry-after-startup"),"test").jobId();
        jobs.claimPendingJobs(tenant,1,1);
        worker.recoverInterruptedJobs();
        assertEquals("RUNNING",jobs.loadJob(tenant.getId(),id).getStatus());
        scoped.run(tenant,() -> jdbc.update("update ingestion_jobs set lease_expires_at=clock_timestamp()-interval '1 second' where id=?",id));
        worker.recoverInterruptedJobs();
        assertEquals("QUEUED",jobs.loadJob(tenant.getId(),id).getStatus());
        assertEquals(1,jobs.claimPendingJobs(tenant,1,1).size());
    }

    @Test void queuedNonemptyPlatformFeedStagesWithoutTenantFanout() throws Exception {
        String slug="feed-peer-"+UUID.randomUUID().toString().substring(0,8);
        Tenant peer=tenants.createTenant(slug,slug,"ENTERPRISE",null);migrations.provisionNewTenant(peer);peer=tenants.resolveTenantUuid(peer.getId());
        String feed="{\"vulnerabilities\":[{\"cveID\":\"CVE-2099-99991\",\"vulnerabilityName\":\"offline regression\"}]}";
        doReturn(feed).when(transport).execute(org.mockito.ArgumentMatchers.anyString(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.eq(String.class),org.mockito.ArgumentMatchers.anyString(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any());
        doAnswer(call -> {((Runnable)call.getArgument(0)).run();return null;}).when(integrationExecutor).execute(any(Runnable.class));
        var accepted=TenantContext.runAsPlatform(() -> kev.triggerKevSync());
        feedWorker.pollQueuedRuns();
        assertEquals("completed",syncRuns.findById(accepted.runId()).orElseThrow().getStatus());
        assertTrue(jdbc.queryForObject("select count(*) from platform.intelligence_staged_records where sync_run_id=?",Integer.class,accepted.runId())>0);
        for (Tenant target:List.of(tenant,peer)) scoped.run(target,() -> assertEquals(0,jdbc.queryForObject("select count(*) from finding_delta_queue where event_type='CVE_METADATA_DELTA' and source_tag='vulnerability-ingestion'",Integer.class)));
    }

}
