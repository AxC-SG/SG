package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.support.*;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Owner provisions fixtures; expiry and delivery execute as non-owner, non-bypass roles. */
@PostgresIntegrationTest
class DemoExpiryDeliveryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("phase3_demo_expiry_delivery");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired DemoTenantPurgeService expiry;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;
    @Autowired ObjectMapper mapper;
    @Autowired CredentialEncryptionService encryption;
    @MockitoSpyBean AuditEventService audit;
    @MockitoBean RequestActorService actors;
    Tenant tenant;
    String role;
    InvitationEmailOutboxService outbox;
    ResendEmailClient provider;
    UUID requestId;
    UUID inviteId;
    UUID deliveryId;
    JdbcTemplate runtime;
    TransactionTemplate runtimeTransactions;
    BackgroundTaskExecutionPolicy background;

    @BeforeEach void setup() {
        TenantContext.clear();
        when(actors.currentActor()).thenReturn(new RequestActor("expiry-test", true, null, null, Set.of("PLATFORM_OWNER")));
        String slug = "expiry-" + UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        tenant = tenants.resolveTenantUuid(tenant.getId());
        role = "expiry_" + UUID.randomUUID().toString().replace("-", "");
        String password = UUID.randomUUID().toString();
        jdbc.execute("create role " + role + " login nosuperuser nobypassrls noinherit password '" + password + "'");
        jdbc.execute("grant usage on schema platform,tenant_default to " + role);
        jdbc.execute("grant select,update on platform.tenants to " + role);
        jdbc.execute("grant select on platform.app_users to " + role);
        jdbc.execute("grant select,insert,update on platform.tenant_intelligence_processing to " + role);
        jdbc.execute("grant select,insert,update on platform.invitation_email_outbox to " + role);
        jdbc.execute("grant select,update on tenant_default.demo_invites,tenant_default.demo_requests to " + role);
        jdbc.execute("grant select,insert on tenant_default.audit_events to " + role);
        var source = new DriverManagerDataSource(DB.url(), role, password);
        runtime = new JdbcTemplate(source);
        runtimeTransactions = new TransactionTemplate(new DataSourceTransactionManager(source));
        background = BackgroundTaskExecutionPolicy.allowAll();
        assertFalse(runtime.queryForObject("select rolsuper or rolbypassrls from pg_roles where rolname=current_user", Boolean.class));
        provider = mock(ResendEmailClient.class);
        when(provider.isConfigured()).thenReturn(true);
        when(provider.freeze(any(), any())).thenAnswer(call -> {
            ResendEmailClient.EmailMessage message = call.getArgument(0);
            return new ResendEmailClient.EmailMessage(message.to(), message.subject(), message.html(), message.text(),
                    message.tags(), call.getArgument(1), "sender@example.test");
        });
        when(provider.send(any())).thenReturn(ResendEmailClient.DeliveryResult.sent("offline-provider-accepted"));
        outbox = new InvitationEmailOutboxService(runtime, new DataSourceTransactionManager(source), mapper,
                encryption, provider, background, "tenant_default");
    }

    @AfterEach void cleanup() {
        TenantContext.clear();
        if (role != null) { jdbc.execute("drop owned by " + role); jdbc.execute("drop role " + role); }
        // Each poll uses the real global outbox. Remove only this disposable
        // fixture's delivery rows so another case cannot claim their leftovers.
        if (tenant != null) {
            jdbc.update("delete from platform.invitation_email_outbox where tenant_id=?", tenant.getId());
            jdbc.update("delete from tenant_default.demo_invites where tenant_id=?", tenant.getId());
            jdbc.update("delete from tenant_default.demo_requests where tenant_id=?", tenant.getId());
        }
    }

    @Test void overlappingExpiryCommitsOneAuditAndRetainsSchemaAndData() throws Exception {
        seedDelivery();
        makeDue();
        CyclicBarrier start = new CyclicBarrier(2);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Callable<Void> sweep = () -> { start.await(10, TimeUnit.SECONDS); expire(); return null; };
            Future<Void> first = pool.submit(sweep), second = pool.submit(sweep);
            first.get(20, TimeUnit.SECONDS);
            second.get(20, TimeUnit.SECONDS);
        } finally { pool.shutdownNow(); }
        expire();
        assertEquals("EXPIRED", tenantState());
        assertEquals(1, auditCount());
        assertEquals(1, jdbc.queryForObject("select count(*) from pg_namespace where nspname=?", Integer.class, tenant.getSchemaName()));
        assertEquals(1, jdbc.queryForObject("select count(*) from tenant_default.demo_requests where id=?", Integer.class, requestId));
        assertEquals(1, jdbc.queryForObject("select count(*) from tenant_default.demo_invites where id=?", Integer.class, inviteId));
    }

    @Test void failedExpiryAuditRollsBackTransitionAndRetrySucceeds() {
        makeDue();
        doThrow(new IllegalStateException("injected expiry audit failure")).when(audit)
                .record(eq("demo.tenant.expired"), anyString(), anyString(), isNull());
        // Exercise the service's own transaction, with no test transaction that
        // could conceal a missing production boundary.
        assertThrows(IllegalStateException.class, () -> TenantContext.runAsPreAuthentication(
                () -> expiry.processExpiredTenant(tenant.getId(), Instant.now())));
        assertEquals("ACTIVE", tenantState());
        assertNull(jdbc.queryForObject("select expired_at from platform.tenants where id=?", Timestamp.class, tenant.getId()));
        assertEquals(0, auditCount());
        doCallRealMethod().when(audit).record(eq("demo.tenant.expired"), anyString(), anyString(), isNull());
        expire();
        assertEquals("EXPIRED", tenantState());
        assertEquals(1, auditCount());
    }

    @Test void extensionCommittedAfterCandidateSelectionRemainsActive() {
        makeDue();
        Instant candidateScanTime = Instant.now();
        jdbc.update("update platform.tenants set demo_expires_at=now()+interval '7 days' where id=?", tenant.getId());
        restricted(() -> expiry.processExpiredTenant(tenant.getId(), candidateScanTime));
        assertEquals("ACTIVE", tenantState());
        assertEquals(0, auditCount());
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void neverAttemptedDeliveryIsCancelledAtExpiryEvenBeforeSweep(boolean swept) {
        seedDelivery();
        makeDue();
        if (swept) expire();
        outbox.poll();
        assertEquals("CANCELLED", deliveryState());
        assertEquals("", payload());
        verify(provider, never()).send(any());
        assertEquals("QUEUED", requestState());
    }

    @ParameterizedTest @ValueSource(strings = {"PENDING", "PROCESSING", "UNKNOWN"})
    void expiryRetainsUncertainAcceptanceForReconciliation(String state) {
        seedDelivery();
        jdbc.update("""
                update platform.invitation_email_outbox set status=?,first_attempt_at=now()-interval '1 hour',
                    claim_token=?,lease_expires_at=now()-interval '1 minute',attempt_count=1 where id=?
                """, state, UUID.randomUUID(), deliveryId);
        String encrypted = payload();
        makeDue();
        expire();
        outbox.poll();
        assertEquals("UNKNOWN", deliveryState());
        assertEquals(encrypted, payload());
        verify(provider, never()).send(any());
        outbox.reconcile(tenant.getId(), deliveryId, "ACCEPTED", "provider-lookup", "operator", "Offline lookup confirmed acceptance");
        assertEquals("ACCEPTED", deliveryState());
        assertEquals("", payload());
        assertEquals("EXPIRED", tenantState());
        assertEquals("provider-lookup", jdbc.queryForObject("select provider_message_id from platform.invitation_email_outbox where id=?", String.class, deliveryId));
    }

    @ParameterizedTest @ValueSource(strings = {"rotated", "accepted", "expired", "rejected"})
    void lateReconciliationCannotOverwriteCurrentDemoRequest(String boundary) {
        seedDelivery();
        jdbc.update("update platform.invitation_email_outbox set status='UNKNOWN',first_attempt_at=now() where id=?", deliveryId);
        switch (boundary) {
            case "rotated" -> jdbc.update("update tenant_default.demo_invites set token_hash=? where id=?", InvitationTokens.hash("replacement-fixture"), inviteId);
            case "accepted" -> {
                jdbc.update("update tenant_default.demo_invites set status='ACCEPTED',accepted_at=now() where id=?", inviteId);
                jdbc.update("update tenant_default.demo_requests set status='ACCEPTED',bootstrap_status='INVITE_ACCEPTED' where id=?", requestId);
            }
            case "expired" -> jdbc.update("update tenant_default.demo_invites set expires_at=now()-interval '1 minute' where id=?", inviteId);
            case "rejected" -> jdbc.update("update tenant_default.demo_requests set status='REJECTED',bootstrap_status='REJECTED' where id=?", requestId);
            default -> throw new AssertionError(boundary);
        }
        String before = requestState();
        String bootstrap = jdbc.queryForObject("select bootstrap_status from tenant_default.demo_requests where id=?", String.class, requestId);
        outbox.reconcile(tenant.getId(), deliveryId, "ACCEPTED", "provider-lookup", "operator", "Offline lookup confirmed old acceptance");
        assertEquals("ACCEPTED", deliveryState());
        assertEquals(before, requestState());
        assertEquals(bootstrap, jdbc.queryForObject("select bootstrap_status from tenant_default.demo_requests where id=?", String.class, requestId));
        verify(provider, never()).send(any());
    }

    @Test void activeDemoDeliveryStillPublishesProviderAcceptance() {
        seedDelivery();
        outbox.poll();
        assertEquals("ACCEPTED", deliveryState());
        assertEquals("SENT", requestState());
        assertEquals("INVITE_SENT", jdbc.queryForObject("select bootstrap_status from tenant_default.demo_requests where id=?", String.class, requestId));
        verify(provider).send(any());
    }

    @Test void rotationDuringProviderCallPreservesOldAcceptanceWithoutPublishingItsToken() {
        seedDelivery();
        UUID oldDelivery = deliveryId;
        String replacement = InvitationTokens.hash("offline-replacement-" + inviteId);
        when(provider.send(any())).thenAnswer(call -> {
            runtimeTransactions.executeWithoutResult(status -> {
                runtime.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,tenant.getId().toString());
                runtime.queryForList("select id from tenant_default.demo_requests where id=? for update",UUID.class,requestId);
                runtime.queryForList("select id from tenant_default.demo_invites where id=? for update",UUID.class,inviteId);
                runtime.update("update tenant_default.demo_invites set token_hash=? where id=?", replacement, inviteId);
                outbox.enqueue(tenant.getId(), "DEMO_INVITE", inviteId, replacement,
                        new ResendEmailClient.EmailMessage("offline@example.test", "Replacement", "<p>Replacement</p>", "Replacement", Map.of(), null));
            });
            background.stopAcceptingWork();
            return ResendEmailClient.DeliveryResult.sent("old-provider-acceptance");
        });
        outbox.poll();
        assertEquals("ACCEPTED", jdbc.queryForObject("select status from platform.invitation_email_outbox where id=?",String.class,oldDelivery));
        assertEquals("old-provider-acceptance", jdbc.queryForObject("select provider_message_id from platform.invitation_email_outbox where id=?",String.class,oldDelivery));
        assertEquals(1,jdbc.queryForObject("select count(*) from platform.invitation_email_outbox where related_id=? and status='PENDING'",Integer.class,inviteId));
        assertEquals("QUEUED", requestState());
        assertEquals(replacement,jdbc.queryForObject("select token_hash from tenant_default.demo_invites where id=?",String.class,inviteId));
    }

    @Test void supersededUncertainAttemptIsRetainedAndReconciliationWaitsForActiveLease() {
        seedDelivery();
        jdbc.update("update platform.invitation_email_outbox set status='PROCESSING',first_attempt_at=now(),claim_token=?,lease_expires_at=now()+interval '1 minute' where id=?",UUID.randomUUID(),deliveryId);
        String encrypted = payload();
        String replacement = InvitationTokens.hash("offline-rotation-" + inviteId);
        outbox.enqueue(tenant.getId(),"DEMO_INVITE",inviteId,replacement,
                new ResendEmailClient.EmailMessage("offline@example.test","Replacement","<p>Replacement</p>","Replacement",Map.of(),null));
        assertEquals("UNKNOWN",deliveryState());
        assertEquals(encrypted,payload());
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> outbox.reconcile(
                tenant.getId(),deliveryId,"ACCEPTED","provider-lookup","operator","Offline lookup"));
        jdbc.update("update platform.invitation_email_outbox set lease_expires_at=now()-interval '1 second' where id=?",deliveryId);
        outbox.reconcile(tenant.getId(),deliveryId,"ACCEPTED","provider-lookup","operator","Offline lookup");
        assertEquals("ACCEPTED",deliveryState());
        verify(provider,never()).send(any());
    }

    private void seedDelivery() {
        requestId = UUID.randomUUID(); inviteId = UUID.randomUUID();
        String hash = InvitationTokens.hash("offline-demo-fixture-" + inviteId);
        jdbc.update("insert into tenant_default.demo_requests(id,tenant_id,company,email,full_name,status,requested_at,bootstrap_status) values (?,?,'Offline fixture',?,'Test user','QUEUED',now(),'CREATED')",
                requestId, tenant.getId(), requestId + "@example.test");
        jdbc.update("insert into tenant_default.demo_invites(id,tenant_id,request_id,email,status,created_at,expires_at,token_hash) values (?,?,?,?,'QUEUED',now(),now()+interval '7 days',?)",
                inviteId, tenant.getId(), requestId, requestId + "@example.test", hash);
        outbox.enqueue(tenant.getId(), "DEMO_INVITE", inviteId, hash,
                new ResendEmailClient.EmailMessage("offline@example.test", "Test invite", "<p>Offline fixture</p>", "Offline fixture", Map.of(), null));
        deliveryId = jdbc.queryForObject("select id from platform.invitation_email_outbox where related_id=?", UUID.class, inviteId);
    }

    private void makeDue() {
        jdbc.update("update platform.tenants set demo_expires_at=now()-interval '1 day' where id=?", tenant.getId());
    }
    private void expire() { restricted(() -> expiry.processExpiredTenant(tenant.getId(), Instant.now())); }
    private void restricted(Runnable work) {
        TenantContext.runAsPreAuthentication(() -> new TransactionTemplate(manager).executeWithoutResult(status -> {
            jdbc.execute("set local role " + role);
            jdbc.execute("set local row_security=on");
            assertEquals(role, jdbc.queryForObject("select current_user", String.class));
            work.run();
        }));
    }
    private String tenantState() { return jdbc.queryForObject("select status from platform.tenants where id=?", String.class, tenant.getId()); }
    private String requestState() { return jdbc.queryForObject("select status from tenant_default.demo_requests where id=?", String.class, requestId); }
    private String deliveryState() { return jdbc.queryForObject("select status from platform.invitation_email_outbox where id=?", String.class, deliveryId); }
    private String payload() { return jdbc.queryForObject("select encrypted_payload from platform.invitation_email_outbox where id=?", String.class, deliveryId); }
    private int auditCount() { return jdbc.queryForObject("select count(*) from tenant_default.audit_events where action='demo.tenant.expired' and target_id=?", Integer.class, tenant.getId().toString()); }
}
