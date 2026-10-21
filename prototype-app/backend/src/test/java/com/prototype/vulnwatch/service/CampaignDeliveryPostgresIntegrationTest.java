package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.config.TenantAwareDataSource;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.support.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

@PostgresIntegrationTest
class CampaignDeliveryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB = LocalPostgresTestDatabase.provision("phase3_campaign_delivery");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) { PostgresITSupport.registerDatabaseProperties(registry,DB); }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired CredentialEncryptionService encryption;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate owner;
    Tenant tenant;
    String role;
    JdbcTemplate jdbc;
    TransactionTemplate tx;
    ResendEmailClient provider;
    CampaignEmailOutboxService outbox;

    @BeforeEach void setup() {
        TenantContext.clear();
        String slug="campaign-delivery-"+UUID.randomUUID().toString().substring(0,8);
        tenant=tenants.createTenant(slug,slug,"ENTERPRISE",null);
        migrations.provisionNewTenant(tenant);tenant=tenants.resolveTenantUuid(tenant.getId());
        role="campaign_"+UUID.randomUUID().toString().replace("-","");
        String password=UUID.randomUUID().toString();
        owner.execute("create role "+role+" login nosuperuser nobypassrls noinherit password '"+password+"'");
        owner.execute("grant usage on schema platform,\""+tenant.getSchemaName()+"\" to "+role);
        owner.execute("grant select on platform.tenants to "+role);
        owner.execute("grant select,insert,update,delete on all tables in schema \""+tenant.getSchemaName()+"\" to "+role);
        var source=new TenantAwareDataSource(new DriverManagerDataSource(DB.url(),role,password),true,"tenant_default",new SimpleMeterRegistry());
        jdbc=new JdbcTemplate(source);tx=new TransactionTemplate(new DataSourceTransactionManager(source));
        provider=mock(ResendEmailClient.class);
        when(provider.isConfigured()).thenReturn(true);
        when(provider.freeze(any(),any())).thenAnswer(call -> {
            ResendEmailClient.EmailMessage message=call.getArgument(0);
            return new ResendEmailClient.EmailMessage(message.to(),message.subject(),message.html(),message.text(),message.tags(),call.getArgument(1),"sender@example.test");
        });
        outbox=new CampaignEmailOutboxService(jdbc,tx.getTransactionManager(),mapper,encryption,provider,
                BackgroundTaskExecutionPolicy.allowAll(),tenants,scoped);
        scoped.run(tenant, () -> {
            assertEquals(role,jdbc.queryForObject("select current_user",String.class));
            assertFalse(jdbc.queryForObject("select rolsuper or rolbypassrls from pg_roles where rolname=current_user",Boolean.class));
        });
    }
    @AfterEach void cleanup() { TenantContext.clear();if(role!=null){owner.execute("drop owned by "+role);owner.execute("drop role "+role);} }

    @Test void rollbackRemovesCampaignAttemptAndIntentWithoutProviderContact() {
        assertThrows(IllegalStateException.class, () -> scoped.run(tenant, () -> tx.execute(status -> {
            enqueueEvent();throw new IllegalStateException("rollback campaign event");
        })));
        scoped.run(tenant, () -> {
            assertEquals(0,count("campaign_delivery_attempts"));assertEquals(0,count("campaign_email_outbox"));assertEquals(0,count("campaigns"));
        });
        verify(provider,never()).send(any());
    }

    @Test void distinctEventsUseDifferentKeysAndEachRetryPreservesItsImmutableMessage() {
        scoped.run(tenant, () -> tx.executeWithoutResult(status -> {enqueueEvent();enqueueEvent();}));
        when(provider.send(any())).thenReturn(new ResendEmailClient.DeliveryResult(ResendEmailClient.DeliveryState.RETRYABLE,null,"PROVIDER_OUTCOME_UNKNOWN"));
        outbox.poll();
        scoped.run(tenant, () -> {
            assertEquals(2,count("campaign_email_outbox"));
            jdbc.update("update campaign_email_outbox set visible_at=now()-interval '1 minute'");
        });
        when(provider.send(any())).thenReturn(ResendEmailClient.DeliveryResult.sent("offline-provider"));
        outbox.poll();
        var sent=org.mockito.ArgumentCaptor.forClass(ResendEmailClient.EmailMessage.class);
        verify(provider,times(4)).send(sent.capture());
        Map<String,List<ResendEmailClient.EmailMessage>> byKey=new HashMap<>();
        for(var message:sent.getAllValues())byKey.computeIfAbsent(message.idempotencyKey(),ignored -> new ArrayList<>()).add(message);
        assertEquals(2,byKey.size());
        byKey.values().forEach(messages -> {assertEquals(2,messages.size());assertEquals(messages.get(0),messages.get(1));});
        scoped.run(tenant, () -> {
            assertEquals(2,jdbc.queryForObject("select count(*) from campaign_email_outbox where status='ACCEPTED' and encrypted_payload=''",Integer.class));
            assertEquals(2,jdbc.queryForObject("select count(*) from campaign_delivery_attempts where delivery_state='ACCEPTED'",Integer.class));
        });
    }

    @Test void unknownAcceptanceStopsProviderReplayAndRequiresScopedOperatorReconciliation() {
        UUID attempt=scoped.run(tenant, () -> tx.execute(status -> enqueueEvent()));
        scoped.run(tenant, () -> jdbc.update("update campaign_email_outbox set first_attempt_at=now()-interval '23 hours'"));
        outbox.poll();
        scoped.run(tenant, () -> {
            assertEquals("UNKNOWN",jdbc.queryForObject("select status from campaign_email_outbox where id=?",String.class,attempt));
            assertFalse(jdbc.queryForObject("select encrypted_payload from campaign_email_outbox where id=?",String.class,attempt).isEmpty());
            assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> outbox.reconcile(UUID.randomUUID(),attempt,"ACCEPTED","provider-lookup","operator","Offline lookup"));
            outbox.reconcile(tenant.getId(),attempt,"ACCEPTED","provider-lookup","operator","Offline lookup");
            assertEquals("operator",jdbc.queryForObject("select reconciled_by from campaign_email_outbox where id=?",String.class,attempt));
            assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> outbox.reconcile(tenant.getId(),attempt,"FAILED",null,"operator","Duplicate decision"));
        });
        verify(provider,never()).send(any());
    }

    @Test void wrongTenantCannotEnqueueCampaignDelivery() {
        assertThrows(IllegalStateException.class, () -> scoped.run(tenant, () -> outbox.enqueue(UUID.randomUUID(),UUID.randomUUID(),message())));
        scoped.run(tenant, () -> assertEquals(0,count("campaign_email_outbox")));
    }

    private UUID enqueueEvent() {
        UUID campaign=UUID.randomUUID(),attempt=UUID.randomUUID();
        jdbc.update("insert into campaigns(id,tenant_id,name,status,created_by,created_at,updated_at) values (?,?,'Offline campaign','ACTIVE','test',now(),now())",campaign,tenant.getId());
        jdbc.update("insert into campaign_delivery_attempts(id,tenant_id,campaign_id,target_type,target_label,target_address,subject,delivery_state,created_at) values (?,?,?,'GROUP','Test group','offline@example.test','Repeated event type','QUEUED',now())",attempt,tenant.getId(),campaign);
        outbox.enqueue(tenant.getId(),attempt,message());outbox.enqueue(tenant.getId(),attempt,message());
        return attempt;
    }
    private ResendEmailClient.EmailMessage message(){return new ResendEmailClient.EmailMessage("offline@example.test","Repeated event type","<p>Offline event</p>","Offline event",Map.of(),null);}
    private int count(String table){return jdbc.queryForObject("select count(*) from "+table,Integer.class);}
}
