package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ResendEmailClient;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class CampaignEmailOutboxService {
    private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(CampaignEmailOutboxService.class);
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper mapper;
    private final CredentialEncryptionService encryption;
    private final ResendEmailClient provider;
    private final BackgroundTaskExecutionPolicy background;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;

    public CampaignEmailOutboxService(JdbcTemplate jdbc,PlatformTransactionManager manager,ObjectMapper mapper,CredentialEncryptionService encryption,
            ResendEmailClient provider,BackgroundTaskExecutionPolicy background,TenantService tenants,TenantSchemaExecutionService tenantExecution) {
        this.jdbc=jdbc;this.mapper=mapper;this.encryption=encryption;this.provider=provider;this.background=background;
        transactions=new TransactionTemplate(manager);
        transactions.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.tenants=tenants;this.tenantExecution=tenantExecution;
    }
    @org.springframework.transaction.annotation.Transactional
    public void enqueue(UUID tenantId,UUID attemptId,ResendEmailClient.EmailMessage message) {
        if (!tenantId.equals(TenantContext.getCurrentTenantId())) throw new IllegalStateException("Campaign email tenant context mismatch");
        jdbc.update("insert into campaign_email_outbox(id,tenant_id,delivery_attempt_id,encrypted_payload) values (?,?,?,?) on conflict(delivery_attempt_id) do nothing",
                attemptId,tenantId,attemptId,encrypted(message,attemptId));
    }

    private String encrypted(ResendEmailClient.EmailMessage message,UUID id) {
        try { return encryption.encrypt(mapper.writeValueAsString(provider.freeze(message,"scout-campaign-"+id))); }
        catch (java.io.IOException failure) { throw new IllegalStateException("Email intent could not be encoded"); }
    }

    @Scheduled(fixedDelayString="${app.email.campaign-poll-ms:5000}")
    public void poll() {
        if (!background.allowsBackgroundTask("CampaignEmailOutboxService.poll")) return;
        if (!provider.isConfigured()) return;
        for (var tenant:tenants.listActiveTenants()) {
            if (!background.allowsBackgroundTask("campaign-email.claim")) return;
            try { tenantExecution.run(tenant, () -> processBatch()); }
            catch (RuntimeException failure) { LOG.warn("Campaign email poll failed for tenant {}",tenant.getId()); }
        }
    }

    private void processBatch() {
        for (int i=0;i<10 && background.allowsBackgroundTask("CampaignEmailOutboxService.claim");i++) {
            Claim claim=transactions.execute(status -> claim());
            if (claim==null) return;
            ResendEmailClient.DeliveryResult result;
            if (EmailDeliveryRetryPolicy.replayWindowExpired(claim.first(),Instant.now())) {
                result=new ResendEmailClient.DeliveryResult(ResendEmailClient.DeliveryState.UNKNOWN,null,"RECONCILIATION_REQUIRED");
            } else {
                try { result=provider.send(mapper.readValue(encryption.decrypt(claim.payload()),ResendEmailClient.EmailMessage.class)); }
                catch (RuntimeException | java.io.IOException failure) { result=ResendEmailClient.DeliveryResult.failed("PAYLOAD_UNAVAILABLE"); }
            }
            finish(claim,result);
        }
    }

    private Claim claim() {
        return jdbc.query("""
                select id,delivery_attempt_id,encrypted_payload,first_attempt_at,attempt_count
                  from campaign_email_outbox where (status='PENDING' and visible_at<=clock_timestamp())
                    or (status='PROCESSING' and lease_expires_at<=clock_timestamp())
                  order by visible_at,id for update skip locked limit 1
                """, (org.springframework.jdbc.core.ResultSetExtractor<Claim>) rs -> {
            if (!rs.next()) return null;
            UUID id=rs.getObject(1,UUID.class),related=rs.getObject(2,UUID.class),token=UUID.randomUUID();
            String payload=rs.getString(3);
            Instant first=rs.getTimestamp(4)==null ? Instant.now() : rs.getTimestamp(4).toInstant();
            int count=rs.getInt(5)+1;
            jdbc.update("update campaign_email_outbox set status='PROCESSING',claim_token=?,lease_expires_at=clock_timestamp()+interval '60 seconds',first_attempt_at=coalesce(first_attempt_at,clock_timestamp()),last_attempt_at=clock_timestamp(),attempt_count=attempt_count+1 where id=?",token,id);
            return new Claim(id,related,token,payload,first,count);
        });
    }

    private void finish(Claim claim,ResendEmailClient.DeliveryResult result) {
        String state=EmailDeliveryRetryPolicy.outcome(result,claim.attempts());
        transactions.executeWithoutResult(status -> {
            int changed=jdbc.update("""
                    update campaign_email_outbox set status=?,provider_message_id=?,last_error_code=?,claim_token=null,lease_expires_at=null,
                        visible_at=clock_timestamp()+make_interval(secs=>?),
                        encrypted_payload=case when ? in ('ACCEPTED','FAILED','CANCELLED') then '' else encrypted_payload end
                     where id=? and status='PROCESSING' and claim_token=? and lease_expires_at>clock_timestamp()
                    """,state,result.providerMessageId(),result.detail(),Math.min(3600,30*(1<<Math.min(7,claim.attempts()))),state,claim.id(),claim.token());
            if (changed==1) publish(claim,state,result);
        });
    }
    private void publish(Claim claim,String state,ResendEmailClient.DeliveryResult result) {

                jdbc.update("update campaign_delivery_attempts set delivery_state=?,provider_message_id=?,detail=? where id=?",state,result.providerMessageId(),result.detail(),claim.related());
    }

    public java.util.List<java.util.Map<String,Object>> status(UUID tenantId) {
        return jdbc.queryForList("select id,status,attempt_count,created_at,first_attempt_at,last_attempt_at,provider_message_id,last_error_code,reconciled_at,reconciled_by from campaign_email_outbox where tenant_id=? order by created_at desc,id desc limit 100",tenantId);
    }

    public void reconcile(UUID tenantId,UUID deliveryId,String outcome,String providerId,String actor,String note) {
        if (outcome==null || !java.util.Set.of("ACCEPTED","FAILED").contains(outcome) || note==null || note.isBlank() || note.length()>500
                || actor==null || actor.isBlank() || actor.length()>255 || (providerId!=null && providerId.length()>255) || ("ACCEPTED".equals(outcome) && (providerId==null || providerId.isBlank() || providerId.length()>255)))
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Reconciliation requires an accepted/failed outcome, provider ID for acceptance, and an operator note");
        transactions.executeWithoutResult(status -> {
            var related=jdbc.query("select delivery_attempt_id from campaign_email_outbox where id=? and tenant_id=? and status='UNKNOWN' for update",(rs,row) -> rs.getObject(1,UUID.class),deliveryId,tenantId);
            if (related.isEmpty()) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,"Delivery is not awaiting reconciliation");
            jdbc.update("update campaign_email_outbox set status=?,provider_message_id=?,last_error_code='OPERATOR_RECONCILED',encrypted_payload='',reconciled_at=now(),reconciled_by=?,reconciliation_note=? where id=? and tenant_id=? and status='UNKNOWN'",outcome,providerId,actor,note,deliveryId,tenantId);
            publish(new Claim(deliveryId,related.get(0),null,null,null,0),outcome,new ResendEmailClient.DeliveryResult("ACCEPTED".equals(outcome) ? ResendEmailClient.DeliveryState.SENT : ResendEmailClient.DeliveryState.FAILED,providerId,"OPERATOR_RECONCILED"));
        });
    }

    private record Claim(UUID id,UUID related,UUID token,String payload,Instant first,int attempts) { }
}
