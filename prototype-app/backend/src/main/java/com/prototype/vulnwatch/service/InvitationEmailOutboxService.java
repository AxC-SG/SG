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
public class InvitationEmailOutboxService {
    private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(InvitationEmailOutboxService.class);
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper mapper;
    private final CredentialEncryptionService encryption;
    private final ResendEmailClient provider;
    private final BackgroundTaskExecutionPolicy background;
    private final String sharedSchema;

    public InvitationEmailOutboxService(JdbcTemplate jdbc,PlatformTransactionManager manager,ObjectMapper mapper,CredentialEncryptionService encryption,
            ResendEmailClient provider,BackgroundTaskExecutionPolicy background,
            @org.springframework.beans.factory.annotation.Value("${app.tenancy.default-schema:tenant_default}") String sharedSchema) {
        this.sharedSchema=new TenantSchemaService(jdbc,sharedSchema).normalizeSchemaName(sharedSchema);
        this.jdbc=jdbc;this.mapper=mapper;this.encryption=encryption;this.provider=provider;this.background=background;
        transactions=new TransactionTemplate(manager);
        transactions.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }
    @org.springframework.transaction.annotation.Transactional
    public ResendEmailClient.DeliveryResult enqueue(UUID tenantId,String type,UUID relatedId,String tokenHash,ResendEmailClient.EmailMessage message) {
        UUID deliveryId=UUID.randomUUID();
        jdbc.update("update platform.invitation_email_outbox set status='CANCELLED',encrypted_payload='' where delivery_type=? and related_id=? and token_hash<>? and status in ('PENDING','PROCESSING')",type,relatedId,tokenHash);
        jdbc.update("""
                insert into platform.invitation_email_outbox(id,tenant_id,delivery_type,related_id,token_hash,encrypted_payload)
                values (?,?,?,?,?,?) on conflict(delivery_type,related_id,token_hash) do nothing
                """,deliveryId,tenantId,type,relatedId,tokenHash,encrypted(message,deliveryId));
        return new ResendEmailClient.DeliveryResult(ResendEmailClient.DeliveryState.QUEUED,null,"Email queued for provider submission");
    }

    private String encrypted(ResendEmailClient.EmailMessage message,UUID id) {
        try { return encryption.encrypt(mapper.writeValueAsString(provider.freeze(message,"scout-invitation-"+id))); }
        catch (java.io.IOException failure) { throw new IllegalStateException("Email intent could not be encoded"); }
    }

    @Scheduled(fixedDelayString="${app.email.invitation-poll-ms:5000}")
    public void poll() {
        if (!background.allowsBackgroundTask("InvitationEmailOutboxService.poll")) return;
        if (!provider.isConfigured()) return;
        TenantContext.runAsPlatform(() -> processBatch());
    }

    private void processBatch() {
        for (int i=0;i<10 && background.allowsBackgroundTask("InvitationEmailOutboxService.claim");i++) {
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
                select id,related_id,encrypted_payload,first_attempt_at,attempt_count,tenant_id
                  from platform.invitation_email_outbox where (status='PENDING' and visible_at<=clock_timestamp())
                    or (status='PROCESSING' and lease_expires_at<=clock_timestamp())
                  order by visible_at,id for update skip locked limit 1
                """, (org.springframework.jdbc.core.ResultSetExtractor<Claim>) rs -> {
            if (!rs.next()) return null;
            UUID id=rs.getObject(1,UUID.class),related=rs.getObject(2,UUID.class),token=UUID.randomUUID();
            String payload=rs.getString(3);
            Instant first=rs.getTimestamp(4)==null ? Instant.now() : rs.getTimestamp(4).toInstant();
            int count=rs.getInt(5)+1;
            UUID tenantId=rs.getObject(6,UUID.class);
            jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,tenantId.toString());
            String lifecycle=jdbc.queryForObject("select status from platform.tenants where id=?",String.class,tenantId);
            if (!"ACTIVE".equals(lifecycle)) {
                if (java.util.Set.of("DELETED","PURGED","EXPIRED").contains(lifecycle)) jdbc.update("update platform.invitation_email_outbox set status='CANCELLED',encrypted_payload='' where id=?",id);
                else jdbc.update("update platform.invitation_email_outbox set visible_at=now()+interval '1 minute' where id=?",id);
                return null;
            }
                String type=jdbc.queryForObject("select delivery_type from platform.invitation_email_outbox where id=?",String.class,id);
                String source="TENANT_INVITE".equals(type) ? "platform.tenant_user_invites" : sharedSchema+".demo_invites";
                Boolean valid=jdbc.queryForObject("select exists(select 1 from "+source+" where id=? and token_hash=(select token_hash from platform.invitation_email_outbox where id=?) and expires_at>clock_timestamp() and accepted_at is null and status not in ('CANCELLED','EXPIRED','ACCEPTED'))",Boolean.class,related,id);
                if (!Boolean.TRUE.equals(valid)) { jdbc.update("update platform.invitation_email_outbox set status='CANCELLED',encrypted_payload='' where id=?",id);return null; }
            jdbc.update("update platform.invitation_email_outbox set status='PROCESSING',claim_token=?,lease_expires_at=clock_timestamp()+interval '60 seconds',first_attempt_at=coalesce(first_attempt_at,clock_timestamp()),last_attempt_at=clock_timestamp(),attempt_count=attempt_count+1 where id=?",token,id);
            return new Claim(id,related,token,payload,first,count);
        });
    }

    private void finish(Claim claim,ResendEmailClient.DeliveryResult result) {
        String state=EmailDeliveryRetryPolicy.outcome(result,claim.attempts());
        transactions.executeWithoutResult(status -> {
            int changed=jdbc.update("""
                    update platform.invitation_email_outbox set status=?,provider_message_id=?,last_error_code=?,claim_token=null,lease_expires_at=null,
                        visible_at=clock_timestamp()+make_interval(secs=>?),
                        encrypted_payload=case when ? in ('ACCEPTED','FAILED','CANCELLED') then '' else encrypted_payload end
                     where id=? and status='PROCESSING' and claim_token=? and lease_expires_at>clock_timestamp()
                    """,state,result.providerMessageId(),result.detail(),Math.min(3600,30*(1<<Math.min(7,claim.attempts()))),state,claim.id(),claim.token());
            if (changed==1) publish(claim,state,result);
        });
    }
    private void publish(Claim claim,String state,ResendEmailClient.DeliveryResult result) {

                String tenantId=jdbc.queryForObject("select tenant_id::text from platform.invitation_email_outbox where id=?",String.class,claim.id());
                jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,tenantId);
                String type=jdbc.queryForObject("select delivery_type from platform.invitation_email_outbox where id=?",String.class,claim.id());
                String source="TENANT_INVITE".equals(type) ? "platform.tenant_user_invites" : sharedSchema+".demo_invites";
                String inviteStatus=switch(state) { case "ACCEPTED" -> "SENT";case "PENDING" -> "QUEUED";case "UNKNOWN" -> "DELIVERY_UNKNOWN";default -> "DELIVERY_ERROR"; };
                jdbc.update("update "+source+" set status=?,last_sent_at=case when ?='ACCEPTED' then now() else last_sent_at end where id=? and token_hash=(select token_hash from platform.invitation_email_outbox where id=?) and accepted_at is null and status not in ('ACCEPTED','CANCELLED','EXPIRED')",inviteStatus,state,claim.related(),claim.id());
                if ("TENANT_INVITE".equals(type)) jdbc.update("update platform.tenant_user_invites set provider_message_id=?,delivery_detail=? where id=? and token_hash=(select token_hash from platform.invitation_email_outbox where id=?) and accepted_at is null and status not in ('ACCEPTED','CANCELLED','EXPIRED')",result.providerMessageId(),result.detail(),claim.related(),claim.id());
                if ("DEMO_INVITE".equals(type)) jdbc.update("update "+sharedSchema+".demo_requests set status=?,bootstrap_status=? where id=(select request_id from "+sharedSchema+".demo_invites where id=?)",inviteStatus,"ACCEPTED".equals(state) ? "INVITE_SENT" : "INVITE_"+inviteStatus,claim.related());
    }

    public java.util.List<java.util.Map<String,Object>> status(UUID tenantId) {
        return jdbc.queryForList("select id,status,attempt_count,created_at,first_attempt_at,last_attempt_at,provider_message_id,last_error_code,reconciled_at,reconciled_by from platform.invitation_email_outbox where tenant_id=? order by created_at desc,id desc limit 100",tenantId);
    }

    public void reconcile(UUID tenantId,UUID deliveryId,String outcome,String providerId,String actor,String note) {
        if (outcome==null || !java.util.Set.of("ACCEPTED","FAILED").contains(outcome) || note==null || note.isBlank() || note.length()>500
                || actor==null || actor.isBlank() || actor.length()>255 || (providerId!=null && providerId.length()>255) || ("ACCEPTED".equals(outcome) && (providerId==null || providerId.isBlank() || providerId.length()>255)))
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Reconciliation requires an accepted/failed outcome, provider ID for acceptance, and an operator note");
        transactions.executeWithoutResult(status -> {
            var related=jdbc.query("select related_id from platform.invitation_email_outbox where id=? and tenant_id=? and status='UNKNOWN' for update",(rs,row) -> rs.getObject(1,UUID.class),deliveryId,tenantId);
            if (related.isEmpty()) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,"Delivery is not awaiting reconciliation");
            jdbc.update("update platform.invitation_email_outbox set status=?,provider_message_id=?,last_error_code='OPERATOR_RECONCILED',encrypted_payload='',reconciled_at=now(),reconciled_by=?,reconciliation_note=? where id=? and tenant_id=? and status='UNKNOWN'",outcome,providerId,actor,note,deliveryId,tenantId);
            publish(new Claim(deliveryId,related.get(0),null,null,null,0),outcome,new ResendEmailClient.DeliveryResult("ACCEPTED".equals(outcome) ? ResendEmailClient.DeliveryState.SENT : ResendEmailClient.DeliveryState.FAILED,providerId,"OPERATOR_RECONCILED"));
        });
    }

    private record Claim(UUID id,UUID related,UUID token,String payload,Instant first,int attempts) { }
}
