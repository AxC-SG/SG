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
        boolean platformSetup = "PLATFORM_OWNER_SETUP".equals(type);
        if (platformSetup != (tenantId == null)
                || !java.util.Set.of("PLATFORM_OWNER_SETUP", "INTERNAL_ADMIN_SETUP", "TENANT_INVITE", "DEMO_INVITE").contains(type)) {
            throw new IllegalArgumentException("Invalid invitation delivery scope");
        }
        UUID deliveryId=UUID.randomUUID();
        jdbc.update("""
                update platform.invitation_email_outbox
                   set status=case when first_attempt_at is null then 'CANCELLED' else 'UNKNOWN' end,
                       encrypted_payload=case when first_attempt_at is null then '' else encrypted_payload end,
                       last_error_code='TOKEN_SUPERSEDED'
                 where delivery_type=? and related_id=? and token_hash<>? and status in ('PENDING','PROCESSING')
                """,type,relatedId,tokenHash);
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
            String type=jdbc.queryForObject("select delivery_type from platform.invitation_email_outbox where id=?",String.class,id);
            if (tenantId != null) {
                jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,tenantId.toString());
                var tenant=jdbc.queryForMap("select status, expired_at, demo_expires_at from platform.tenants where id=?",tenantId);
                String lifecycle=(String) tenant.get("status");
                java.sql.Timestamp demoExpiry=(java.sql.Timestamp) tenant.get("demo_expires_at");
                boolean expired=tenant.get("expired_at")!=null || (demoExpiry!=null && !demoExpiry.toInstant().isAfter(Instant.now()));
                if (!"ACTIVE".equals(lifecycle) || expired) {
                    if (expired || java.util.Set.of("DELETED","PURGED","EXPIRED").contains(lifecycle)) retire(id,rs.getTimestamp(4)!=null,"TENANT_UNAVAILABLE");
                    else jdbc.update("update platform.invitation_email_outbox set visible_at=now()+interval '1 minute' where id=?",id);
                    return null;
                }
            } else if (!"PLATFORM_OWNER_SETUP".equals(type)) {
                retire(id,rs.getTimestamp(4)!=null,"INVALID_SCOPE"); return null;
            }
            Boolean valid;
            if (isSetup(type)) {
                valid=jdbc.queryForObject("select exists(select 1 from platform.app_users where id=? and status='ACTIVE' and password_setup_token_hash=(select token_hash from platform.invitation_email_outbox where id=?) and password_setup_token_expires_at>clock_timestamp())",Boolean.class,related,id);
            } else {
                String source="TENANT_INVITE".equals(type) ? "platform.tenant_user_invites" : sharedSchema+".demo_invites";
                valid=jdbc.queryForObject("select exists(select 1 from "+source+" where id=? and token_hash=(select token_hash from platform.invitation_email_outbox where id=?) and expires_at>clock_timestamp() and accepted_at is null and status not in ('CANCELLED','EXPIRED','ACCEPTED'))",Boolean.class,related,id);
            }
            if (!Boolean.TRUE.equals(valid)) { retire(id,rs.getTimestamp(4)!=null,"INVITATION_UNAVAILABLE");return null; }
            jdbc.update("update platform.invitation_email_outbox set status='PROCESSING',claim_token=?,lease_expires_at=clock_timestamp()+interval '60 seconds',first_attempt_at=coalesce(first_attempt_at,clock_timestamp()),last_attempt_at=clock_timestamp(),attempt_count=attempt_count+1 where id=?",token,id);
            return new Claim(id,related,token,payload,first,count);
        });
    }

    private void retire(UUID id,boolean attempted,String reason) {
        // Once an attempt may have reached the provider, cancellation cannot
        // establish non-acceptance. Keep its payload for operator reconciliation.
        jdbc.update("""
                update platform.invitation_email_outbox
                   set status=?,last_error_code=?,claim_token=null,lease_expires_at=null,
                       encrypted_payload=case when ? then encrypted_payload else '' end
                 where id=?
                """,attempted ? "UNKNOWN" : "CANCELLED",reason,attempted,id);
    }

    private void finish(Claim claim,ResendEmailClient.DeliveryResult result) {
        String state=EmailDeliveryRetryPolicy.outcome(result,claim.attempts());
        transactions.executeWithoutResult(status -> {
            lockPublicationSource(claim.id(),claim.related());
            int changed=jdbc.update("""
                    update platform.invitation_email_outbox set status=?,provider_message_id=?,last_error_code=?,claim_token=null,lease_expires_at=null,
                        visible_at=clock_timestamp()+make_interval(secs=>?),
                        encrypted_payload=case when ? in ('ACCEPTED','FAILED','CANCELLED') then '' else encrypted_payload end
                     where id=? and status in ('PROCESSING','UNKNOWN') and claim_token=? and lease_expires_at>clock_timestamp()
                    """,state,result.providerMessageId(),result.detail(),Math.min(3600,30*(1<<Math.min(7,claim.attempts()))),state,claim.id(),claim.token());
            if (changed==1) publish(claim,state,result);
        });
    }
    private void lockPublicationSource(UUID deliveryId,UUID relatedId) {
        var rows=jdbc.queryForList("select tenant_id,delivery_type from platform.invitation_email_outbox where id=?",deliveryId);
        if (rows.isEmpty()) return;
        var row=rows.get(0);
        jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,row.get("tenant_id")==null ? "" : row.get("tenant_id").toString());
        if (isSetup((String) row.get("delivery_type"))) {
            jdbc.queryForList("select id from platform.app_users where id=? for update",UUID.class,relatedId);
        } else if ("DEMO_INVITE".equals(row.get("delivery_type"))) {
            // Match demo resend/accept: request -> invite -> delivery. Never
            // hold an outbox lock while waiting on one of its source locks.
            var requests=jdbc.queryForList("select request_id from "+sharedSchema+".demo_invites where id=?",UUID.class,relatedId);
            if (!requests.isEmpty() && requests.get(0)!=null)
                jdbc.queryForList("select id from "+sharedSchema+".demo_requests where id=? for update",UUID.class,requests.get(0));
            jdbc.queryForList("select id from "+sharedSchema+".demo_invites where id=? for update",UUID.class,relatedId);
        } else {
            jdbc.queryForList("select id from platform.tenant_user_invites where id=? for update",UUID.class,relatedId);
        }
    }
    private void publish(Claim claim,String state,ResendEmailClient.DeliveryResult result) {

                String tenantId=jdbc.queryForObject("select tenant_id::text from platform.invitation_email_outbox where id=?",String.class,claim.id());
                jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,tenantId==null ? "" : tenantId);
                String type=jdbc.queryForObject("select delivery_type from platform.invitation_email_outbox where id=?",String.class,claim.id());
                if (isSetup(type)) return;
                String source="TENANT_INVITE".equals(type) ? "platform.tenant_user_invites" : sharedSchema+".demo_invites";
                String inviteStatus=switch(state) { case "ACCEPTED" -> "SENT";case "PENDING" -> "QUEUED";case "UNKNOWN" -> "DELIVERY_UNKNOWN";default -> "DELIVERY_ERROR"; };
                int changed=jdbc.update("update "+source+" set status=?,last_sent_at=case when ?='ACCEPTED' then now() else last_sent_at end where id=? and token_hash=(select token_hash from platform.invitation_email_outbox where id=?) and expires_at>clock_timestamp() and accepted_at is null and status not in ('ACCEPTED','CANCELLED','EXPIRED')",inviteStatus,state,claim.related(),claim.id());
                if ("TENANT_INVITE".equals(type)) jdbc.update("update platform.tenant_user_invites set provider_message_id=?,delivery_detail=? where id=? and token_hash=(select token_hash from platform.invitation_email_outbox where id=?) and accepted_at is null and status not in ('ACCEPTED','CANCELLED','EXPIRED')",result.providerMessageId(),result.detail(),claim.related(),claim.id());
                if ("DEMO_INVITE".equals(type) && changed==1) jdbc.update("update "+sharedSchema+".demo_requests set status=?,bootstrap_status=? where id=(select request_id from "+sharedSchema+".demo_invites where id=?) and status in ('QUEUED','SENT','ERROR','DELIVERY_UNKNOWN','DELIVERY_ERROR')",inviteStatus,"ACCEPTED".equals(state) ? "INVITE_SENT" : "INVITE_"+inviteStatus,claim.related());
    }

    public java.util.List<java.util.Map<String,Object>> status(UUID tenantId) {
        return jdbc.queryForList("select id,status,attempt_count,created_at,first_attempt_at,last_attempt_at,provider_message_id,last_error_code,reconciled_at,reconciled_by from platform.invitation_email_outbox where tenant_id is not distinct from ? order by created_at desc,id desc limit 100",tenantId);
    }

    public void reconcile(UUID tenantId,UUID deliveryId,String outcome,String providerId,String actor,String note) {
        if (outcome==null || !java.util.Set.of("ACCEPTED","FAILED").contains(outcome) || note==null || note.isBlank() || note.length()>500
                || actor==null || actor.isBlank() || actor.length()>255 || (providerId!=null && providerId.length()>255) || ("ACCEPTED".equals(outcome) && (providerId==null || providerId.isBlank() || providerId.length()>255)))
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Reconciliation requires an accepted/failed outcome, provider ID for acceptance, and an operator note");
        transactions.executeWithoutResult(status -> {
            var source=jdbc.queryForList("select related_id from platform.invitation_email_outbox where id=? and tenant_id is not distinct from ?",UUID.class,deliveryId,tenantId);
            if (!source.isEmpty()) lockPublicationSource(deliveryId,source.get(0));
            var related=jdbc.query("select related_id from platform.invitation_email_outbox where id=? and tenant_id is not distinct from ? and status='UNKNOWN' and (lease_expires_at is null or lease_expires_at<=clock_timestamp()) for update",(rs,row) -> rs.getObject(1,UUID.class),deliveryId,tenantId);
            if (related.isEmpty()) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,"Delivery is not awaiting reconciliation");
            jdbc.update("update platform.invitation_email_outbox set status=?,provider_message_id=?,last_error_code='OPERATOR_RECONCILED',encrypted_payload='',reconciled_at=now(),reconciled_by=?,reconciliation_note=? where id=? and tenant_id is not distinct from ? and status='UNKNOWN'",outcome,providerId,actor,note,deliveryId,tenantId);
            publish(new Claim(deliveryId,related.get(0),null,null,null,0),outcome,new ResendEmailClient.DeliveryResult("ACCEPTED".equals(outcome) ? ResendEmailClient.DeliveryState.SENT : ResendEmailClient.DeliveryState.FAILED,providerId,"OPERATOR_RECONCILED"));
        });
    }

    private static boolean isSetup(String type) { return "PLATFORM_OWNER_SETUP".equals(type) || "INTERNAL_ADMIN_SETUP".equals(type); }

    private record Claim(UUID id,UUID related,UUID token,String payload,Instant first,int attempts) { }
}
