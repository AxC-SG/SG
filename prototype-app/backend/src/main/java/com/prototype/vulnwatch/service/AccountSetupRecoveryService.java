package com.prototype.vulnwatch.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/** Explicit per-account recovery; ordinary deployments never rotate activation authority. */
@Service
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AccountSetupRecoveryService {
    private final JdbcTemplate jdbc;
    private final InvitationEmailOutboxService outbox;
    private final String baseUrl;
    private final int lifetimeMinutes;
    public AccountSetupRecoveryService(JdbcTemplate jdbc,InvitationEmailOutboxService outbox,
            @Value("${app.demo.app-base-url:http://localhost:5173}") String baseUrl,
            @Value("${app.security.initial-activation-ttl-minutes:30}") int lifetimeMinutes) {
        if(lifetimeMinutes<5 || lifetimeMinutes>1440) throw new IllegalArgumentException("Activation lifetime must be between 5 and 1440 minutes");
        this.jdbc=jdbc;this.outbox=outbox;this.baseUrl=baseUrl;this.lifetimeMinutes=lifetimeMinutes;
    }
    @Transactional(readOnly=true)
    public List<Map<String,Object>> status() {
        return jdbc.queryForList("select o.id,o.related_id,o.tenant_id,o.delivery_type,o.status,o.attempt_count,o.last_error_code,o.created_at,u.password_setup_token_expires_at expires_at from platform.invitation_email_outbox o join platform.app_users u on u.id=o.related_id where delivery_type in ('PLATFORM_OWNER_SETUP','INTERNAL_ADMIN_SETUP') order by o.created_at desc limit 100");
    }
    @Transactional
    public Map<String,Object> reissue(UUID userId,String reason,String actor) {
        if(reason==null || reason.isBlank() || reason.length()>500) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"An explicit recovery reason is required");
        var users=jdbc.queryForList("select * from platform.app_users where id=? and status='ACTIVE' for update",userId);
        if(users.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Setup identity is unavailable");
        var user=users.get(0);
        boolean owner=Boolean.TRUE.equals(user.get("platform_owner")) && Boolean.TRUE.equals(jdbc.queryForObject("select exists(select 1 from platform.app_user_global_roles where app_user_id=? and role='PLATFORM_OWNER')",Boolean.class,userId));
        UUID tenant=null;
        if(!owner) {
            var memberships=jdbc.queryForList("select m.tenant_id from platform.tenant_memberships m join platform.tenants t on t.id=m.tenant_id where m.user_id=? and m.role='TENANT_ADMIN' and m.status='ACTIVE' and t.classification='INTERNAL'",UUID.class,userId);
            if(memberships.size()!=1 || Boolean.TRUE.equals(user.get("platform_owner"))) throw new ResponseStatusException(HttpStatus.CONFLICT,"Use tenant invitation recovery for this identity");
            tenant=memberships.get(0);
        }
        String token=UUID.randomUUID()+"-"+UUID.randomUUID();
        String digest;
        try { digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8))); }
        catch(java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
        Instant expiry=Instant.now().plusSeconds(lifetimeMinutes*60L);
        jdbc.update("update platform.app_users set password_setup_token_hash=?,password_setup_token_expires_at=?,updated_at=now() where id=?",digest,Timestamp.from(expiry),userId);
        outbox.enqueue(tenant,owner ? "PLATFORM_OWNER_SETUP" : "INTERNAL_ADMIN_SETUP",userId,digest,
                AccountSetupEmail.message((String)user.get("email"),baseUrl,token,expiry));
        jdbc.update("insert into platform.intelligence_audit_events(id,action,actor,detail) values(?,'ACCOUNT_SETUP_REISSUED',?,jsonb_build_object('userId',?::text,'reason',?::text))",UUID.randomUUID(),actor,userId.toString(),reason);
        return Map.of("userId",userId,"status","QUEUED","expiresAt",expiry);
    }
    @Transactional
    public void reconcile(UUID delivery,String outcome,String providerId,String note,String actor) {
        var rows=jdbc.queryForList("select tenant_id from platform.invitation_email_outbox where id=? and delivery_type in ('PLATFORM_OWNER_SETUP','INTERNAL_ADMIN_SETUP')",UUID.class,delivery);
        if(rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Setup delivery is unavailable");
        outbox.reconcile(rows.get(0),delivery,outcome,providerId,actor,note);
    }
}
