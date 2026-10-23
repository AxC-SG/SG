package com.prototype.vulnwatch.migration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.service.AccountSetupEmail;
import com.prototype.vulnwatch.service.CredentialEncryptionService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;

/** Writes encrypted delivery intent in the same transaction as setup authority. Never sends email. */
final class PlatformOwnerSetupLinkIssuer {
    private final ResendEmailClient provider;
    private final CredentialEncryptionService encryption;
    private final ObjectMapper mapper = new ObjectMapper();

    PlatformOwnerSetupLinkIssuer(ResendEmailClient provider, CredentialEncryptionService encryption) {
        this.provider = provider;
        this.encryption = encryption;
    }

    DeliverySummary issue(Connection connection, String email, String baseUrl, int ttlMinutes,
                          boolean reissue, UUID runId) throws SQLException {
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            UUID userId;
            try (var statement = connection.prepareStatement("""
                    select u.id from platform.app_users u where lower(email)=? and platform_owner and status='ACTIVE'
                     and exists(select 1 from platform.app_user_global_roles r where r.app_user_id=u.id and r.role='PLATFORM_OWNER') for update
                    """)) {
                statement.setString(1, email.trim().toLowerCase(Locale.ROOT));
                try (var result = statement.executeQuery()) {
                    if (!result.next()) throw new IllegalStateException("Configured platform owner authority does not exist");
                    userId = result.getObject(1, UUID.class);
                    if (result.next()) throw new IllegalStateException("Conflicting owner identities");
                }
            }
            DeliverySummary summary = enqueue(connection, userId, null, "PLATFORM_OWNER_SETUP", email, baseUrl, ttlMinutes, reissue);
            if (autoCommit) connection.commit();
            return summary;
        } catch (SQLException | RuntimeException failure) {
            if (autoCommit) connection.rollback();
            throw failure;
        } finally {
            connection.setAutoCommit(autoCommit);
        }
    }

    DeliverySummary enqueue(Connection connection, UUID userId, UUID tenantId, String type, String email,
                            String baseUrl, int ttlMinutes, boolean reissue) throws SQLException {
        if (connection.getAutoCommit()) throw new IllegalStateException("Setup authority requires a transaction");
        try (var statement = connection.prepareStatement("""
                select password_hash, password_setup_token_hash, password_setup_token_expires_at
                  from platform.app_users where id=? and status='ACTIVE' for update
                """)) {
            statement.setObject(1, userId);
            try (var row = statement.executeQuery()) {
                if (!row.next()) throw new IllegalStateException("Setup identity is unavailable");
                if (!reissue && ((row.getString(1) != null && !row.getString(1).isBlank()) || row.getString(2) != null)) {
                    // Includes expired tokens: expiry needs an explicit recovery operation.
                    Timestamp expiry = row.getTimestamp(3);
                    return new DeliverySummary(expiry == null ? null : expiry.toInstant());
                }
            }
        }
        if (ttlMinutes < 5 || ttlMinutes > 1440) throw new IllegalArgumentException("Invalid setup token lifetime");
        String token = UUID.randomUUID() + "-" + UUID.randomUUID();
        String digest = hash(token);
        Instant expiry = Instant.now().plus(ttlMinutes, ChronoUnit.MINUTES);
        UUID deliveryId = UUID.randomUUID();
        String payload;
        try {
            payload = encryption.encrypt(mapper.writeValueAsString(provider.freeze(
                    AccountSetupEmail.message(email, baseUrl, token, expiry), "sg-invitation-" + deliveryId)));
        } catch (java.io.IOException failure) {
            throw new IllegalStateException("Unable to encode account setup delivery");
        }
        try (var update = connection.prepareStatement("update platform.app_users set password_setup_token_hash=?,password_setup_token_expires_at=?,updated_at=now() where id=?")) {
            update.setString(1, digest); update.setTimestamp(2, Timestamp.from(expiry)); update.setObject(3, userId);
            if (update.executeUpdate() != 1) throw new IllegalStateException("Setup identity changed");
        }
        try (var cancel = connection.prepareStatement("""
                update platform.invitation_email_outbox set status=case when first_attempt_at is null then 'CANCELLED' else 'UNKNOWN' end,
                 encrypted_payload=case when first_attempt_at is null then '' else encrypted_payload end,last_error_code='TOKEN_SUPERSEDED'
                 where delivery_type=? and related_id=? and status in ('PENDING','PROCESSING')
                """)) {
            cancel.setString(1, type); cancel.setObject(2, userId); cancel.executeUpdate();
        }
        try (var insert = connection.prepareStatement("""
                insert into platform.invitation_email_outbox(id,tenant_id,delivery_type,related_id,token_hash,encrypted_payload)
                values(?,?,?,?,?,?)
                """)) {
            insert.setObject(1, deliveryId); insert.setObject(2, tenantId); insert.setString(3, type);
            insert.setObject(4, userId); insert.setString(5, digest); insert.setString(6, payload); insert.executeUpdate();
        }
        return new DeliverySummary(expiry);
    }

    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
    }
    record DeliverySummary(Instant expiresAt) { }
}
