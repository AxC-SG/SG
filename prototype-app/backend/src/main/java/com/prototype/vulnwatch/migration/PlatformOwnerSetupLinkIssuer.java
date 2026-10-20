package com.prototype.vulnwatch.migration;

import com.prototype.vulnwatch.client.ResendEmailClient;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

final class PlatformOwnerSetupLinkIssuer {

    private final ResendEmailClient emailClient;

    PlatformOwnerSetupLinkIssuer(ResendEmailClient emailClient) {
        this.emailClient = emailClient;
    }

    DeliverySummary issue(
            Connection connection,
            String configuredEmail,
            String appBaseUrl,
            int tokenTtlMinutes,
            boolean allowReissue,
            UUID runId
    ) throws SQLException {
        String email = normalizeEmail(configuredEmail);
        String baseUrl = normalizeBaseUrl(appBaseUrl);
        boolean originalAutoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            PlatformOwner owner = loadPlatformOwnerForUpdate(connection, email);
            if (owner.passwordAlreadySet() && !allowReissue) {
                throw new IllegalStateException(
                        "Platform owner already has a password; explicit reissue approval is required");
            }

            String token = UUID.randomUUID() + "-" + UUID.randomUUID();
            String tokenHash = hashToken(token);
            Instant expiresAt = Instant.now().plus(tokenTtlMinutes, ChronoUnit.MINUTES);
            updateSetupToken(connection, owner.userId(), tokenHash, expiresAt);

            String setupUrl = baseUrl + "/setup#token="
                    + URLEncoder.encode(token, StandardCharsets.UTF_8)
                    + "&email=" + URLEncoder.encode(email, StandardCharsets.UTF_8);
            ResendEmailClient.DeliveryResult result = emailClient.send(new ResendEmailClient.EmailMessage(
                    email,
                    "Set up your Scout platform-owner password",
                    htmlMessage(setupUrl, tokenTtlMinutes),
                    textMessage(setupUrl, tokenTtlMinutes),
                    Map.of("message_type", "platform_owner_setup"),
                    "platform-owner-setup-" + runId));
            if (result.state() != ResendEmailClient.DeliveryState.SENT) {
                throw new IllegalStateException("Resend did not accept the platform-owner setup email");
            }
            connection.commit();
            return new DeliverySummary(expiresAt);
        } catch (Exception ex) {
            rollbackQuietly(connection);
            if (ex instanceof SQLException sqlException) {
                throw sqlException;
            }
            throw new IllegalStateException(ex.getMessage(), ex);
        } finally {
            connection.setAutoCommit(originalAutoCommit);
        }
    }

    private PlatformOwner loadPlatformOwnerForUpdate(Connection connection, String email) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                select u.id, nullif(u.password_hash, '') is not null as password_already_set
                from platform.app_users u
                where lower(u.email) = ?
                  and u.platform_owner
                  and u.status = 'ACTIVE'
                  and exists (
                      select 1
                      from platform.app_user_global_roles r
                      where r.app_user_id = u.id
                        and r.role = 'PLATFORM_OWNER'
                  )
                for update
                """)) {
            statement.setString(1, email);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException(
                            "No active platform owner with the required global role matches the configured email");
                }
                PlatformOwner owner = new PlatformOwner(
                        result.getObject("id", UUID.class),
                        result.getBoolean("password_already_set"));
                if (result.next()) {
                    throw new IllegalStateException("Multiple active platform owners match the configured email");
                }
                return owner;
            }
        }
    }

    private void updateSetupToken(
            Connection connection,
            UUID userId,
            String tokenHash,
            Instant expiresAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                update platform.app_users
                set password_setup_token_hash = ?,
                    password_setup_token_expires_at = ?,
                    updated_at = now()
                where id = ?
                """)) {
            statement.setString(1, tokenHash);
            statement.setTimestamp(2, Timestamp.from(expiresAt));
            statement.setObject(3, userId);
            if (statement.executeUpdate() != 1) {
                throw new IllegalStateException("Platform-owner setup token update did not affect one row");
            }
        }
    }

    private String htmlMessage(String setupUrl, int tokenTtlMinutes) {
        String escapedUrl = escapeHtml(setupUrl);
        return """
                <p>A one-time Scout platform-owner setup link was requested by the production migrator.</p>
                <p><a href="%s">Set your password</a></p>
                <p>This link expires in %d minutes and can be used only once.</p>
                <p>If you did not authorize this operation, do not use the link and review the migration logs.</p>
                """.formatted(escapedUrl, tokenTtlMinutes);
    }

    private String textMessage(String setupUrl, int tokenTtlMinutes) {
        return """
                A one-time Scout platform-owner setup link was requested by the production migrator.

                Set your password:
                %s

                This link expires in %d minutes and can be used only once.
                If you did not authorize this operation, do not use the link and review the migration logs.
                """.formatted(setupUrl, tokenTtlMinutes);
    }

    private String normalizeEmail(String email) {
        if (email == null || email.isBlank() || !email.contains("@")) {
            throw new IllegalArgumentException("A valid PLATFORM_OWNER_SETUP_EMAIL is required");
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeBaseUrl(String appBaseUrl) {
        if (appBaseUrl == null || appBaseUrl.isBlank()
                || !(appBaseUrl.startsWith("https://") || appBaseUrl.startsWith("http://localhost"))) {
            throw new IllegalArgumentException(
                    "PLATFORM_OWNER_SETUP_APP_BASE_URL must use HTTPS, except for localhost testing");
        }
        return appBaseUrl.trim().replaceAll("/+$", "");
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash the platform-owner setup token", ex);
        }
    }

    private String escapeHtml(String value) {
        return value.replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private void rollbackQuietly(Connection connection) {
        try {
            connection.rollback();
        } catch (SQLException ignored) {
            // The original delivery or database error remains authoritative.
        }
    }

    record DeliverySummary(Instant expiresAt) {
    }

    private record PlatformOwner(UUID userId, boolean passwordAlreadySet) {
    }
}
