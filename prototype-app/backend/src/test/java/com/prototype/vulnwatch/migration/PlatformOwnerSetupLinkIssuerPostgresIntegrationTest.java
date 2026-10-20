package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.mockito.ArgumentCaptor;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class PlatformOwnerSetupLinkIssuerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("platform_owner_setup_link_issuer");
    private static final String RUNTIME_USERNAME = "scout_runtime_setup_link_it";
    private static final String RUNTIME_PASSWORD = "scout-runtime-setup-link-it-" + UUID.randomUUID();
    private static final String OWNER_EMAIL = "platform-owner@example.test";
    private static final Pattern SETUP_TOKEN = Pattern.compile("/setup#token=([0-9a-f-]+)");

    @Test
    void deliversHashedOneTimeTokenAndRollsBackFailedDelivery() throws Exception {
        bootstrapDatabase();
        UUID userId = insertPlatformOwner();
        ResendEmailClient emailClient = mock(ResendEmailClient.class);
        PlatformOwnerSetupLinkIssuer issuer = new PlatformOwnerSetupLinkIssuer(emailClient);

        when(emailClient.send(any())).thenReturn(ResendEmailClient.DeliveryResult.sent("resend-message"));
        try (Connection connection = ownerConnection()) {
            PlatformOwnerSetupLinkIssuer.DeliverySummary summary = issuer.issue(
                    connection,
                    OWNER_EMAIL,
                    "https://scoutgrid.io",
                    30,
                    false,
                    UUID.randomUUID());
            assertTrue(summary.expiresAt().isAfter(Instant.now()));
        }

        ArgumentCaptor<ResendEmailClient.EmailMessage> messageCaptor =
                ArgumentCaptor.forClass(ResendEmailClient.EmailMessage.class);
        verify(emailClient).send(messageCaptor.capture());
        ResendEmailClient.EmailMessage message = messageCaptor.getValue();
        assertEquals(OWNER_EMAIL, message.to());
        assertTrue(message.text().contains("https://scoutgrid.io/setup#token="));
        String token = extractToken(message.text());
        assertEquals(hashToken(token), queryString(
                "select password_setup_token_hash from platform.app_users where id = ?", userId));
        assertNotNull(queryString(
                "select password_setup_token_expires_at::text from platform.app_users where id = ?", userId));

        reset(emailClient);
        clearToken(userId);
        when(emailClient.send(any())).thenReturn(ResendEmailClient.DeliveryResult.failed("rejected"));
        try (Connection connection = ownerConnection()) {
            assertThrows(IllegalStateException.class, () -> issuer.issue(
                    connection,
                    OWNER_EMAIL,
                    "https://scoutgrid.io",
                    30,
                    false,
                    UUID.randomUUID()));
        }
        assertNull(queryString(
                "select password_setup_token_hash from platform.app_users where id = ?", userId));

        reset(emailClient);
        setPasswordHash(userId);
        try (Connection connection = ownerConnection()) {
            assertThrows(IllegalStateException.class, () -> issuer.issue(
                    connection,
                    OWNER_EMAIL,
                    "https://scoutgrid.io",
                    30,
                    false,
                    UUID.randomUUID()));
        }
        verify(emailClient, never()).send(any());
    }

    private void bootstrapDatabase() throws Exception {
        set("DB_URL", DATABASE.url());
        set("DB_USERNAME", DATABASE.username());
        set("DB_PASSWORD", DATABASE.password());
        set("RUNTIME_DB_USERNAME", RUNTIME_USERNAME);
        set("RUNTIME_DB_PASSWORD", RUNTIME_PASSWORD);
        try {
            ProductionBootstrapCli.main(new String[0]);
        } finally {
            clear("DB_URL");
            clear("DB_USERNAME");
            clear("DB_PASSWORD");
            clear("RUNTIME_DB_USERNAME");
            clear("RUNTIME_DB_PASSWORD");
        }
    }

    private UUID insertPlatformOwner() throws Exception {
        UUID userId = UUID.randomUUID();
        try (Connection connection = ownerConnection();
             var user = connection.prepareStatement("""
                     insert into platform.app_users (
                         id, created_at, display_name, email, external_subject,
                         platform_owner, status, updated_at
                     ) values (?, now(), 'Platform Owner', ?, ?, true, 'ACTIVE', now())
                     """);
             var role = connection.prepareStatement("""
                     insert into platform.app_user_global_roles (id, app_user_id, role, created_at)
                     values (?, ?, 'PLATFORM_OWNER', now())
                     """)) {
            user.setObject(1, userId);
            user.setString(2, OWNER_EMAIL);
            user.setString(3, OWNER_EMAIL);
            user.executeUpdate();
            role.setObject(1, UUID.randomUUID());
            role.setObject(2, userId);
            role.executeUpdate();
        }
        return userId;
    }

    private void clearToken(UUID userId) throws Exception {
        executeUpdate("""
                update platform.app_users
                set password_setup_token_hash = null,
                    password_setup_token_expires_at = null
                where id = ?
                """, userId);
    }

    private void setPasswordHash(UUID userId) throws Exception {
        executeUpdate("""
                update platform.app_users
                set password_hash = 'existing-password-hash',
                    password_set_at = now()
                where id = ?
                """, userId);
    }

    private void executeUpdate(String sql, Object parameter) throws Exception {
        try (Connection connection = ownerConnection();
             var statement = connection.prepareStatement(sql)) {
            statement.setObject(1, parameter);
            statement.executeUpdate();
        }
    }

    private String queryString(String sql, Object parameter) throws Exception {
        try (Connection connection = ownerConnection();
             var statement = connection.prepareStatement(sql)) {
            statement.setObject(1, parameter);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getString(1);
            }
        }
    }

    private Connection ownerConnection() throws Exception {
        return DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
    }

    private String extractToken(String text) {
        Matcher matcher = SETUP_TOKEN.matcher(text);
        assertTrue(matcher.find());
        return matcher.group(1);
    }

    private String hashToken(String token) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
    }

    private void set(String key, String value) {
        System.setProperty(key, value);
    }

    private void clear(String key) {
        System.clearProperty(key);
    }
}
