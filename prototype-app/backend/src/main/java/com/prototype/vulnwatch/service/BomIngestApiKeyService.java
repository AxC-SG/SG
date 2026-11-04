package com.prototype.vulnwatch.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Tenant-scoped credentials that can push BOM documents and nothing else.
 *
 * <p>A key looks like {@code sgk_<16 hex prefix>_<64 hex secret>}. Only the prefix (a lookup handle)
 * and a SHA-256 of the secret are stored, and the full value is returned exactly once at creation.
 * The secret is 256 random bits, so a plain digest is enough; there is nothing to brute-force.
 */
@Service
public class BomIngestApiKeyService {

    public static final String TOKEN_PREFIX = "sgk_";
    static final int MAX_ACTIVE_KEYS_PER_TENANT = 25;
    private static final int PREFIX_HEX = 16;
    private static final int SECRET_HEX = 64;
    private static final int TOKEN_LENGTH = TOKEN_PREFIX.length() + PREFIX_HEX + 1 + SECRET_HEX;

    public record CreatedKey(UUID id, String name, String keyPrefix, String token, Instant createdAt, Instant expiresAt) {
    }

    public record KeyInfo(UUID id, String name, String keyPrefix, String createdBy, Instant createdAt,
                          Instant expiresAt, Instant lastUsedAt, Instant revokedAt) {
        public String state(Instant now) {
            if (revokedAt != null) {
                return "REVOKED";
            }
            return expiresAt != null && !expiresAt.isAfter(now) ? "EXPIRED" : "ACTIVE";
        }
    }

    /** The tenant and key an accepted token belongs to. */
    public record KeyPrincipal(UUID keyId, UUID tenantId, String name, String keyPrefix) {
    }

    private final JdbcTemplate jdbc;
    private final SecureRandom random = new SecureRandom();

    public BomIngestApiKeyService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public CreatedKey create(UUID tenantId, String name, String createdBy, Instant expiresAt) {
        String cleanName = name == null ? "" : name.trim();
        if (cleanName.isEmpty() || cleanName.length() > 120) {
            throw new BomIngestException(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER",
                    "name is required and must be at most 120 characters.");
        }
        if (expiresAt != null && !expiresAt.isAfter(Instant.now())) {
            throw new BomIngestException(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER",
                    "expiresAt must be in the future.");
        }
        return TenantContext.runAsPlatform(() -> {
            Integer active = jdbc.queryForObject(
                    "SELECT count(*) FROM platform.bom_ingest_api_keys WHERE tenant_id = ? AND revoked_at IS NULL"
                            + " AND (expires_at IS NULL OR expires_at > now())",
                    Integer.class, tenantId);
            if (active != null && active >= MAX_ACTIVE_KEYS_PER_TENANT) {
                throw new BomIngestException(HttpStatus.CONFLICT, "KEY_LIMIT_REACHED",
                        "This workspace already has " + MAX_ACTIVE_KEYS_PER_TENANT
                                + " active ingest keys. Revoke one first.");
            }
            String prefix = randomHex(PREFIX_HEX / 2);
            String secret = randomHex(SECRET_HEX / 2);
            UUID id = UUID.randomUUID();
            Instant now = Instant.now();
            jdbc.update(
                    "INSERT INTO platform.bom_ingest_api_keys"
                            + " (id, tenant_id, name, key_prefix, key_hash, created_by, created_at, expires_at)"
                            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    id, tenantId, cleanName, prefix, sha256(secret), createdBy,
                    Timestamp.from(now), expiresAt == null ? null : Timestamp.from(expiresAt));
            return new CreatedKey(id, cleanName, prefix, TOKEN_PREFIX + prefix + "_" + secret, now, expiresAt);
        });
    }

    public List<KeyInfo> list(UUID tenantId) {
        return TenantContext.runAsPlatform(() -> jdbc.query(
                "SELECT id, name, key_prefix, created_by, created_at, expires_at, last_used_at, revoked_at"
                        + " FROM platform.bom_ingest_api_keys WHERE tenant_id = ? ORDER BY created_at DESC",
                (rs, row) -> new KeyInfo(
                        rs.getObject("id", UUID.class), rs.getString("name"), rs.getString("key_prefix"),
                        rs.getString("created_by"), instant(rs.getTimestamp("created_at")),
                        instant(rs.getTimestamp("expires_at")), instant(rs.getTimestamp("last_used_at")),
                        instant(rs.getTimestamp("revoked_at"))),
                tenantId));
    }

    /** Revokes a key of this tenant; false when it does not exist, belongs to another tenant, or is already revoked. */
    public boolean revoke(UUID tenantId, UUID keyId) {
        return TenantContext.runAsPlatform(() -> jdbc.update(
                "UPDATE platform.bom_ingest_api_keys SET revoked_at = now()"
                        + " WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL",
                keyId, tenantId) > 0);
    }

    /** Empty for anything that is not a live, matching key; callers must not say which part failed. */
    public Optional<KeyPrincipal> authenticate(String token) {
        if (token == null || token.length() != TOKEN_LENGTH || !token.startsWith(TOKEN_PREFIX)
                || token.charAt(TOKEN_PREFIX.length() + PREFIX_HEX) != '_') {
            return Optional.empty();
        }
        String prefix = token.substring(TOKEN_PREFIX.length(), TOKEN_PREFIX.length() + PREFIX_HEX);
        String secret = token.substring(TOKEN_PREFIX.length() + PREFIX_HEX + 1);
        if (!isHex(prefix) || !isHex(secret)) {
            return Optional.empty();
        }
        return TenantContext.runAsPlatform(() -> {
            List<Object[]> rows = jdbc.query(
                    "SELECT id, tenant_id, name, key_hash FROM platform.bom_ingest_api_keys"
                            + " WHERE key_prefix = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
                    (rs, row) -> new Object[] {
                            rs.getObject("id", UUID.class), rs.getObject("tenant_id", UUID.class),
                            rs.getString("name"), rs.getString("key_hash")},
                    prefix);
            if (rows.isEmpty()) {
                return Optional.<KeyPrincipal>empty();
            }
            Object[] row = rows.get(0);
            boolean match = MessageDigest.isEqual(
                    sha256(secret).getBytes(StandardCharsets.US_ASCII),
                    ((String) row[3]).getBytes(StandardCharsets.US_ASCII));
            if (!match) {
                return Optional.<KeyPrincipal>empty();
            }
            // Coarse on purpose: a high-volume pipeline should not write on every request.
            jdbc.update("UPDATE platform.bom_ingest_api_keys SET last_used_at = now() WHERE id = ?"
                    + " AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')", row[0]);
            return Optional.of(new KeyPrincipal((UUID) row[0], (UUID) row[1], (String) row[2], prefix));
        });
    }

    private String randomHex(int bytes) {
        byte[] buffer = new byte[bytes];
        random.nextBytes(buffer);
        return HexFormat.of().formatHex(buffer);
    }

    private static boolean isHex(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.digit(value.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
