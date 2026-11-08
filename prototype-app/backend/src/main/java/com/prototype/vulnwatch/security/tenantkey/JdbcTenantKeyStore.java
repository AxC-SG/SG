package com.prototype.vulnwatch.security.tenantkey;

import com.prototype.vulnwatch.service.TenantContext;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/** JDBC store for {@code platform.tenant_data_keys}. Every statement runs in platform context. */
public class JdbcTenantKeyStore implements TenantKeyStore {

    private static final String COLUMNS = "tenant_id, key_version, wrapper_kind, kms_key_ref, wrapped_dek, state";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public JdbcTenantKeyStore(JdbcTemplate jdbc, TransactionTemplate tx) {
        this.jdbc = jdbc;
        this.tx = tx;
    }

    @Override
    public Optional<StoredKey> active(UUID tenantId) {
        return one("SELECT " + COLUMNS + " FROM platform.tenant_data_keys WHERE tenant_id = ? AND state = 'ACTIVE'", tenantId);
    }

    @Override
    public Optional<StoredKey> find(UUID tenantId, int version) {
        return one("SELECT " + COLUMNS + " FROM platform.tenant_data_keys WHERE tenant_id = ? AND key_version = ?", tenantId, version);
    }

    @Override
    public boolean insertInitial(StoredKey key) {
        return TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.tenant_data_keys (tenant_id, key_version, wrapper_kind, kms_key_ref, wrapped_dek, state)
                VALUES (?, ?, ?, ?, ?, 'ACTIVE')
                ON CONFLICT DO NOTHING
                """, key.tenantId(), key.version(), key.wrapperKind(), key.keyRef(), key.wrappedKey()) == 1);
    }

    @Override
    public boolean rotate(UUID tenantId, int expectedActiveVersion, StoredKey next) {
        return TenantContext.runAsPlatform(() -> {
            try {
                return Boolean.TRUE.equals(tx.execute(status -> {
                    int demoted = jdbc.update("""
                            UPDATE platform.tenant_data_keys SET state = 'DECRYPT_ONLY', rotated_at = now()
                             WHERE tenant_id = ? AND key_version = ? AND state = 'ACTIVE'
                            """, tenantId, expectedActiveVersion);
                    if (demoted != 1) {
                        status.setRollbackOnly();
                        return false;
                    }
                    jdbc.update("""
                            INSERT INTO platform.tenant_data_keys (tenant_id, key_version, wrapper_kind, kms_key_ref, wrapped_dek, state)
                            VALUES (?, ?, ?, ?, ?, 'ACTIVE')
                            """, tenantId, next.version(), next.wrapperKind(), next.keyRef(), next.wrappedKey());
                    return true;
                }));
            } catch (DuplicateKeyException ex) {
                return false;
            }
        });
    }

    private Optional<StoredKey> one(String sql, Object... args) {
        return TenantContext.runAsPlatform(() -> {
            List<StoredKey> rows = jdbc.query(sql, JdbcTenantKeyStore::map, args);
            return rows.stream().findFirst();
        });
    }

    private static StoredKey map(ResultSet rs, int row) throws SQLException {
        return new StoredKey(rs.getObject(1, UUID.class), rs.getInt(2), rs.getString(3), rs.getString(4),
                rs.getBytes(5), State.valueOf(rs.getString(6)));
    }
}
