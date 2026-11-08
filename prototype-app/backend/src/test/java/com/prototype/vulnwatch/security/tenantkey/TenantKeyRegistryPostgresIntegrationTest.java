package com.prototype.vulnwatch.security.tenantkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Real-PostgreSQL proof for platform V11 tenant keys and the JDBC key store. */
@PostgresIntegrationTest
class TenantKeyRegistryPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("tenant_keys");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantKeyRegistry registry;
    @Autowired private TenantDataCipher cipher;
    @Autowired private TenantService tenantService;
    @Autowired private JdbcTemplate jdbc;

    private UUID tenantId;

    @BeforeEach
    void setUp() {
        tenantId = tenantService.getDefaultTenant().getId();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.tenant_data_keys WHERE tenant_id = ?", tenantId));
        registry.evict(tenantId);
    }

    @Test
    void provisionsEncryptsRotatesAndStoresOnlyWrappedKeys() {
        assertThat(registry.configured()).isTrue();
        assertThat(cipher.readiness(tenantId).reason()).isEqualTo(TenantKeyUnavailableException.Reason.NOT_PROVISIONED);
        assertThat(registry.provision(tenantId)).isEqualTo(1);
        assertThat(cipher.readiness(tenantId).ready()).isTrue();

        String v1 = cipher.encrypt(tenantId, "directory_user.email", "ada@example.com");
        assertThat(registry.rotate(tenantId)).isEqualTo(2);
        registry.evict(tenantId);
        String v2 = cipher.encrypt(tenantId, "directory_user.email", "ada@example.com");
        assertThat(cipher.decrypt(tenantId, "directory_user.email", v1)).isEqualTo("ada@example.com");
        assertThat(cipher.decrypt(tenantId, "directory_user.email", v2)).isEqualTo("ada@example.com");

        List<String> states = TenantContext.runAsPlatform(() -> jdbc.queryForList(
                "SELECT state FROM platform.tenant_data_keys WHERE tenant_id = ? ORDER BY key_version", String.class, tenantId));
        assertThat(states).containsExactly("DECRYPT_ONLY", "ACTIVE");
        Integer wrappedLength = TenantContext.runAsPlatform(() -> jdbc.queryForObject(
                "SELECT length(wrapped_dek) FROM platform.tenant_data_keys WHERE tenant_id = ? AND key_version = 2", Integer.class, tenantId));
        assertThat(wrappedLength).isEqualTo(12 + 32 + 16);
    }

    @Test
    void concurrentProvisioningCreatesExactlyOneActiveKey() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Integer>> tasks = List.of(() -> registry.provision(tenantId), () -> registry.provision(tenantId),
                    () -> registry.provision(tenantId), () -> registry.provision(tenantId));
            for (Future<Integer> f : pool.invokeAll(tasks)) assertThat(f.get()).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
        Integer rows = TenantContext.runAsPlatform(() -> jdbc.queryForObject(
                "SELECT count(*) FROM platform.tenant_data_keys WHERE tenant_id = ?", Integer.class, tenantId));
        assertThat(rows).isEqualTo(1);
    }

    @Test
    void schemaRejectsSecondActiveKeyAndMissingMaterial() {
        registry.provision(tenantId);
        assertThatThrownBy(() -> TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.tenant_data_keys (tenant_id, key_version, wrapper_kind, kms_key_ref, wrapped_dek, state)
                VALUES (?, 9, 'LOCAL', 'x', '\\x00'::bytea, 'ACTIVE')""", tenantId)))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.tenant_data_keys (tenant_id, key_version, wrapper_kind, kms_key_ref, wrapped_dek, state)
                VALUES (?, 9, 'LOCAL', 'x', NULL, 'DECRYPT_ONLY')""", tenantId)))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void canonicalAuthorityRequiresAcceptance() {
        assertThatThrownBy(() -> TenantContext.runAsPlatform(() -> jdbc.update(
                "INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state) VALUES (?, 'CORE', 'CANONICAL')", tenantId)))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> TenantContext.runAsPlatform(() -> jdbc.update(
                "INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state) VALUES (?, 'UNKNOWN', 'DARK')", tenantId)))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
