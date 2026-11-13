package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Background pollers call {@link TenantService#listActiveTenants()} from scheduler threads that carry no
 * tenant context. The registry read must acquire its connection through the tenant-aware datasource
 * already in platform scope, which a method-level transaction cannot guarantee because the transaction
 * acquires the connection before the method body runs (Sydney lab, November 12, finding 3).
 */
@PostgresIntegrationTest
class TenantRegistryPlatformScopePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("tenant_registry_platform_scope");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }

    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired JdbcTemplate jdbc;
    @Autowired @Qualifier("platformJdbcTemplate") JdbcTemplate platformJdbc;
    @Autowired PlatformTransactionManager transactionManager;
    @Autowired MeterRegistry meters;

    private UUID active;
    private UUID suspended;

    @BeforeEach
    void setUp() {
        TenantContext.clear();
        active = provision("registry-active-");
        suspended = provision("registry-suspended-");
        platformJdbc.update("update platform.tenants set status = 'SUSPENDED' where id = ?", suspended);
        TenantContext.clear();
    }

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    @Test
    void controlAnUnscopedConnectionIsCountedAsMissingContext() {
        double before = count("missing_unclassified");

        jdbc.queryForObject("select 1", Integer.class);

        assertEquals(before + 1, count("missing_unclassified"),
                "The datasource must classify an unscoped checkout, or the other assertions prove nothing");
    }

    @Test
    void schedulerThreadReadsTheRegistryOnAPlatformScopedConnection() {
        double missingBefore = count("missing_unclassified");
        double platformBefore = count("platform");

        List<Tenant> result = tenants.listActiveTenants();

        assertEquals(missingBefore, count("missing_unclassified"));
        assertTrue(count("platform") > platformBefore);
        List<UUID> ids = result.stream().map(Tenant::getId).toList();
        assertTrue(ids.contains(active));
        assertFalse(ids.contains(suspended));
        assertFalse(TenantContext.isPlatformContext());
        assertNull(TenantContext.getCurrentTenantId());
    }

    @Test
    void callerTransactionOpenedInPlatformScopeIsJoined() {
        double missingBefore = count("missing_unclassified");

        List<Tenant> result = TenantContext.runAsPlatform(() ->
                new TransactionTemplate(transactionManager).execute(status -> tenants.listActiveTenants()));

        assertEquals(missingBefore, count("missing_unclassified"));
        assertTrue(result.stream().map(Tenant::getId).toList().contains(active));
    }

    @Test
    void callerTransactionOpenedInTenantScopeIsRejected() {
        TenantContext.setCurrentTenantId(active);

        assertThrows(IllegalStateException.class, () ->
                new TransactionTemplate(transactionManager).execute(status -> {
                    jdbc.queryForObject("select 1", Integer.class);
                    return tenants.listActiveTenants();
                }));

        assertEquals(active, TenantContext.getCurrentTenantId());
        assertFalse(TenantContext.isPlatformContext());
    }

    private UUID provision(String prefix) {
        String slug = prefix + UUID.randomUUID().toString().substring(0, 8);
        Tenant tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        return tenant.getId();
    }

    private double count(String classification) {
        var counter = meters.find("tenant.context.missing").tag("classification", classification).counter();
        return counter == null ? 0 : counter.count();
    }
}
