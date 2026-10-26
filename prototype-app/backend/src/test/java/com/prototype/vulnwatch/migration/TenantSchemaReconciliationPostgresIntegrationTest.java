package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class TenantSchemaReconciliationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("tenant_schema_reconciliation");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaMigrationService tenantSchemaMigrationService;

    @Autowired
    @Qualifier("platformJdbcTemplate")
    private JdbcTemplate platformJdbcTemplate;

    @Test
    void provisionedTenantReachesPackagedTargetAndHasRls() {
        Tenant tenant = tenantService.createTenant("Drift Customer", "drift-customer", "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        String schemaName = tenant.getSchemaName();

        Integer version = platformJdbcTemplate.queryForObject("""
                select current_version from platform.tenant_schema_versions where tenant_id = ?
                """, Integer.class, tenant.getId());
        Integer target = platformJdbcTemplate.queryForObject("""
                select target_version from platform.tenant_schema_versions where tenant_id = ? and status = 'CURRENT'
                """, Integer.class, tenant.getId());
        Integer incompleteRls = platformJdbcTemplate.queryForObject("""
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = ? and c.relkind in ('r', 'p')
                  and c.relname not in ('tenant_schema_history', 'flyway_schema_history', 'demo_requests')
                  and (not c.relrowsecurity or not c.relforcerowsecurity
                       or not exists (select 1 from pg_policy p where p.polrelid = c.oid and p.polname = 'tenant_isolation'))
                """, Integer.class, schemaName);
        assertEquals(PackagedMigrationCatalog.resolve().tenantTarget(), version);
        assertEquals(PackagedMigrationCatalog.resolve().tenantTarget(), target);
        assertEquals(0, incompleteRls);
    }

    /** Regression: startup reconciliation used to recreate tenant V1's tenant-pinned policies in an unpinned form. */
    @Test
    void startupReconciliationKeepsTenantPinnedRlsPolicies() {
        Tenant tenant = tenantService.createTenant("Pinned Customer", "pinned-customer", "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        String schemaName = tenant.getSchemaName();
        UUID templateTenantId = platformJdbcTemplate.queryForObject(
                "select id from platform.tenants where schema_name = 'tenant_default'", UUID.class);
        int pinnedAfterProvisioning = pinnedPolicies(schemaName, tenant.getId());
        assertTrue(pinnedAfterProvisioning > 0, "tenant V1 creates tenant-pinned policies");
        assertEquals(pinnedPolicies("tenant_default", templateTenantId), pinnedAfterProvisioning);

        TenantSchemaMigrationService.MigrationReport report = tenantSchemaMigrationService.migrateAll(false);

        assertTrue(report.success(), () -> "reconciliation failed: " + report.failureCode() + " " + report.schemas());
        assertEquals(pinnedAfterProvisioning, pinnedPolicies(schemaName, tenant.getId()));
        assertEquals(0, pinnedPolicies(schemaName, templateTenantId), "policies are pinned to the tenant, not the template");
        assertEquals("CURRENT", platformJdbcTemplate.queryForObject(
                "select status from platform.tenant_schema_versions where tenant_id = ?", String.class, tenant.getId()));
    }

    private int pinnedPolicies(String schemaName, UUID tenantId) {
        String pin = "%'" + tenantId + "'::uuid%";
        Integer count = platformJdbcTemplate.queryForObject("""
                select count(*) from pg_policies
                where schemaname = ? and policyname = 'tenant_isolation' and qual like ? and with_check like ?
                """, Integer.class, schemaName, pin, pin);
        return count == null ? 0 : count;
    }
}
