package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Ownership and directory writers stamp tenant_id from the session tenant, never from the column default. The tenant
 * schema repair copies column defaults from tenant_default, so in a real database another tenant's id can sit there.
 */
@PostgresIntegrationTest
class OwnershipTenantStampPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_tenant_stamp");
    private static final List<String> TABLES = List.of("team", "team_alias", "identity_source", "directory_user", "directory_group",
            "directory_group_member", "directory_search_token", "ownership_subject", "ownership_claim", "ownership_assignment",
            "ownership_event", "ownership_cache_invalidation");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TeamNamespaceService teams;
    @Autowired private DirectoryService directory;
    @Autowired private OwnershipSubjectService subjects;
    @Autowired private ManualAssignmentService assignments;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;

    @AfterEach
    void clear() {
        TenantContext.clear();
        if (tenant != null) {
            TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
        }
    }

    @Test
    void writesCarryTheSessionTenantEvenWhenColumnDefaultsNameAnotherTenant() {
        tenant = newTenant();
        Tenant other = newTenant();
        keys.provision(tenant.getId());
        pointTenantDefaultsAt(tenant, other);
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by)
                VALUES (?, 'CORE', 'CANONICAL', 'test', now(), 'test')""", tenant.getId()));

        enter(tenant);
        UUID payments = teams.createTeam("Payments", null, null, "admin").id();
        teams.addAlias(payments, "payments-eng", "MANUAL", null, "admin");
        UUID manual = directory.manualSource("admin");
        UUID ada = directory.createUser("Ada Lovelace", "ada@example.test", "E-1", null, manual, "admin").id();
        UUID group = directory.createGroup("payments-oncall", manual, "admin").id();
        directory.addMember(group, ada, manual, "admin");
        UUID app = subjects.register("APPLICATION", "checkout", null).id();
        assignments.assign(app, "APPLICATION", payments, "service review", null, "key-1", "admin", null);

        Map<String, long[]> counts = new LinkedHashMap<>();
        TenantContext.runAsPlatform(() -> TABLES.forEach(table -> counts.put(table, new long[] {
                count(tenant, table, "tenant_id = ?", tenant.getId()), count(tenant, table, "tenant_id <> ?", tenant.getId())})));
        counts.forEach((table, c) -> {
            assertThat(c[0]).as(table + " rows for the session tenant").isPositive();
            assertThat(c[1]).as(table + " rows stamped with another tenant").isZero();
        });
    }

    private void pointTenantDefaultsAt(Tenant target, Tenant wrong) {
        TenantContext.runAsPlatform(() -> jdbc.queryForList("""
                SELECT c.table_name FROM information_schema.columns c
                  JOIN pg_class r ON r.relname = c.table_name AND r.relnamespace = c.table_schema::regnamespace AND r.relkind = 'r'
                 WHERE c.table_schema = ? AND c.column_name = 'tenant_id' AND c.column_default IS NOT NULL""", String.class,
                target.getSchemaName()).forEach(table -> jdbc.execute("ALTER TABLE \"%s\".\"%s\" ALTER COLUMN tenant_id SET DEFAULT '%s'::uuid"
                .formatted(target.getSchemaName(), table, wrong.getId()))));
    }

    private long count(Tenant t, String table, String where, UUID tenantId) {
        Long n = jdbc.queryForObject("SELECT count(*) FROM \"%s\".\"%s\" WHERE %s".formatted(t.getSchemaName(), table, where), Long.class, tenantId);
        return n == null ? 0 : n;
    }

    private Tenant newTenant() {
        String slug = "own-stamp-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        return tenantService.resolveTenantUuid(created.getId());
    }

    private void enter(Tenant t) {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(t.getId());
        TenantContext.setCurrentSchemaName(t.getSchemaName());
    }
}
