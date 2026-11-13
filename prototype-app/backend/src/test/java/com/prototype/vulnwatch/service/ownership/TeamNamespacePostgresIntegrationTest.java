package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/** Real-PostgreSQL proof for tenant V20 and the shared team-name/alias namespace. */
@PostgresIntegrationTest
class TeamNamespacePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("team_namespace");
    private static final List<String> V20_TABLES = List.of("identity_source", "identity_import_run", "directory_user",
            "directory_group", "external_identity", "external_group", "directory_group_member", "directory_search_token",
            "team", "team_alias", "external_group_team_mapping", "team_member");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private Tenant other;

    @BeforeEach
    void setUp() {
        tenant = newTenant();
        other = newTenant();
        enter(tenant);
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    void everyV20TableForcesRlsAndEveryForeignKeyIsTenantInclusive() {
        for (String table : V20_TABLES) {
            Boolean forced = jdbc.queryForObject("""
                    SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = ? AND c.relname = ?""", Boolean.class, tenant.getSchemaName(), table);
            assertThat(forced).as(table + " forces RLS").isTrue();
            Integer policies = jdbc.queryForObject("SELECT count(*) FROM pg_policies WHERE schemaname = ? AND tablename = ? AND policyname = 'tenant_isolation'",
                    Integer.class, tenant.getSchemaName(), table);
            assertThat(policies).as(table).isEqualTo(1);
        }
        List<String> nonInclusive = jdbc.queryForList("""
                SELECT con.conname FROM pg_constraint con
                  JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_class r ON r.oid = con.confrelid JOIN pg_namespace rn ON rn.oid = r.relnamespace
                 WHERE con.contype = 'f' AND n.nspname = ? AND c.relname = ANY (?) AND rn.nspname = n.nspname
                   AND (SELECT attname FROM pg_attribute WHERE attrelid = con.conrelid AND attnum = con.conkey[1]) <> 'tenant_id'
                """, String.class, tenant.getSchemaName(), V20_TABLES.toArray(String[]::new));
        assertThat(nonInclusive).isEmpty();
        Integer cascades = jdbc.queryForObject("""
                SELECT count(*) FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE con.contype = 'f' AND n.nspname = ? AND c.relname = ANY (?) AND con.confdeltype = 'c'
                """, Integer.class, tenant.getSchemaName(), V20_TABLES.toArray(String[]::new));
        assertThat(cascades).isZero();
    }

    @Test
    void namesAndAliasesShareOneCaseInsensitiveNamespace() {
        var payments = teams.createTeam("  Payments   Platform ", null, "PAY-OPS", "admin");
        assertThat(payments.name()).isEqualTo("Payments Platform");
        var identity = teams.createTeam("Identity", null, null, "admin");

        assertConflict(() -> teams.createTeam("payments platform", null, null, "admin"));
        var alias = teams.addAlias(payments.id(), "PAY", "MANUAL", null, "admin");
        assertThat(teams.addAlias(payments.id(), "pay", "MANUAL", null, "admin").id()).isEqualTo(alias.id());
        assertConflict(() -> teams.addAlias(identity.id(), "Pay", "MANUAL", null, "admin"));
        assertConflict(() -> teams.addAlias(identity.id(), "PAYMENTS PLATFORM", "MANUAL", null, "admin"));
        assertConflict(() -> teams.createTeam("pay", null, null, "admin"));
        assertConflict(() -> teams.renameTeam(identity.id(), "Pay", identity.version(), "admin"));

        assertThat(teams.resolve("PAYMENTS platform")).contains(payments.id());
        assertThat(teams.resolve("pay")).contains(payments.id());
        assertThat(teams.resolve("unknown")).isEmpty();
        assertThat(teams.resolve("   ")).isEmpty();

        var renamed = teams.renameTeam(payments.id(), "Payments", payments.version(), "admin");
        assertThat(teams.resolve("payments platform")).isEmpty();
        assertThat(teams.resolve("payments")).contains(payments.id());
        assertConflict(() -> teams.renameTeam(payments.id(), "Payments Two", payments.version(), "admin"));
        teams.removeAlias(payments.id(), alias.id());
        assertThat(teams.resolve("pay")).isEmpty();
        assertThat(teams.createTeam("Pay", null, null, "admin").name()).isEqualTo("Pay");
        assertThat(renamed.version()).isEqualTo(payments.version() + 1);

        Integer audits = jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE action LIKE 'ownership.team%'", Integer.class);
        assertThat(audits).isGreaterThanOrEqualTo(6);
    }

    @Test
    void namespacesAreIndependentPerTenant() {
        var mine = teams.createTeam("Platform", null, null, "admin");
        enter(other);
        assertThat(teams.resolve("platform")).isEmpty();
        assertThat(teams.team(mine.id())).isEmpty();
        var theirs = teams.createTeam("Platform", null, null, "admin");
        assertThat(theirs.id()).isNotEqualTo(mine.id());
        assertThatThrownBy(() -> teams.addAlias(mine.id(), "x", "MANUAL", null, "admin")).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void parentChangesRejectCyclesAndArchivedParents() {
        var root = teams.createTeam("Root", null, null, "admin");
        var child = teams.createTeam("Child", root.id(), null, "admin");
        var grandchild = teams.createTeam("Grandchild", child.id(), null, "admin");
        var current = teams.team(root.id()).orElseThrow();
        assertBadRequest(() -> teams.updateTeam(root.id(), grandchild.id(), null, current.version(), "admin"));
        assertConflict(() -> teams.setStatus(root.id(), "ARCHIVED", current.version(), "admin"));
        // Re-parenting under a root (whose own parent is null) walks to the top without error.
        var other = teams.createTeam("Other Root", null, null, "admin");
        assertThat(teams.updateTeam(other.id(), root.id(), null, other.version(), "admin").parentTeamId()).isEqualTo(root.id());
        teams.setStatus(grandchild.id(), "ARCHIVED", grandchild.version(), "admin");
        assertBadRequest(() -> teams.createTeam("Orphan", grandchild.id(), null, "admin"));
        assertConflict(() -> teams.createTeam("grandchild", null, null, "admin"));
        assertBadRequest(() -> teams.createTeam("bad\u0007name", null, null, "admin"));
        assertBadRequest(() -> teams.createTeam("x".repeat(201), null, null, "admin"));
    }

    @Test
    void concurrentCreatesOfTheSameKeyAdmitExactlyOne() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Boolean>> tasks = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                String spelling = i % 2 == 0 ? "Data Platform" : "DATA platform";
                tasks.add(() -> {
                    enter(tenant);
                    try {
                        teams.createTeam(spelling, null, null, "admin");
                        return true;
                    } catch (ResponseStatusException ex) {
                        return false;
                    } finally {
                        TenantContext.clear();
                    }
                });
            }
            int created = 0;
            for (Future<Boolean> f : pool.invokeAll(tasks)) if (f.get()) created++;
            assertThat(created).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    private Tenant newTenant() {
        String slug = "own-ns-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        return tenantService.resolveTenantUuid(created.getId());
    }

    private void enter(Tenant t) {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(t.getId());
        TenantContext.setCurrentSchemaName(t.getSchemaName());
    }

    private static void assertConflict(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));
    }

    private static void assertBadRequest(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(400));
    }
}
