package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.web.server.ResponseStatusException;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class DemoTenantPurgePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("demo_tenant_purge");
    private static final String RUNTIME_ROLE = "demo_purge_test_runtime";

    private Connection connection;
    private JdbcTemplate jdbc;
    private DemoTenantPurgeService service;
    private UUID tenantId;
    private UUID otherTenantId;

    @BeforeEach
    void setUp() throws Exception {
        connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
        jdbc = new JdbcTemplate(new SingleConnectionDataSource(connection, true));
        jdbc.execute("CREATE SCHEMA platform");
        jdbc.execute("CREATE SCHEMA tenant_default");
        jdbc.execute("CREATE TABLE platform.tenants (id uuid PRIMARY KEY)");
        jdbc.execute("""
                CREATE TABLE platform.tenant_memberships (
                    tenant_id uuid REFERENCES platform.tenants(id), user_id uuid)
                """);
        jdbc.execute("CREATE TABLE platform.tenant_support_grants (tenant_id uuid REFERENCES platform.tenants(id))");
        jdbc.execute("""
                CREATE TABLE tenant_default.demo_requests (
                    id uuid PRIMARY KEY, tenant_id uuid REFERENCES platform.tenants(id))
                """);
        jdbc.execute("""
                CREATE TABLE tenant_default.demo_invites (
                    id uuid PRIMARY KEY,
                    request_id uuid REFERENCES tenant_default.demo_requests(id),
                    tenant_id uuid NOT NULL,
                    CONSTRAINT fk_demo_invites_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id))
                """);
        jdbc.execute("ALTER TABLE tenant_default.demo_invites ENABLE ROW LEVEL SECURITY");
        jdbc.execute("ALTER TABLE tenant_default.demo_invites FORCE ROW LEVEL SECURITY");
        jdbc.execute("""
                CREATE POLICY tenant_runtime_isolation ON tenant_default.demo_invites
                USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
                """);
        jdbc.execute("CREATE ROLE " + RUNTIME_ROLE + " NOSUPERUSER NOBYPASSRLS");
        jdbc.execute("GRANT USAGE ON SCHEMA platform, tenant_default TO " + RUNTIME_ROLE);
        jdbc.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA platform, tenant_default TO " + RUNTIME_ROLE);

        tenantId = UUID.randomUUID();
        otherTenantId = UUID.randomUUID();
        seedLifecycle(tenantId);
        seedLifecycle(otherTenantId);
        jdbc.execute("SET ROLE " + RUNTIME_ROLE);
        jdbc.queryForObject("select set_config('app.current_tenant_id', ?, false)", String.class, otherTenantId.toString());

        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Demo Customer");
        tenant.setSchemaName("tenant_demo_customer");
        tenant.setStatus("ACTIVE");
        TenantRepository repository = mock(TenantRepository.class);
        when(repository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(repository.existsById(tenantId)).thenReturn(true);
        service = new DemoTenantPurgeService(repository, mock(AppUserRepository.class), jdbc,
                mock(AuditEventService.class), mock(TenantLifecycleGuardService.class),
                mock(TenantSchemaService.class), mock(DemoTenantPurgePlanner.class));
    }

    @AfterEach
    void tearDown() throws Exception {
        if (connection != null) {
            try {
                jdbc.execute("RESET ROLE");
                jdbc.execute("DROP SCHEMA tenant_default CASCADE");
                jdbc.execute("DROP SCHEMA platform CASCADE");
                jdbc.execute("DROP ROLE IF EXISTS " + RUNTIME_ROLE);
            } finally {
                connection.close();
            }
        }
    }

    @Test
    void restrictedRoleCannotDeleteTenantAndSharedHistoryRemains() {
        // Matches production grants: metadata cannot expose the referenced PK
        // through constraint_column_usage, even though DML is allowed.
        assertFalse(jdbc.queryForObject("select rolsuper or rolbypassrls from pg_roles where rolname = current_user", Boolean.class));
        assertEquals(0, jdbc.queryForObject("""
                select count(*) from information_schema.constraint_column_usage
                where table_schema = 'platform' and table_name = 'tenants'
                """, Integer.class));

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.deleteTenant(tenantId, Instant.now()));
        assertEquals(503, error.getStatusCode().value());

        assertEquals(otherTenantId.toString(), currentTenantContext());
        assertEquals(1, countForTenant("platform.tenants", "id", tenantId));
        assertEquals(1, countForTenant("platform.tenant_memberships", "tenant_id", tenantId));
        assertEquals(1, countForTenant("platform.tenant_support_grants", "tenant_id", tenantId));
        assertEquals(1, countForTenant("platform.tenants", "id", otherTenantId));
        assertEquals(1, countForTenant("platform.tenant_support_grants", "tenant_id", otherTenantId));
        assertEquals(1, countForTenant("tenant_default.demo_invites", "tenant_id", otherTenantId));
        assertEquals(1, countForTenant("tenant_default.demo_requests", "tenant_id", otherTenantId));
        assertEquals(0, jdbc.queryForObject("select count(*) from tenant_default.demo_requests where tenant_id is null", Integer.class));
        jdbc.execute("RESET ROLE");
        assertEquals(1, countForTenant("tenant_default.demo_invites", "tenant_id", tenantId));
        assertEquals(1, countForTenant("tenant_default.demo_requests", "tenant_id", tenantId));
    }

    @Test
    void inviteCleanupFailureRestoresConnectionContextAndKeepsTenantRegistry() {
        jdbc.execute("RESET ROLE");
        jdbc.execute("""
                CREATE FUNCTION tenant_default.fail_invite_delete() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'invite cleanup failed'; END $$
                """);
        jdbc.execute("""
                CREATE TRIGGER fail_invite_delete BEFORE DELETE ON tenant_default.demo_invites
                FOR EACH ROW EXECUTE FUNCTION tenant_default.fail_invite_delete()
                """);
        jdbc.execute("SET ROLE " + RUNTIME_ROLE);

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.deleteTenant(tenantId, Instant.now()));

        assertEquals(503, error.getStatusCode().value());
        assertEquals(otherTenantId.toString(), currentTenantContext());
        assertEquals(1, countForTenant("platform.tenants", "id", tenantId));
        assertEquals(1, countForTenant("tenant_default.demo_requests", "tenant_id", tenantId));
    }

    private void seedLifecycle(UUID id) {
        UUID requestId = UUID.randomUUID();
        jdbc.update("insert into platform.tenants (id) values (?)", id);
        jdbc.update("insert into platform.tenant_memberships (tenant_id, user_id) values (?, ?)", id, UUID.randomUUID());
        jdbc.update("insert into platform.tenant_support_grants (tenant_id) values (?)", id);
        jdbc.update("insert into tenant_default.demo_requests (id, tenant_id) values (?, ?)", requestId, id);
        jdbc.update("insert into tenant_default.demo_invites (id, request_id, tenant_id) values (?, ?, ?)", UUID.randomUUID(), requestId, id);
    }

    private String currentTenantContext() {
        return jdbc.queryForObject("select current_setting('app.current_tenant_id', true)", String.class);
    }

    private int countForTenant(String table, String column, UUID id) {
        return jdbc.queryForObject("select count(*) from " + table + " where " + column + " = ?", Integer.class, id);
    }
}
