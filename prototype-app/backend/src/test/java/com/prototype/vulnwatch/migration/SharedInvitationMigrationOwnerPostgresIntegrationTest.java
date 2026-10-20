package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.UUID;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.core.io.ClassPathResource;

/** The template's shared demo invitations can reference a different customer tenant. */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class SharedInvitationMigrationOwnerPostgresIntegrationTest {

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void nonBypassMigrationOwnerConvertsSharedCustomerInvitesAndRestoresForcedRls(boolean duplicateToken) throws Exception {
        var database = LocalPostgresTestDatabase.provision("phase_two_shared_invite_owner_" + duplicateToken);
        String owner = "phase2_owner_" + UUID.randomUUID().toString().replace("-", "");
        String templateTenant = UUID.randomUUID().toString();
        String customerTenant = UUID.randomUUID().toString();
        try (var connection = DriverManager.getConnection(database.url(), database.username(), database.password());
             var sql = connection.createStatement()) {
            sql.execute("CREATE ROLE " + owner + " NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT");
            sql.execute("CREATE SCHEMA tenant_default AUTHORIZATION " + owner);
            sql.execute("CREATE TABLE tenant_default.demo_invites (id uuid PRIMARY KEY, tenant_id uuid NOT NULL,"
                    + " token varchar(96) NOT NULL, status varchar(32), expires_at timestamptz NOT NULL, accepted_at timestamptz)");
            sql.execute("INSERT INTO tenant_default.demo_invites VALUES ('" + UUID.randomUUID() + "','" + customerTenant
                    + "','controlled-shared-invite-sentinel','READY',now()+interval '1 day',NULL)");
            if (duplicateToken) {
                sql.execute("INSERT INTO tenant_default.demo_invites SELECT '" + UUID.randomUUID()
                        + "',tenant_id,token,status,expires_at,accepted_at FROM tenant_default.demo_invites");
            }
            sql.execute("ALTER TABLE tenant_default.demo_invites ENABLE ROW LEVEL SECURITY");
            sql.execute("ALTER TABLE tenant_default.demo_invites FORCE ROW LEVEL SECURITY");
            sql.execute("CREATE POLICY tenant_runtime_isolation ON tenant_default.demo_invites"
                    + " USING (tenant_id=nullif(current_setting('app.current_tenant_id',true),'')::uuid)"
                    + " WITH CHECK (tenant_id=nullif(current_setting('app.current_tenant_id',true),'')::uuid)");
            for (String table : new String[]{"aws_discovery_configs", "sccm_cmdb_configs", "servicenow_cmdb_configs"}) {
                sql.execute("CREATE TABLE tenant_default." + table
                        + " (id uuid, credential_secret varchar(255), enabled boolean, auto_sync_enabled boolean)");
            }
            sql.execute("CREATE TABLE tenant_default.aws_discovery_targets (id uuid, enabled boolean)");
            sql.execute("CREATE TABLE tenant_default.ai_security_connector_configs (id uuid, provider text, enabled boolean)");
            for (String table : new String[]{"demo_invites", "aws_discovery_configs", "sccm_cmdb_configs",
                    "servicenow_cmdb_configs", "aws_discovery_targets", "ai_security_connector_configs"}) {
                sql.execute("ALTER TABLE tenant_default." + table + " OWNER TO " + owner);
            }
            sql.execute("SET ROLE " + owner);
            try (var role = sql.executeQuery("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")) {
                role.next();
                assertFalse(role.getBoolean(1));
            }
            String migration;
            try (var input = new ClassPathResource("db/migration/tenant/V3__credential_and_invitation_boundaries.sql").getInputStream()) {
                migration = new String(input.readAllBytes(), StandardCharsets.UTF_8)
                        .replace("${tenantSchema}", "tenant_default").replace("${tenantId}", templateTenant);
            }
            connection.setAutoCommit(false);
            Exception rejected = null;
            try {
                sql.execute(migration);
                connection.commit();
            } catch (Exception failure) {
                connection.rollback();
                rejected = failure;
            } finally {
                connection.setAutoCommit(true);
                sql.execute("RESET ROLE");
            }
            if (duplicateToken) {
                org.junit.jupiter.api.Assertions.assertNotNull(rejected);
                assertEquals("23505", ((java.sql.SQLException) rejected).getSQLState());
                try (var row = sql.executeQuery("SELECT count(*) FROM information_schema.columns"
                        + " WHERE table_schema='tenant_default' AND table_name='demo_invites' AND column_name='token_hash'")) {
                    row.next();
                    assertEquals(0, row.getInt(1));
                }
                try (var row = sql.executeQuery("SELECT relforcerowsecurity FROM pg_class"
                        + " WHERE oid='tenant_default.demo_invites'::regclass")) {
                    row.next();
                    assertTrue(row.getBoolean(1));
                }
                return;
            }
            org.junit.jupiter.api.Assertions.assertNull(rejected);
            try (var row = sql.executeQuery("SELECT token IS NULL, token_hash ~ '^[0-9a-f]{64}$',status"
                    + " FROM tenant_default.demo_invites")) {
                row.next();
                assertTrue(row.getBoolean(1));
                assertTrue(row.getBoolean(2));
                assertEquals("EXPIRED", row.getString(3));
            }
            try (var row = sql.executeQuery("SELECT relforcerowsecurity FROM pg_class"
                    + " WHERE oid='tenant_default.demo_invites'::regclass")) {
                row.next();
                assertTrue(row.getBoolean(1));
            }
        }
    }
}
