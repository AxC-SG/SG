package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/** Proves forward conversion from the applied Phase 1 schema, with actual legacy rows. */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class PhaseTwoUpgradePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("phase_two_upgrade");

    @Test
    void forwardMigrationsClearRawInvitesAndContainOnlyUnboundAwsConnectors() throws Exception {
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource(
                DATABASE.url(), DATABASE.username(), DATABASE.password()));
        UUID tenantId = UUID.randomUUID();
        String schema = "tenant_upgrade";
        platform("1").migrate();
        jdbc.update("""
                INSERT INTO platform.tenants
                  (id,name,slug,schema_name,status,plan_code,created_at,updated_at,max_connector_count,
                   max_daily_exposure_refreshes,max_daily_sbom_uploads,max_export_rows,max_service_account_count)
                VALUES (?, 'Upgrade Fixture','upgrade-fixture',?,'ACTIVE','ENTERPRISE',now(),now(),10,10,10,100,10)
                """, tenantId, schema);
        tenant(schema, tenantId, "2").migrate();
        String raw = "controlled-legacy-invite-sentinel";
        String accepted = "controlled-accepted-invite-sentinel";
        for (String status : new String[]{"READY", "ACCEPTED"}) {
            String token = "READY".equals(status) ? raw : accepted;
            jdbc.update("""
                    INSERT INTO platform.tenant_user_invites
                      (id,tenant_id,email,external_subject,role,status,token,expires_at,accepted_at,created_at,updated_at)
                    VALUES (?,?,'invite@example.test',?,'TENANT_ADMIN',?,?,now()+interval '1 day',
                            CASE WHEN ? = 'ACCEPTED' THEN now() ELSE NULL END,now(),now())
                    """, UUID.randomUUID(), tenantId, status + "@example.test", status, token, status);
            jdbc.update("INSERT INTO " + schema + ".demo_invites"
                    + " (id,tenant_id,email,status,token,expires_at,accepted_at,created_at)"
                    + " VALUES (?,?,'demo@example.test',?,?,now()+interval '1 day',"
                    + " CASE WHEN ? = 'ACCEPTED' THEN now() ELSE NULL END,now())",
                    UUID.randomUUID(), tenantId, status, token, status);
        }
        UUID configId = UUID.randomUUID();
        jdbc.update("INSERT INTO " + schema + ".aws_discovery_configs"
                + " (id,tenant_id,auth_type,enabled,auto_sync_enabled,interval_minutes,regions_json,resource_types_json,"
                + "source_system,created_at,updated_at,external_id)"
                + " VALUES (?,?,'CROSS_ACCOUNT_ROLE',true,true,60,'[]','[]','AWS',now(),now(),'legacy-caller-id')",
                configId, tenantId);
        jdbc.update("INSERT INTO " + schema + ".aws_discovery_targets"
                + " (id,tenant_id,config_id,enabled,regions_json,resource_types_json,created_at,updated_at)"
                + " VALUES (?,?,?,true,'[]','[]',now(),now())", UUID.randomUUID(), tenantId, configId);
        for (String provider : new String[]{"AWS", "AZURE"}) {
            jdbc.update("INSERT INTO " + schema + ".ai_security_connector_configs"
                    + " (id,tenant_id,provider,account_id,enabled) VALUES (?,?,?,'123456789012',true)",
                    UUID.randomUUID(), tenantId, provider);
        }

        platform("2").migrate();
        tenant(schema, tenantId, "3").migrate();
        // Re-running through the ordinary Flyway catalog must be harmless.
        platform("2").migrate();
        tenant(schema, tenantId, "3").migrate();

        String expectedHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(raw.getBytes(StandardCharsets.UTF_8)));
        for (String table : new String[]{"platform.tenant_user_invites", schema + ".demo_invites"}) {
            Map<String, Object> retired = jdbc.queryForMap("SELECT token,token_hash,status,expires_at <= now() AS expired"
                    + " FROM " + table + " WHERE token_hash = ?", expectedHash);
            assertNull(retired.get("token"));
            assertEquals("EXPIRED", retired.get("status"));
            assertEquals(true, retired.get("expired"));
            assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM " + table
                    + " WHERE status='ACCEPTED' AND accepted_at IS NOT NULL AND token IS NULL", Integer.class));
        }
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM " + schema
                + ".aws_discovery_configs WHERE enabled OR auto_sync_enabled OR credential_binding_version<>0", Integer.class));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM " + schema
                + ".aws_discovery_targets WHERE enabled OR credential_binding_version<>0", Integer.class));
        assertFalse(jdbc.queryForObject("SELECT enabled FROM " + schema
                + ".ai_security_connector_configs WHERE provider='AWS'", Boolean.class));
        assertTrue(jdbc.queryForObject("SELECT enabled FROM " + schema
                + ".ai_security_connector_configs WHERE provider='AZURE'", Boolean.class));
        // The schema itself rejects a raw bearer value even if a stale writer runs.
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
             var statement = connection.prepareStatement("UPDATE platform.tenant_user_invites SET token=?")) {
            statement.setString(1, raw);
            assertThrows(SQLException.class, statement::executeUpdate);
        }
    }

    private Flyway platform(String target) {
        return Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .locations("classpath:db/migration/postgres_reset").defaultSchema("public")
                .target(target).load();
    }

    private Flyway tenant(String schema, UUID tenantId, String target) {
        return Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .locations("classpath:db/migration/tenant").defaultSchema(schema).schemas(schema)
                .table("tenant_schema_history").target(target)
                .placeholders(Map.of("tenantSchema", schema, "tenantId", tenantId.toString()))
                .callbacks(new TenantSearchPathFlywayCallback(schema)).load();
    }
}
