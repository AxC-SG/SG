package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/** Exercises the real standalone bootstrap, with database faults before activation. */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class BootstrapFailureRecoveryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("phase3_bootstrap_failure");

    @Test void failedSchemaGrantLeavesTenantInaccessibleAndExplicitRetryActivatesAfterGrants() throws Exception {
        String role = "bootstrap_failure_" + UUID.randomUUID().toString().replace("-", "");
        Map<String, String> config = new LinkedHashMap<>();
        config.put("DB_URL", DB.url()); config.put("DB_USERNAME", DB.username());
        config.put("DB_PASSWORD", DB.password()); config.put("RUNTIME_DB_USERNAME", role);
        config.put("RUNTIME_DB_PASSWORD", UUID.randomUUID().toString());
        config.put("APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED", "false");
        config.put("PLATFORM_OWNER_SETUP_LINK_ENABLED", "false");
        config.put("BOOTSTRAP_REPORT_ONLY", "false");
        Map<String, String> previous = new HashMap<>();
        config.forEach((key, value) -> { previous.put(key, System.getProperty(key)); System.setProperty(key, value); });
        try (Connection owner = DriverManager.getConnection(DB.url(), DB.username(), DB.password());
             Statement sql = owner.createStatement()) {
            ProductionBootstrapCli.main(new String[0]);
            sql.execute("""
                    insert into platform.tenants(id,name,slug,schema_name,status,plan_code,created_at,updated_at,
                      max_connector_count,max_service_account_count,max_daily_sbom_uploads,max_export_rows,max_daily_exposure_refreshes)
                    values (gen_random_uuid(),'Grant failure fixture','grant-failure','tenant_grant_failure','PROVISIONING',
                      'ENTERPRISE',now(),now(),10,25,100,50000,25)
                    """);
            sql.execute("""
                    create function public.reject_fixture_grant() returns event_trigger language plpgsql as $$
                    begin
                      if tg_tag='GRANT' and current_query() like '%tenant_grant_failure%' then
                        raise exception 'injected runtime grant failure';
                      end if;
                    end $$
                    """);
            sql.execute("create event trigger reject_fixture_grant on ddl_command_start execute function public.reject_fixture_grant()");
            try {
                assertThrows(Exception.class, () -> ProductionBootstrapCli.main(new String[0]));
                assertEquals("PROVISIONING_FAILED", scalar(sql, "select status from platform.tenants where slug='grant-failure'"));
                assertEquals("PROVISIONING_FAILED", scalar(sql, "select status from platform.tenant_schema_versions where schema_name='tenant_grant_failure'"));
                assertEquals("false", scalar(sql, "select has_table_privilege('" + role + "','tenant_grant_failure.findings','SELECT')::text"));
            } finally {
                sql.execute("drop event trigger reject_fixture_grant");
                sql.execute("drop function public.reject_fixture_grant()");
            }
            // This is the existing explicit operator retry, not automatic reactivation.
            sql.execute("update platform.tenants set status='PROVISIONING' where slug='grant-failure'");
            sql.execute("""
                    create function public.verify_fixture_activation() returns trigger language plpgsql as $$
                    begin
                      if new.slug='grant-failure' and new.status='ACTIVE'
                        and not has_table_privilege('%s','tenant_grant_failure.findings','SELECT,INSERT,UPDATE,DELETE') then
                        raise exception 'activation preceded runtime grants';
                      end if;
                      return new;
                    end $$
                    """.formatted(role));
            sql.execute("create trigger verify_fixture_activation before update on platform.tenants for each row execute function public.verify_fixture_activation()");
            ProductionBootstrapCli.main(new String[0]);
            assertEquals("ACTIVE", scalar(sql, "select status from platform.tenants where slug='grant-failure'"));
            assertEquals("CURRENT", scalar(sql, "select status from platform.tenant_schema_versions where schema_name='tenant_grant_failure'"));
            for (String privilege : List.of("SELECT", "INSERT", "UPDATE", "DELETE")) {
                assertEquals("true", scalar(sql, "select has_table_privilege('" + role + "','tenant_grant_failure.findings','" + privilege + "')::text"));
            }

            sql.execute("""
                    create function public.reject_report_ddl() returns event_trigger language plpgsql as $$
                    begin raise exception 'report-only attempted DDL'; end $$
                    """);
            sql.execute("create event trigger reject_report_ddl on ddl_command_start execute function public.reject_report_ddl()");
            try {
                System.setProperty("BOOTSTRAP_REPORT_ONLY", "true");
                ProductionBootstrapCli.main(new String[0]);
            } finally {
                // Disabling an event trigger is itself DDL; suppress the trigger via session role.
                sql.execute("set session_replication_role=replica");
                sql.execute("drop event trigger reject_report_ddl");
                sql.execute("set session_replication_role=origin");
                sql.execute("drop function public.reject_report_ddl()");
            }
        } finally {
            previous.forEach((key, value) -> { if (value == null) System.clearProperty(key); else System.setProperty(key, value); });
        }
    }

    private String scalar(Statement sql, String query) throws SQLException {
        try (ResultSet rows = sql.executeQuery(query)) { assertTrue(rows.next()); return rows.getString(1); }
    }
}
