package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class ProductionBootstrapCliPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("production_bootstrap_cli_final");
    private static final String RUNTIME_USERNAME = "scout_runtime_bootstrap_it";
    private static final String RUNTIME_PASSWORD = "scout-runtime-bootstrap-it-" + UUID.randomUUID();
    private static final String PLATFORM_OWNER_EMAIL = "bootstrap-owner@example.test";
    private static final int TENANT_TARGET_VERSION = PackagedMigrationCatalog.resolve().tenantTarget();

    @Test
    void cleanDatabaseBootstrapsProvisionsTenantAndRerunsIdempotently() throws Exception {
        UUID tenantId = UUID.randomUUID();
        withBootstrapProperties(() -> {
            ProductionBootstrapCli.main(new String[0]);
            insertProvisioningTenant(tenantId, "tenant_bootstrap_customer");
            ProductionBootstrapCli.main(new String[0]);
            ProductionBootstrapCli.main(new String[0]);
            set("BOOTSTRAP_REPORT_ONLY", "true");
            try {
                ProductionBootstrapCli.main(new String[0]);
            } finally {
                clear("BOOTSTRAP_REPORT_ONLY");
            }
        });

        assertEquals(PackagedMigrationCatalog.resolve().platformTarget(), queryInt("""
                select max(version::integer)
                from public.flyway_schema_history
                where version ~ '^[0-9]+$' and success
                """));
        assertEquals(1, queryInt("""
                select count(*)
                from platform.tenants
                where name = 'SG Internal'
                  and schema_name = 'tenant_default'
                  and status = 'ACTIVE'
                """));
        assertEquals(1, queryInt("""
                select count(*)
                from platform.tenant_schema_versions
                where schema_name = 'tenant_default'
                  and status = 'CURRENT'
                  and current_version = %d
                  and last_successful_version = %d
                  and nullif(structural_checksum, '') is not null
                """.formatted(TENANT_TARGET_VERSION, TENANT_TARGET_VERSION)));
        assertEquals(1, queryInt("""
                select count(*)
                from platform.app_users u
                join platform.app_user_global_roles r on r.app_user_id = u.id
                where lower(u.email) = lower(?)
                  and u.external_subject = ?
                  and u.platform_owner
                  and u.status = 'ACTIVE'
                  and r.role = 'PLATFORM_OWNER'
                """, PLATFORM_OWNER_EMAIL, PLATFORM_OWNER_EMAIL));
        assertEquals(1, queryInt("""
                select count(*)
                from tenant_default.tenant_schema_history
                where version = '%d' and success
                """.formatted(TENANT_TARGET_VERSION)));
        assertTrue(queryInt("""
                select count(*)
                from pg_roles
                where rolname = 'scout_runtime_bootstrap_it'
                  and rolcanlogin
                  and not rolinherit
                  and not rolsuper
                  and not rolcreatedb
                  and not rolcreaterole
                  and not rolbypassrls
                """) >= 1);
        assertEquals(1, queryInt("""
                select count(*)
                from platform.tenants
                where id = ? and status = 'ACTIVE'
                """, tenantId));
        assertEquals(1, queryInt("""
                select count(*)
                from platform.tenant_schema_versions customer
                join platform.tenant_schema_versions template
                  on template.schema_name = 'tenant_default'
                where customer.tenant_id = ?
                  and customer.status = 'CURRENT'
                  and customer.current_version = %d
                  and customer.structural_checksum = template.structural_checksum
                """.formatted(TENANT_TARGET_VERSION), tenantId));
        assertEquals(0, queryInt("""
                select count(*)
                from pg_constraint con
                join pg_class rel on rel.oid = con.conrelid
                join pg_namespace source_ns on source_ns.oid = rel.relnamespace
                join pg_class referenced on referenced.oid = con.confrelid
                join pg_namespace referenced_ns on referenced_ns.oid = referenced.relnamespace
                where source_ns.nspname = 'tenant_bootstrap_customer'
                  and referenced_ns.nspname = 'tenant_default'
                """));
        assertEquals(0, queryInt("""
                select count(*)
                from information_schema.columns
                where table_schema = 'tenant_bootstrap_customer'
                  and column_default like '%tenant_default.%'
                """));
        assertEquals(0, queryInt("""
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = 'tenant_bootstrap_customer'
                  and c.relkind in ('r', 'p')
                  and c.relname not in ('tenant_schema_history', 'flyway_schema_history', 'demo_requests')
                  and (not c.relrowsecurity or not c.relforcerowsecurity
                       or not exists (
                           select 1 from pg_policy p
                           where p.polrelid = c.oid and p.polname = 'tenant_isolation'
                       ))
                """));

        verifyRuntimeIsolation(tenantId);
        verifyRuntimeCoverageLedger();
        UUID vulnerabilityId = verifyRuntimePlatformObservationRead();
        verifyRuntimeCatalogPolicyIsolation(tenantId, vulnerabilityId);
    }

    private void withBootstrapProperties(ThrowingRunnable runnable) throws Exception {
        set("DB_URL", DATABASE.url());
        set("DB_USERNAME", DATABASE.username());
        set("DB_PASSWORD", DATABASE.password());
        set("RUNTIME_DB_USERNAME", RUNTIME_USERNAME);
        set("RUNTIME_DB_PASSWORD", RUNTIME_PASSWORD);
        set("APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED", "true");
        set("SG_INTERNAL_ADMIN_EMAIL", "internal-admin@example.test");
        set("APP_CREDENTIAL_ENCRYPTION_KEY", java.util.Base64.getEncoder().encodeToString(new byte[32]));
        set("APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EMAIL", PLATFORM_OWNER_EMAIL);
        set("APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_DISPLAY_NAME", "Bootstrap Owner");
        try {
            runnable.run();
        } finally {
            clear("DB_URL");
            clear("DB_USERNAME");
            clear("DB_PASSWORD");
            clear("RUNTIME_DB_USERNAME");
            clear("RUNTIME_DB_PASSWORD");
            clear("APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED");
            clear("SG_INTERNAL_ADMIN_EMAIL");
            clear("APP_CREDENTIAL_ENCRYPTION_KEY");
            clear("APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EMAIL");
            clear("APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_DISPLAY_NAME");
            clear("BOOTSTRAP_REPORT_ONLY");
        }
    }

    private void insertProvisioningTenant(UUID tenantId, String schemaName) throws Exception {
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
             var statement = connection.prepareStatement("""
                     insert into platform.tenants (
                         id, name, slug, schema_name, status, plan_code,
                         created_at, updated_at, max_connector_count,
                         max_service_account_count, max_daily_sbom_uploads,
                         max_export_rows, max_daily_exposure_refreshes
                     ) values (?, ?, ?, ?, 'PROVISIONING',
                               'ENTERPRISE', now(), now(), 10, 25, 100, 50000, 25)
                     """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, "Bootstrap Customer " + schemaName);
            statement.setString(3, "bootstrap-" + schemaName.replace('_', '-'));
            statement.setString(4, schemaName);
            statement.executeUpdate();
        }
    }

    private String quotedIdentifier(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private void setTenantStatus(UUID tenantId, String status) throws SQLException {
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
             var statement = connection.prepareStatement("update platform.tenants set status = ? where id = ?")) {
            statement.setString(1, status);
            statement.setObject(2, tenantId);
            statement.executeUpdate();
        }
    }

    private void verifyRuntimeIsolation(UUID tenantId) throws Exception {
        UUID assetId = UUID.randomUUID();
        try (Connection owner = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password())) {
            setTenantContext(owner, tenantId);
            try (var statement = owner.prepareStatement("""
                    insert into tenant_bootstrap_customer.assets (
                        id, business_criticality, created_at, identifier, name, state, type, tenant_id
                    ) values (?, 'HIGH', now(), 'bootstrap-asset', 'Bootstrap Asset',
                              'ACTIVE', 'HOST', ?)
                    """)) {
                statement.setObject(1, assetId);
                statement.setObject(2, tenantId);
                statement.executeUpdate();
            }
        }

        try (Connection runtime = DriverManager.getConnection(DATABASE.url(), RUNTIME_USERNAME, RUNTIME_PASSWORD);
             Statement statement = runtime.createStatement()) {
            statement.execute("select set_config('search_path', 'tenant_bootstrap_customer,platform', false)");
            setTenantContext(runtime, tenantId);
            assertEquals(1, countAsset(runtime, assetId));

            setTenantContext(runtime, UUID.randomUUID());
            assertEquals(0, countAsset(runtime, assetId));
            SQLException crossTenantWrite = assertThrows(SQLException.class, () -> {
                try (var insert = runtime.prepareStatement("""
                    insert into assets (
                        id, business_criticality, created_at, identifier, name, state, type, tenant_id
                    ) values (?, 'HIGH', now(), 'cross-tenant', 'Cross Tenant',
                              'ACTIVE', 'HOST', ?)
                    """)) {
                    insert.setObject(1, UUID.randomUUID());
                    insert.setObject(2, tenantId);
                    insert.executeUpdate();
                }
            });
            assertEquals("42501", crossTenantWrite.getSQLState());
        }
    }

    private void verifyRuntimeCoverageLedger() throws Exception {
        UUID runId = UUID.randomUUID();
        String scope = "nvd:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        java.time.Instant from = java.time.Instant.parse("2026-01-01T00:00:00Z");
        java.time.Instant to = from.plusSeconds(3 * 86400L);
        try (Connection runtime = DriverManager.getConnection(DATABASE.url(), RUNTIME_USERNAME, RUNTIME_PASSWORD)) {
            try (var insert = runtime.prepareStatement("""
                    insert into platform.sync_runs
                      (id, records_failed, records_fetched, records_inserted, records_updated,
                       run_scope, started_at, status, sync_type)
                    values (?, 0, 0, 0, 0, 'PLATFORM', now(), 'completed', 'NVD')
                    """)) {
                insert.setObject(1, runId);
                assertEquals(1, insert.executeUpdate());
            }
            try (var insert = runtime.prepareStatement("""
                    insert into platform.feed_coverage_observations
                      (run_id, source_system, feed_key, interval_start, interval_end, fetched_records, ids_recorded_at)
                    values (?, 'nvd', ?, ?, ?, 1, now())
                    """)) {
                insert.setObject(1, runId);
                insert.setString(2, scope);
                insert.setObject(3, java.sql.Timestamp.from(from));
                insert.setObject(4, java.sql.Timestamp.from(from.plusSeconds(86400L)));
                assertEquals(1, insert.executeUpdate());
            }
            try (var insert = runtime.prepareStatement("""
                    insert into platform.nvd_observed_interval_ids
                      (run_id, interval_start, interval_end, cve_id)
                    values (?, ?, ?, 'CVE-2026-12345')
                    """)) {
                insert.setObject(1, runId);
                insert.setObject(2, java.sql.Timestamp.from(from));
                insert.setObject(3, java.sql.Timestamp.from(from.plusSeconds(86400L)));
                assertEquals(1, insert.executeUpdate());
            }
            try (var read = runtime.prepareStatement("""
                    select count(*) from platform.feed_coverage_observations o
                    join platform.nvd_observed_interval_ids ids
                      on ids.run_id=o.run_id and ids.interval_start=o.interval_start
                      and ids.interval_end=o.interval_end
                    where o.run_id = ? and o.feed_key = ? and o.fetched_records = 1
                      and o.ids_recorded_at is not null and ids.cve_id='CVE-2026-12345'
                    """)) {
                read.setObject(1, runId);
                read.setString(2, scope);
                try (ResultSet result = read.executeQuery()) {
                    result.next();
                    assertEquals(1, result.getInt(1));
                }
            }
        }
        var dataSource = new org.springframework.jdbc.datasource.DriverManagerDataSource(
                DATABASE.url(), RUNTIME_USERNAME, RUNTIME_PASSWORD);
        var diagnostic = new com.prototype.vulnwatch.service.vulningestion.NvdObservedGapsService(
                new org.springframework.jdbc.core.JdbcTemplate(dataSource));
        var scopes = diagnostic.scopes(null);
        assertEquals(1, scopes.items().size());
        assertEquals(scope, scopes.items().get(0).feedKey());
        assertEquals(1, scopes.items().get(0).observedWindowCount());
        var gaps = diagnostic.inspect(scope, from, to);
        assertEquals(1, gaps.observedWindowCount());
        assertEquals("UNKNOWN", gaps.historicalCoverageStatus());
        assertEquals(java.util.List.of(new com.prototype.vulnwatch.dto.NvdObservedGapsResponse.Interval(
                from.plusSeconds(86400L), to)), gaps.unobservedIntervals());
    }

    private UUID verifyRuntimePlatformObservationRead() throws Exception {
        UUID vulnerabilityId = UUID.randomUUID();
        UUID observationId = UUID.randomUUID();
        try (Connection owner = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password())) {
            try (var insert = owner.prepareStatement("""
                    insert into platform.vulnerabilities
                      (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                    values (?, ?, 'NVD', 'Bootstrap observation', 'HIGH', false, now(), now())
                    """)) {
                insert.setObject(1, vulnerabilityId);
                insert.setString(2, "CVE-2098-" + vulnerabilityId.toString().substring(0, 8).toUpperCase());
                assertEquals(1, insert.executeUpdate());
            }
            try (var insert = owner.prepareStatement("""
                    insert into platform.vulnerability_intel_observations
                      (id, vulnerability_id, source_system, source_record_id, description,
                       raw_payload, payload_hash, observed_at, last_seen_at, created_at, updated_at)
                    values (?, ?, 'nvd', ?, 'Public fixture description',
                            'private bootstrap payload', 'fixture-fingerprint', now(), now(), now(), now())
                    """)) {
                insert.setObject(1, observationId);
                insert.setObject(2, vulnerabilityId);
                insert.setString(3, "bootstrap-" + observationId);
                assertEquals(1, insert.executeUpdate());
            }
        }
        try (Connection runtime = DriverManager.getConnection(DATABASE.url(), RUNTIME_USERNAME, RUNTIME_PASSWORD);
             Statement statement = runtime.createStatement()) {
            statement.execute("select set_config('search_path', 'pg_catalog', false)");
            try (var read = runtime.prepareStatement("""
                    select id, source_system, source_record_id, description, observed_at,
                           last_seen_at, payload_hash
                    from platform.vulnerability_intel_observations
                    where vulnerability_id = ? and (cast(? as uuid) is null or id > cast(? as uuid))
                    order by id limit 2
                    """)) {
                read.setObject(1, vulnerabilityId);
                read.setNull(2, java.sql.Types.OTHER);
                read.setNull(3, java.sql.Types.OTHER);
                try (ResultSet result = read.executeQuery()) {
                    assertTrue(result.next());
                    assertEquals(observationId, result.getObject("id", UUID.class));
                    assertEquals("fixture-fingerprint", result.getString("payload_hash"));
                    assertEquals(7, result.getMetaData().getColumnCount());
                    assertTrue(!result.next());
                }
            }
        }
        return vulnerabilityId;
    }

    private void verifyRuntimeCatalogPolicyIsolation(UUID tenantId, UUID vulnerabilityId) throws Exception {
        try (Connection runtime = DriverManager.getConnection(DATABASE.url(), RUNTIME_USERNAME, RUNTIME_PASSWORD)) {
            setTenantContext(runtime, tenantId);
            try (var insert = runtime.prepareStatement("""
                    insert into tenant_bootstrap_customer.intelligence_catalog_policy_versions
                      (tenant_id, version, policy_json, policy_sha256)
                    values (?, 1, '{}'::jsonb, repeat('a', 64))
                    """)) {
                insert.setObject(1, tenantId);
                assertEquals(1, insert.executeUpdate());
            }
            assertEquals(1, countCatalogPolicies(runtime));
            UUID buildId = UUID.randomUUID();
            try (var insert = runtime.prepareStatement("""
                    insert into tenant_bootstrap_customer.intelligence_catalog_builds
                      (tenant_id, id, policy_version, generation, override_state, source_state, status)
                    values (?, ?, 1, 1, 'test-override-state', 'test-source-state', 'QUEUED')
                    """)) {
                insert.setObject(1, tenantId);
                insert.setObject(2, buildId);
                assertEquals(1, insert.executeUpdate());
            }
            assertEquals(1, countCatalogBuilds(runtime));
            try (var insert = runtime.prepareStatement("""
                    insert into tenant_bootstrap_customer.intelligence_catalog_members
                      (tenant_id, build_id, vulnerability_id, reason)
                    values (?, ?, ?, 'POLICY')
                    """)) {
                insert.setObject(1, tenantId);
                insert.setObject(2, buildId);
                insert.setObject(3, vulnerabilityId);
                assertEquals(1, insert.executeUpdate());
            }
            assertEquals(1, countCatalogMembers(runtime));
            setTenantContext(runtime, UUID.randomUUID());
            assertEquals(0, countCatalogPolicies(runtime));
            assertEquals(0, countCatalogBuilds(runtime));
            assertEquals(0, countCatalogMembers(runtime));
            SQLException crossTenantWrite = assertThrows(SQLException.class, () -> {
                try (var insert = runtime.prepareStatement("""
                        insert into tenant_bootstrap_customer.intelligence_catalog_policy_versions
                          (tenant_id, version, policy_json, policy_sha256)
                        values (?, 2, '{}'::jsonb, repeat('b', 64))
                        """)) {
                    insert.setObject(1, tenantId);
                    insert.executeUpdate();
                }
            });
            assertEquals("42501", crossTenantWrite.getSQLState());
            SQLException crossTenantMember = assertThrows(SQLException.class, () -> {
                try (var insert = runtime.prepareStatement("""
                        insert into tenant_bootstrap_customer.intelligence_catalog_members
                          (tenant_id, build_id, vulnerability_id, reason)
                        values (?, ?, ?, 'POLICY')
                        """)) {
                    insert.setObject(1, tenantId);
                    insert.setObject(2, buildId);
                    insert.setObject(3, UUID.randomUUID());
                    insert.executeUpdate();
                }
            });
            assertEquals("42501", crossTenantMember.getSQLState());
        }
    }

    private int countCatalogPolicies(Connection connection) throws SQLException {
        try (var statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select count(*) from tenant_bootstrap_customer.intelligence_catalog_policy_versions")) {
            result.next();
            return result.getInt(1);
        }
    }

    private int countCatalogBuilds(Connection connection) throws SQLException {
        try (var statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select count(*) from tenant_bootstrap_customer.intelligence_catalog_builds")) {
            result.next();
            return result.getInt(1);
        }
    }

    private int countCatalogMembers(Connection connection) throws SQLException {
        try (var statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select count(*) from tenant_bootstrap_customer.intelligence_catalog_members")) {
            result.next();
            return result.getInt(1);
        }
    }

    private void setTenantContext(Connection connection, UUID tenantId) throws SQLException {
        try (var statement = connection.prepareStatement(
                "select set_config('app.current_tenant_id', ?, false)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private int countAsset(Connection connection, UUID assetId) throws SQLException {
        try (var statement = connection.prepareStatement("select count(*) from assets where id = ?")) {
            statement.setObject(1, assetId);
            try (ResultSet resultSet = statement.executeQuery()) {
                resultSet.next();
                return resultSet.getInt(1);
            }
        }
    }

    private int queryInt(String sql, Object... params) throws Exception {
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
             var statement = connection.prepareStatement(sql)) {
            for (int index = 0; index < params.length; index++) {
                statement.setObject(index + 1, params[index]);
            }
            try (ResultSet resultSet = statement.executeQuery()) {
                resultSet.next();
                return resultSet.getInt(1);
            }
        }
    }

    private void set(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }

    private void clear(String key) {
        System.clearProperty(key);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
