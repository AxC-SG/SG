package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/** Verifies the fresh V1 lifecycle defaults, tenant parity, and reconciliation constraints. */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiBomLifecycleBaselinePostgresIntegrationTest {

    private static final String UPGRADE_TENANT_ID = "e5fe0d29-1d64-4175-8ce6-c34f42b214cc";
    private static final String FRESH_TENANT_ID = "00000000-0000-4000-8000-000000000404";
    private static final String ASSET_ID = "00000000-0000-0000-0000-0000000004a1";
    private static final String UPLOAD_ID = "00000000-0000-0000-0000-0000000004b1";
    private static final String COMPONENT_ID = "00000000-0000-0000-0000-0000000004c1";
    private static final String BOM_RECORD_ID = "00000000-0000-0000-0000-0000000004aa";
    private static final String CBOM_COMPONENT_ID = "00000000-0000-0000-0000-0000000004d1";
    private static final String CBOM_FINDING_ID = "00000000-0000-0000-0000-0000000004e1";
    private static final String SOURCE_ID = "00000000-0000-0000-0000-0000000004f1";
    // Separate databases keep the defaults and constraint fixtures independent.
    private static final LocalPostgresTestDatabase.DatabaseConfig UPGRADE_DB =
            LocalPostgresTestDatabase.provision("ai_bom_lifecycle_v4_upgrade");
    private static final LocalPostgresTestDatabase.DatabaseConfig CONSTRAINT_DB =
            LocalPostgresTestDatabase.provision("ai_bom_lifecycle_v4_constraints");


    @Test void v1UpgradeAndFreshTenantReceiveCorrelationEvidenceWithoutChangingV1() throws Exception {
        var db = LocalPostgresTestDatabase.provision("ai_bom_correlation_v2_upgrade");
        platform(db).migrate();
        registerTenant(db, FRESH_TENANT_ID, "tenant_fresh");
        tenant(db, "tenant_default", UPGRADE_TENANT_ID, "1").migrate();
        int checksum = queryInt(db, "select checksum from tenant_default.tenant_schema_history where version='1'");
        tenant(db, "tenant_default", UPGRADE_TENANT_ID, "2").migrate();
        tenant(db, "tenant_fresh", FRESH_TENANT_ID, "2").migrate();
        assertEquals(checksum, queryInt(db, "select checksum from tenant_default.tenant_schema_history where version='1'"));
        for (String schema : java.util.List.of("tenant_default", "tenant_fresh")) {
            assertEquals(2, queryInt(db, "select count(*) from information_schema.tables where table_schema='" + schema
                    + "' and table_name in ('ai_bom_correlation_paths','ai_bom_correlation_gaps')"));
            assertEquals(2, queryInt(db, "select count(*) from pg_class c join pg_namespace n on c.relnamespace=n.oid where n.nspname='"
                    + schema + "' and c.relname in ('ai_bom_correlation_paths','ai_bom_correlation_gaps') and c.relrowsecurity and c.relforcerowsecurity"));
            assertEquals(1, queryInt(db, "select count(*) from information_schema.table_constraints where table_schema='" + schema
                    + "' and table_name='ai_bom_resource_vulnerability_links' and constraint_type='UNIQUE'"));
        }
    }

    @Test
    void baselineDefaultsPreserveEvidenceAndMatchAcrossTenants() throws Exception {
        platform(UPGRADE_DB).migrate();
        registerTenant(UPGRADE_DB, FRESH_TENANT_ID, "tenant_fresh");
        tenant(UPGRADE_DB, "tenant_default", UPGRADE_TENANT_ID, "1").migrate();
        seedLegacyInventory(UPGRADE_DB);
        seedLegacyCbomFinding(UPGRADE_DB);

        tenant(UPGRADE_DB, "tenant_default", UPGRADE_TENANT_ID, "1").migrate();
        tenant(UPGRADE_DB, "tenant_fresh", FRESH_TENANT_ID, "1").migrate();

        assertEquals(4, queryInt(UPGRADE_DB, """
                select count(*) from information_schema.tables
                 where table_schema='tenant_default' and table_name in
                     ('bom_sources','bom_source_completeness_assertions',
                      'bom_component_contributions','bom_asset_backfill_state')
                """), "all four lifecycle tables should exist");

        // A component that predates the migration has no contribution rows. It must be
        // LEGACY_UNKNOWN, never absent: "missing contribution rows cannot justify retirement".
        assertEquals("LEGACY_UNKNOWN",
                queryTextAsTenant(UPGRADE_DB, "select bom_evidence_state from tenant_default.inventory_components where id='"
                        + COMPONENT_ID + "'"),
                "baseline components must not be readable as absent");
        assertEquals("ACTIVE",
                queryTextAsTenant(UPGRADE_DB, "select component_status from tenant_default.inventory_components where id='"
                        + COMPONENT_ID + "'"),
                "repeat migration must not disturb component presence");

        // CBOM keeps its own store; it gains the evidence lifecycle without its existing
        // resolution being touched.
        assertEquals("SUPPORTED",
                queryTextAsTenant(UPGRADE_DB, "select evidence_state from tenant_default.cbom_risk_findings where id='"
                        + CBOM_FINDING_ID + "'"));
        assertEquals("RESOLVED",
                queryTextAsTenant(UPGRADE_DB, "select status from tenant_default.cbom_risk_findings where id='"
                        + CBOM_FINDING_ID + "'"),
                "withdrawal columns must not alter existing finding status");
        assertNull(queryTextAsTenant(UPGRADE_DB, "select withdrawn_at from tenant_default.cbom_risk_findings where id='"
                        + CBOM_FINDING_ID + "'"),
                "an untouched finding has not been withdrawn");

        assertEquals("PARTIAL",
                queryTextAsTenant(UPGRADE_DB, "select completeness from tenant_default.bom_ingestion_records where id='"
                        + BOM_RECORD_ID + "'"),
                "a pre-existing document version defaults to PARTIAL, never claiming completeness");

        try (Connection connection = connection(UPGRADE_DB)) {
            assertEquals(TenantSchemaFingerprint.of(connection, "tenant_fresh"),
                    TenantSchemaFingerprint.of(connection, "tenant_default"),
                    "tenant schemas must be structurally identical");
        }
    }

    @Test
    void constraintsRejectTheStatesTheReconciliationRulesForbid() throws Exception {
        platform(CONSTRAINT_DB).migrate();
        tenant(CONSTRAINT_DB, "tenant_default", UPGRADE_TENANT_ID, "1").migrate();
        seedLegacyInventory(CONSTRAINT_DB);
        execute(CONSTRAINT_DB, """
                insert into tenant_default.bom_sources (id,tenant_id,bom_type,asset_id,completeness,state)
                values ('%s','%s','SBOM','%s','PARTIAL','ACTIVE')
                """.formatted(SOURCE_ID, UPGRADE_TENANT_ID, ASSET_ID));

        // A CBOM describes cryptographic assets and can never assert software completeness.
        assertThrows(SQLException.class, () -> execute(CONSTRAINT_DB, """
                insert into tenant_default.bom_sources (id,tenant_id,bom_type,completeness,state)
                values ('00000000-0000-0000-0000-00000000f001','%s','CBOM','COMPLETE_ASSET_SOFTWARE','ACTIVE')
                """.formatted(UPGRADE_TENANT_ID)));

        // Withdrawal is audited: the state and its timestamp cannot disagree.
        assertThrows(SQLException.class, () -> insertContribution(CONSTRAINT_DB, "00000000-0000-0000-0000-00000000f002",
                "WITHDRAWN", "null", "false"));

        // Authoritative absence is a withdrawal outcome, never a standing supported claim.
        assertThrows(SQLException.class, () -> insertContribution(CONSTRAINT_DB, "00000000-0000-0000-0000-00000000f003",
                "SUPPORTED", "null", "true"));

        // The legitimate shape still inserts.
        insertContribution(CONSTRAINT_DB, "00000000-0000-0000-0000-00000000f004", "SUPPORTED", "null", "false");
        assertEquals(1, queryIntAsTenant(CONSTRAINT_DB,
                "select count(*) from tenant_default.bom_component_contributions where contribution_state='SUPPORTED'"));

        // source_key is uniquely indexed only where present. An automated caller must
        // resolve back to one source, while manual uploads leave the key null and any
        // number of them may coexist for the same asset.
        execute(CONSTRAINT_DB, """
                insert into tenant_default.bom_sources (id,tenant_id,bom_type,source_key,completeness,state)
                values ('00000000-0000-0000-0000-00000000f101','%s','SBOM','github-repo:SBOM:acme/widget','PARTIAL','ACTIVE')
                """.formatted(UPGRADE_TENANT_ID));
        assertThrows(SQLException.class, () -> execute(CONSTRAINT_DB, """
                insert into tenant_default.bom_sources (id,tenant_id,bom_type,source_key,completeness,state)
                values ('00000000-0000-0000-0000-00000000f102','%s','SBOM','github-repo:SBOM:acme/widget','PARTIAL','ACTIVE')
                """.formatted(UPGRADE_TENANT_ID)), "a duplicate source_key must be rejected");

        execute(CONSTRAINT_DB, """
                insert into tenant_default.bom_sources (id,tenant_id,bom_type,asset_id,completeness,state)
                values ('00000000-0000-0000-0000-00000000f103','%s','SBOM','%s','PARTIAL','ACTIVE')
                """.formatted(UPGRADE_TENANT_ID, ASSET_ID));
        execute(CONSTRAINT_DB, """
                insert into tenant_default.bom_sources (id,tenant_id,bom_type,asset_id,completeness,state)
                values ('00000000-0000-0000-0000-00000000f104','%s','SBOM','%s','PARTIAL','ACTIVE')
                """.formatted(UPGRADE_TENANT_ID, ASSET_ID));
        // Three: the SBOM source seeded at the top of this test, plus the two just added.
        assertEquals(3, queryIntAsTenant(CONSTRAINT_DB,
                "select count(*) from tenant_default.bom_sources where source_key is null and asset_id='"
                        + ASSET_ID + "'"),
                "unnamed uploads for one asset stay independent rather than superseding");
    }

    private void insertContribution(LocalPostgresTestDatabase.DatabaseConfig db, String id, String state, String withdrawnAt, String absence) throws Exception {
        execute(db, """
                insert into tenant_default.bom_component_contributions
                    (id,tenant_id,source_id,bom_id,inventory_component_id,resolved_identity_key,
                     contribution_state,authoritative_absence,withdrawn_at)
                values ('%s','%s','%s','00000000-0000-0000-0000-00000000bbbb','%s','npm|lodash|4.17.20',
                        '%s',%s,%s)
                """.formatted(id, UPGRADE_TENANT_ID, SOURCE_ID, COMPONENT_ID, state, absence, withdrawnAt));
    }

    private void seedLegacyInventory(LocalPostgresTestDatabase.DatabaseConfig db) throws Exception {
        execute(db, """
                insert into tenant_default.assets
                    (id,tenant_id,business_criticality,created_at,identifier,name,state,type)
                values ('%s','%s','MEDIUM',now(),'pkg:npm/legacy-app','legacy-app','ACTIVE','APPLICATION')
                on conflict (id) do nothing
                """.formatted(ASSET_ID, UPGRADE_TENANT_ID));
        execute(db, """
                insert into tenant_default.sbom_uploads
                    (id,tenant_id,format,original_filename,status,uploaded_at)
                values ('%s','%s','CYCLONEDX','legacy.json','SUCCESS',now())
                on conflict (id) do nothing
                """.formatted(UPLOAD_ID, UPGRADE_TENANT_ID));
        execute(db, """
                insert into tenant_default.inventory_components
                    (id,tenant_id,component_status,ecosystem,ingested_at,last_observed_at,
                     package_name,purl,asset_id,sbom_upload_id)
                values ('%s','%s','ACTIVE','npm',now(),now(),'lodash',
                        'pkg:npm/lodash@4.17.20','%s','%s')
                on conflict (id) do nothing
                """.formatted(COMPONENT_ID, UPGRADE_TENANT_ID, ASSET_ID, UPLOAD_ID));
    }

    private void seedLegacyCbomFinding(LocalPostgresTestDatabase.DatabaseConfig db) throws Exception {
        // The CBOM component references a real document version.
        execute(db, """
                insert into tenant_default.bom_ingestion_records
                    (id,tenant_id,bom_type,supplier,status)
                values ('%s','%s','CBOM','legacy-supplier','ACTIVE')
                """.formatted(BOM_RECORD_ID, UPGRADE_TENANT_ID));
        execute(db, """
                insert into tenant_default.cbom_components
                    (id,tenant_id,source_bom_id,component_fingerprint,name,asset_type)
                values ('%s','%s','%s','fp-legacy','rsa-2048','ALGORITHM')
                """.formatted(CBOM_COMPONENT_ID, UPGRADE_TENANT_ID, BOM_RECORD_ID));
        execute(db, """
                insert into tenant_default.cbom_risk_findings
                    (id,tenant_id,cbom_component_id,rule_id,finding_fingerprint,risk_class,
                     severity,title,status,resolved_at)
                values ('%s','%s','%s','CBOM-RULE-1','ff-legacy','QUANTUM_VULNERABLE',
                        'HIGH','Legacy resolved finding','RESOLVED',now())
                """.formatted(CBOM_FINDING_ID, UPGRADE_TENANT_ID, CBOM_COMPONENT_ID));
    }

    private Flyway platform(LocalPostgresTestDatabase.DatabaseConfig db) {
        return Flyway.configure().configuration(java.util.Map.of("flyway.postgresql.transactional.lock", "false")).dataSource(db.url(), db.username(), db.password())
                .defaultSchema("public").locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .validateOnMigrate(true).load();
    }

    private Flyway tenant(LocalPostgresTestDatabase.DatabaseConfig db, String schema, String tenantId, String target) {
        return Flyway.configure().dataSource(db.url(), db.username(), db.password())
                .schemas(schema).defaultSchema(schema).table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(Map.of("tenantSchema", schema, "tenantId", tenantId))
                .target(target).validateOnMigrate(true).load();
    }

    private Connection connection(LocalPostgresTestDatabase.DatabaseConfig db) throws Exception {
        return DriverManager.getConnection(db.url(), db.username(), db.password());
    }

    private void execute(LocalPostgresTestDatabase.DatabaseConfig db, String sql) throws Exception {
        try (Connection connection = connection(db); Statement statement = connection.createStatement()) {
            statement.execute("select set_config('app.current_tenant_id','" + UPGRADE_TENANT_ID + "',false)");
            statement.execute(sql);
        }
    }

    private void registerTenant(LocalPostgresTestDatabase.DatabaseConfig db, String id, String schema) throws Exception {
        try (Connection connection = connection(db); PreparedStatement statement = connection.prepareStatement("""
                insert into platform.tenants (
                    id,created_at,max_connector_count,max_daily_exposure_refreshes,max_daily_sbom_uploads,
                    max_export_rows,max_service_account_count,name,plan_code,schema_name,slug,status,updated_at)
                values (?::uuid,now(),10,10,10,10000,10,'Fresh migration tenant','pilot',?,?,'ACTIVE',now())
                """)) {
            statement.setString(1, id);
            statement.setString(2, schema);
            statement.setString(3, schema.replace('_', '-'));
            statement.executeUpdate();
        }
    }

    private int queryInt(LocalPostgresTestDatabase.DatabaseConfig db, String sql) throws Exception {
        try (Connection connection = connection(db); Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

    // Row-level security hides tenant rows unless app.current_tenant_id is set on the session.
    private int queryIntAsTenant(LocalPostgresTestDatabase.DatabaseConfig db, String sql) throws Exception {
        try (Connection connection = connection(db); Statement statement = connection.createStatement()) {
            statement.execute("select set_config('app.current_tenant_id','" + UPGRADE_TENANT_ID + "',false)");
            try (ResultSet resultSet = statement.executeQuery(sql)) {
                resultSet.next();
                return resultSet.getInt(1);
            }
        }
    }

    private String queryTextAsTenant(LocalPostgresTestDatabase.DatabaseConfig db, String sql) throws Exception {
        try (Connection connection = connection(db); Statement statement = connection.createStatement()) {
            statement.execute("select set_config('app.current_tenant_id','" + UPGRADE_TENANT_ID + "',false)");
            try (ResultSet resultSet = statement.executeQuery(sql)) {
                resultSet.next();
                return resultSet.getString(1);
            }
        }
    }
}
