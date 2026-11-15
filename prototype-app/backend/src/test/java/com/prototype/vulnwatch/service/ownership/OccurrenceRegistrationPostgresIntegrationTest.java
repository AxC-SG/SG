package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Real-PostgreSQL proof for software occurrence subjects (Phase 0B §3.1–§3.4). */
@PostgresIntegrationTest
class OccurrenceRegistrationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_occurrences");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private OwnershipSubjectService subjects;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private OwnershipMaintenanceJob maintenance;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        String slug = "own-occ-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        enter();
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void theJavaAndSqlKeysAgreeWhateverNormalizationTheWriterApplied() {
        UUID host = asset("HOST", null);
        UUID row = component(host, " NPM ", "Lodash ", " 4.17.21", "PKG:NPM/Lodash@4.17.21 ", "ACTIVE");
        String sql = jdbc.queryForObject("SELECT " + OccurrenceKey.SQL + " FROM inventory_components ic WHERE ic.id = ?", String.class, row);
        assertThat(sql).isEqualTo(OccurrenceKey.sourceObjectId("npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"));
    }

    @Test
    void rowsWithTheSameKeyOnOneAssetShareASubjectUnderTheAssetAndOtherAssetsGetTheirOwn() {
        UUID web = asset("HOST", null);
        UUID db = asset("HOST", null);
        UUID first = component(web, "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "ACTIVE");
        UUID duplicate = component(web, "NPM", "Lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "ACTIVE");
        UUID upgraded = component(web, "npm", "lodash", "4.17.22", "pkg:npm/lodash@4.17.22", "ACTIVE");
        UUID elsewhere = component(db, "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "ACTIVE");
        inventory.linkAssets(100);

        assertThat(subjects.registerOccurrences(100)).isEqualTo(4);
        assertThat(subjectOf(first)).isEqualTo(subjectOf(duplicate));
        assertThat(subjectOf(upgraded)).as("a new version is a new occurrence").isNotEqualTo(subjectOf(first));
        assertThat(subjectOf(elsewhere)).isNotEqualTo(subjectOf(first));
        assertThat(jdbc.queryForObject("SELECT context_key FROM ownership_subject WHERE id = ?", String.class, subjectOf(first)))
                .isEqualTo("asset:" + web);
        assertThat(subjects.currentParent(subjectOf(first))).contains(assetSubject(web));
        assertThat(jdbc.queryForObject("SELECT created_by FROM ownership_subject_edge WHERE child_subject_id = ?", String.class, subjectOf(first)))
                .isEqualTo("bom-occurrence-adapter");
        assertThat(subjects.registerOccurrences(100)).as("idempotent").isZero();
    }

    @Test
    void aRetiredComponentThatReappearsKeepsItsSubject() {
        UUID web = asset("HOST", null);
        UUID row = component(web, "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "ACTIVE");
        inventory.linkAssets(100);
        subjects.registerOccurrences(100);
        UUID subject = subjectOf(row);

        jdbc.update("UPDATE inventory_components SET component_status = 'RETIRED', ownership_subject_id = NULL WHERE id = ?", row);
        assertThat(subjects.registerOccurrences(100)).as("retired rows are not registered").isZero();
        jdbc.update("UPDATE inventory_components SET component_status = 'ACTIVE' WHERE id = ?", row);
        subjects.registerOccurrences(100);
        assertThat(subjectOf(row)).isEqualTo(subject);
    }

    @Test
    void imagesWithoutADigestGetNoOccurrencesAndDeepAssetsGetNoParentEdge() {
        UUID tagOnly = asset("CONTAINER_IMAGE", null);
        UUID pinned = asset("CONTAINER_IMAGE", "sha256:" + "a".repeat(64));
        UUID deep = asset("HOST", null);
        UUID tagRow = component(tagOnly, "deb", "openssl", "3.0.2", "pkg:deb/openssl@3.0.2", "ACTIVE");
        UUID pinnedRow = component(pinned, "deb", "openssl", "3.0.2", "pkg:deb/openssl@3.0.2", "ACTIVE");
        UUID deepRow = component(deep, "deb", "openssl", "3.0.2", "pkg:deb/openssl@3.0.2", "ACTIVE");
        inventory.linkAssets(100);
        // Five ancestors above the deep host: one more hop to its occurrence would exceed six.
        UUID child = assetSubject(deep);
        for (int i = 0; i < 5; i++) {
            UUID parent = subjects.register("APPLICATION", "app-" + i + "-" + UUID.randomUUID(), null).id();
            subjects.setParent(child, parent, "admin");
            child = parent;
        }

        subjects.registerOccurrences(100);
        assertThat(subjectOf(tagRow)).isNull();
        assertThat(subjectOf(pinnedRow)).isNotNull();
        assertThat(subjectOf(deepRow)).isNotNull();
        assertThat(subjects.currentParent(subjectOf(deepRow))).isEmpty();
    }

    @Test
    void theMaintenanceJobRegistersOccurrencesOnlyOnceCloudBomLeavesLegacy() {
        UUID web = asset("HOST", null);
        UUID row = component(web, "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "ACTIVE");
        maintenance.runForTenant(tenant);
        enter();
        assertThat(subjectOf(row)).isNull();

        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, updated_by) VALUES (?, 'CLOUD_BOM', 'DARK', 'test')""",
                tenant.getId()));
        maintenance.runForTenant(tenant);
        enter();
        assertThat(subjectOf(row)).isNotNull();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_event WHERE event_type = 'OCCURRENCES_REGISTERED'", Integer.class))
                .isEqualTo(1);
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private UUID asset(String type, String digest) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, image_digest)
                VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', ?, ?)""", id, "asset-" + id, "asset-" + id, type, digest);
        return id;
    }

    private UUID component(UUID asset, String ecosystem, String name, String version, String purl, String status) {
        UUID upload = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO sbom_uploads (id, asset_id, format, status, original_filename, uploaded_at)
                VALUES (?, ?, 'CYCLONEDX', 'SUCCESS', 'bom.json', now())""", upload, asset);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO inventory_components (id, component_status, ecosystem, ingested_at, last_observed_at, package_name, purl, version,
                    asset_id, sbom_upload_id)
                VALUES (?, ?, ?, now(), now(), ?, ?, ?, ?, ?)""", id, status, ecosystem, name, purl, version, asset, upload);
        return id;
    }

    private UUID subjectOf(UUID component) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM inventory_components WHERE id = ?", UUID.class, component);
    }

    private UUID assetSubject(UUID asset) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM assets WHERE id = ?", UUID.class, asset);
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
