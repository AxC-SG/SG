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

/** Real-PostgreSQL proof for CBOM occurrence subjects (Phase 0B §3.1–§3.3, §3.2 retirement). */
@PostgresIntegrationTest
class CbomOccurrencePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_cbom_occurrences");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private OwnershipSubjectService subjects;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        String slug = "own-cbom-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        enter();
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    void theSameFingerprintAcrossRevisionsIsOneOccurrenceUnderItsAsset() {
        UUID host = asset("HOST", null);
        UUID source = source();
        UUID first = revision(source, null, 0);
        UUID current = revision(source, null, 0);
        jdbc.update("UPDATE bom_ingestion_records SET status = 'SUPERSEDED', superseded_by = ? WHERE id = ?", current, first);
        UUID old = component(first, host, "fp-tls");
        UUID now = component(current, host, "fp-tls");
        inventory.linkAssets(100);

        assertThat(subjects.registerCbomOccurrences(100)).as("only the current revision registers").isEqualTo(1);
        UUID subject = subjectOf(now);
        assertThat(subjectOf(old)).isNull();
        assertThat(jdbc.queryForObject("SELECT source_object_id || '|' || context_key FROM ownership_subject WHERE id = ?", String.class, subject))
                .isEqualTo("crypto:fp-tls|asset:" + host);
        assertThat(subjects.currentParent(subject)).contains(jdbc.queryForObject(
                "SELECT ownership_subject_id FROM assets WHERE id = ?", UUID.class, host));

        // The next revision brings a new row with the same fingerprint: it links to the same subject.
        UUID next = revision(source, null, 0);
        jdbc.update("UPDATE bom_ingestion_records SET status = 'SUPERSEDED', superseded_by = ? WHERE id = ?", next, current);
        UUID again = component(next, host, "fp-tls");
        subjects.registerCbomOccurrences(100);
        assertThat(subjectOf(again)).isEqualTo(subject);
    }

    @Test
    void aCbomWithoutAnAssetIsScopedToItsSourceAndHasNoParent() {
        UUID source = source();
        UUID row = component(revision(source, null, 0), null, "fp-key");
        assertThat(subjects.registerCbomOccurrences(100)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT context_key FROM ownership_subject WHERE id = ?", String.class, subjectOf(row)))
                .isEqualTo("bom-source:" + source);
        assertThat(subjects.currentParent(subjectOf(row))).isEmpty();
    }

    @Test
    void aTagOnlyImageGetsNoCbomOccurrence() {
        UUID image = asset("CONTAINER_IMAGE", null);
        UUID row = component(revision(source(), null, 0), image, "fp-cert");
        inventory.linkAssets(100);
        assertThat(subjects.registerCbomOccurrences(100)).isZero();
        assertThat(subjectOf(row)).isNull();
    }

    @Test
    void aCbomOccurrenceRetiresOnceAbsentFromTheCurrentRevisionForNinetyDays() {
        UUID host = asset("HOST", null);
        UUID source = source();
        UUID old = revision(source, null, 100);
        UUID gone = component(old, host, "fp-gone");
        UUID kept = component(old, host, "fp-kept");
        inventory.linkAssets(100);
        subjects.registerCbomOccurrences(100);
        UUID goneSubject = subjectOf(gone);
        // A newer revision still contains fp-kept, but not fp-gone.
        UUID current = revision(source, null, 0);
        jdbc.update("UPDATE bom_ingestion_records SET status = 'SUPERSEDED', superseded_by = ? WHERE id = ?", current, old);
        UUID keptNow = component(current, host, "fp-kept");
        subjects.registerCbomOccurrences(100);
        jdbc.update("UPDATE ownership_subject SET created_at = now() - interval '120 days' WHERE subject_type = 'COMPONENT_OCCURRENCE'");

        assertThat(subjects.retireOccurrences(100)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT lifecycle_status FROM ownership_subject WHERE id = ?", String.class, goneSubject)).isEqualTo("RETIRED");
        assertThat(subjectOf(gone)).isNull();
        assertThat(subjectOf(keptNow)).isEqualTo(subjectOf(kept));
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private UUID asset(String type, String digest) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, image_digest) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', ?, ?)",
                id, "a-" + id, "a-" + id, type, digest);
        return id;
    }

    private UUID source() {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO bom_sources (id, tenant_id, bom_type) VALUES (?, ?, 'CBOM')", id, tenant.getId());
        return id;
    }

    private UUID revision(UUID source, UUID asset, int daysAgo) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO bom_ingestion_records (id, bom_type, source_id, asset_id, ingested_at) VALUES (?, 'CBOM', ?, ?, now() - make_interval(days => ?))",
                id, source, asset, daysAgo);
        return id;
    }

    private UUID component(UUID revision, UUID asset, String fingerprint) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO cbom_components (id, source_bom_id, component_fingerprint, name, asset_type, asset_id) VALUES (?, ?, ?, 'crypto asset', 'KEY', ?)",
                id, revision, fingerprint, asset);
        return id;
    }

    private UUID subjectOf(UUID component) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM cbom_components WHERE id = ?", UUID.class, component);
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
