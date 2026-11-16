package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.FindingSubjectAdapterRegistry.DarkReport;
import com.prototype.vulnwatch.service.ownership.FindingSubjectAdapterRegistry.Outcome;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Real-PostgreSQL proof for the finding-adapter registry and occurrence retirement (Phase 0B §3.2, §3.5, §3.6). */
@PostgresIntegrationTest
class FindingSubjectAdapterPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_finding_adapters");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private FindingSubjectAdapterRegistry registry;
    @Autowired private OwnershipSubjectService subjects;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private OwnershipClaimService claims;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID identity;
    private UUID vulnerability;

    @BeforeEach
    void setUp() {
        String slug = "own-fa-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        authority("CORE", "CANONICAL");
        authority("CLOUD_BOM", "DARK");
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
        identity = teams.createTeam("Identity", null, null, "admin").id();
        vulnerability = UUID.randomUUID();
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                VALUES (?, ?, 'NVD', 'Adapter fixture', 'HIGH', false, now(), now())""", vulnerability, "CVE-2026-" + slug.substring(7)));
        enter();
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void inDarkV2OnlyFeedsTheReportAndAtTheSwitchFindingsMoveWithoutAnOwnerChange() {
        UUID host = host();
        UUID component = component(host);
        UUID finding = vulnerabilityFinding(host, component);
        claims.recordClaim(serviceNow(inventory.subjectForAsset(host).orElseThrow(), payments, "ci-1"));
        subjects.registerOccurrences(100);
        UUID occurrence = occurrenceOf(component);

        // DARK: the finding links to its asset (v1); v2 would move it, with the same effective owner.
        assertThat(registry.subjectForFinding(finding)).contains(inventory.subjectForAsset(host).orElseThrow());
        assertThat(registry.switchBatch(100)).as("never writes an occurrence in DARK").isZero();
        DarkReport dark = registry.darkReport();
        assertThat(dark.wouldMoveToOccurrence()).isEqualTo(1);
        assertThat(dark.effectiveOwnerChanges()).isZero();
        assertThat(dark.passed()).isTrue();

        authority("CLOUD_BOM", "CANONICAL");
        enter();
        assertThat(registry.switchBatch(100)).isEqualTo(1);
        assertThat(subjectOf(finding)).isEqualTo(occurrence);
        assertThat(ownerOf(occurrence)).isEqualTo(payments);
        assertThat(registry.switchBatch(100)).as("idempotent").isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_event WHERE event_type = 'FINDING_SUBJECTS_SWITCHED'", Integer.class))
                .isEqualTo(1);
    }

    @Test
    void aComponentOnAnotherAssetKeepsV1AndIsCountedAsAMismatch() {
        UUID host = host();
        UUID other = host();
        UUID component = component(other);
        UUID finding = vulnerabilityFinding(host, component);
        subjects.registerOccurrences(100);
        authority("CLOUD_BOM", "CANONICAL");
        enter();

        assertThat(registry.select(finding).subjectId()).isEqualTo(inventory.subjectForAsset(host).orElseThrow());
        assertThat(registry.darkReport().stayOnAsset()).containsEntry("ASSET_MISMATCH", 1L);
    }

    @Test
    void aDirectClaimOnAnOccurrenceShowsUpAsAnOwnerChangeAndFailsTheReport() {
        UUID host = host();
        UUID component = component(host);
        vulnerabilityFinding(host, component);
        claims.recordClaim(serviceNow(inventory.subjectForAsset(host).orElseThrow(), payments, "ci-1"));
        subjects.registerOccurrences(100);
        // A defect the report must catch: the occurrence resolves to another team than its asset.
        claims.recordClaim(serviceNow(occurrenceOf(component), identity, "occurrence-defect"));

        DarkReport dark = registry.darkReport();
        assertThat(dark.effectiveOwnerChanges()).isEqualTo(1);
        assertThat(dark.passed()).isFalse();
    }

    @Test
    void cryptoFindingsAreUnownedUntilCloudBomIsCanonicalAndPendingWithoutAnOccurrence() {
        UUID host = host();
        UUID cbomComponent = cbomComponent(host);
        UUID crypto = cryptoFinding(host, cbomComponent);
        assertThat(registry.select(crypto).reason()).isEqualTo("LEGACY_PENDING_MIGRATION");

        authority("CLOUD_BOM", "CANONICAL");
        enter();
        assertThat(registry.select(crypto).reason()).isEqualTo("SUBJECT_PENDING");
        assertThat(registry.subjectForFinding(crypto)).isEmpty();

        UUID occurrence = subjects.register("COMPONENT_OCCURRENCE", "crypto:fp-1", "asset:" + host).id();
        jdbc.update("UPDATE cbom_components SET ownership_subject_id = ? WHERE id = ?", occurrence, cbomComponent);
        assertThat(registry.select(crypto).outcome()).isEqualTo(Outcome.CANONICAL_SUBJECT);
        registry.switchBatch(100);
        assertThat(subjectOf(crypto)).isEqualTo(occurrence);
        assertThat(registry.darkReport().cryptoSubjectPending()).isZero();
    }

    @Test
    void occurrencesRetireAfterNinetyDaysOnlyWithoutClaimsOrOpenFindings() {
        UUID host = host();
        UUID quiet = component(host);
        UUID claimed = component(host, "requests");
        UUID referenced = component(host, "urllib3");
        subjects.registerOccurrences(100);
        UUID quietSubject = occurrenceOf(quiet);
        claims.recordClaim(serviceNow(occurrenceOf(claimed), payments, "claimed"));
        UUID finding = vulnerabilityFinding(host, referenced);
        jdbc.update("UPDATE findings SET ownership_subject_id = ? WHERE id = ?", occurrenceOf(referenced), finding);
        jdbc.update("UPDATE inventory_components SET component_status = 'RETIRED', retired_at = now() - interval '91 days'");
        jdbc.update("UPDATE ownership_subject SET created_at = now() - interval '120 days' WHERE subject_type = 'COMPONENT_OCCURRENCE'");

        assertThat(subjects.retireOccurrences(100)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT lifecycle_status FROM ownership_subject WHERE id = ?", String.class, quietSubject)).isEqualTo("RETIRED");
        assertThat(occurrenceOf(quiet)).as("unlinked, so a reappearance registers generation 2").isNull();
        assertThat(subjects.currentParent(quietSubject)).isEmpty();

        jdbc.update("UPDATE inventory_components SET component_status = 'ACTIVE', retired_at = NULL WHERE id = ?", quiet);
        subjects.registerOccurrences(100);
        assertThat(jdbc.queryForObject("SELECT generation FROM ownership_subject WHERE id = ?", Integer.class, occurrenceOf(quiet))).isEqualTo(2);
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private ClaimRequest serviceNow(UUID subject, UUID team, String ref) {
        return new ClaimRequest(subject, team, null, "SERVICENOW", "SERVICENOW", null, "servicenow:cmdb_ci:" + ref + ":support_group", "v1",
                "servicenow-cmdb-1", Instant.now(), null, null, null, "test");
    }

    private UUID host() {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')",
                id, "host-" + id, "host-" + id);
        inventory.subjectForAsset(id);
        return id;
    }

    private UUID component(UUID asset) {
        return component(asset, "lodash");
    }

    private UUID component(UUID asset, String name) {
        UUID upload = UUID.randomUUID();
        jdbc.update("INSERT INTO sbom_uploads (id, asset_id, format, status, original_filename, uploaded_at) VALUES (?, ?, 'CYCLONEDX', 'SUCCESS', 'b.json', now())",
                upload, asset);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO inventory_components (id, component_status, ecosystem, ingested_at, last_observed_at, package_name, purl, version, asset_id, sbom_upload_id)
                VALUES (?, 'ACTIVE', 'npm', now(), now(), ?, ?, '1.0.0', ?, ?)""", id, name, "pkg:npm/" + name + "@1.0.0", asset, upload);
        return id;
    }

    private UUID cbomComponent(UUID asset) {
        UUID record = UUID.randomUUID();
        jdbc.update("INSERT INTO bom_ingestion_records (id, bom_type) VALUES (?, 'CBOM')", record);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO cbom_components (id, source_bom_id, component_fingerprint, name, asset_type, asset_id)
                VALUES (?, ?, 'fp-1', 'TLS key', 'KEY', ?)""", id, record, asset);
        return id;
    }

    private UUID vulnerabilityFinding(UUID asset, UUID component) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, status, finding_kind,
                    vulnerability_id, asset_id, component_id)
                VALUES (?, now(), now(), 'AUTOMATIC', ?, 'CPE', 7.0, 'OPEN', 'VULNERABILITY', ?, ?, ?)""",
                id, "F-" + id.toString().substring(0, 8), vulnerability, asset, component);
        return id;
    }

    private UUID cryptoFinding(UUID asset, UUID cbomComponent) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, status, finding_kind, asset_id, evidence)
                VALUES (?, now(), now(), 'AUTOMATIC', ?, 'CBOM_RULE', 5.0, 'OPEN', 'CRYPTO', ?, ?::jsonb)""",
                id, "C-" + id.toString().substring(0, 8), asset, "{\"cbomComponentId\":\"" + cbomComponent + "\"}");
        return id;
    }

    private UUID occurrenceOf(UUID component) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM inventory_components WHERE id = ?", UUID.class, component);
    }

    private UUID subjectOf(UUID finding) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM findings WHERE id = ?", UUID.class, finding);
    }

    private UUID ownerOf(UUID subject) {
        return jdbc.query("SELECT owner_team_id FROM ownership_effective_assignment WHERE subject_id = ?",
                rs -> rs.next() ? rs.getObject(1, UUID.class) : null, subject);
    }

    private void authority(String domain, String state) {
        boolean canonical = "CANONICAL".equals(state);
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by)
                VALUES (?, ?, ?, ?, CASE WHEN ? THEN now() END, 'test')
                ON CONFLICT (tenant_id, domain) DO UPDATE SET state = EXCLUDED.state, accepted_by = EXCLUDED.accepted_by,
                       accepted_at = EXCLUDED.accepted_at""", tenant.getId(), domain, state, canonical ? "test" : null, canonical));
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
