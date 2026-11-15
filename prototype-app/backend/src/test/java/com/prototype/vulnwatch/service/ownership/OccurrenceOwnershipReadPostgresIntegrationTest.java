package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.IdentityCoverage;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.OccurrenceTable;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Owner envelopes on BOM/CBOM rows and software identity coverage (Phase 0B §3.7), gated on CLOUD_BOM. */
@PostgresIntegrationTest
class OccurrenceOwnershipReadPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_occurrence_reads");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.read-waves.inventory", () -> "*");
    }

    @Autowired private OwnershipReadAdapter reads;
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
    private UUID software;

    @BeforeEach
    void setUp() {
        String slug = "own-occr-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        authority("CORE", "CANONICAL");
        authority("CLOUD_BOM", "DARK");
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
        identity = teams.createTeam("Identity", null, null, "admin").id();
        software = UUID.randomUUID();
        UUID id = software;
        TenantContext.runAsPlatform(() -> jdbc.update(
                "INSERT INTO platform.software_identities (id, canonical_key, display_name, created_at, updated_at) VALUES (?, ?, 'lodash', now(), now())",
                id, "npm:lodash:" + id));
        enter();
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void componentRowsCarryTheirOccurrenceOwnerOnlyOnceCloudBomIsCanonical() {
        UUID web = host(payments, "ci-web");
        UUID db = host(identity, "ci-db");
        UUID webRow = component(web);
        UUID dbRow = component(db);
        UUID unlinked = component(web);
        subjects.registerOccurrences(100);
        jdbc.update("UPDATE inventory_components SET ownership_subject_id = NULL, component_status = 'RETIRED' WHERE id = ?", unlinked);

        assertThat(reads.forOccurrences(OccurrenceTable.INVENTORY_COMPONENTS, List.of(webRow))).as("DARK reads nothing").isEmpty();
        assertThat(reads.identityCoverage(software)).isEmpty();

        authority("CLOUD_BOM", "CANONICAL");
        enter();
        Map<UUID, Summary> owners = reads.forOccurrences(OccurrenceTable.INVENTORY_COMPONENTS, List.of(webRow, dbRow, unlinked));
        assertThat(owners.get(webRow).ownerTeamId()).isEqualTo(payments);
        assertThat(owners.get(webRow).authorityDomain()).isEqualTo("CLOUD_BOM");
        assertThat(owners.get(dbRow).ownerTeamName()).isEqualTo("Identity");
        assertThat(owners.get(unlinked).ownershipStatus()).isEqualTo("UNOWNED");

        IdentityCoverage coverage = reads.identityCoverage(software).orElseThrow();
        assertThat(coverage.occurrences()).isEqualTo(2);
        assertThat(coverage.ownedOccurrences()).isEqualTo(2);
        assertThat(coverage.teamIds()).containsExactlyInAnyOrder(payments, identity);
    }

    private UUID host(UUID team, String ci) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')",
                id, "h-" + id, "h-" + id);
        UUID subject = inventory.subjectForAsset(id).orElseThrow();
        claims.recordClaim(new ClaimRequest(subject, team, null, "SERVICENOW", "SERVICENOW", null, "servicenow:cmdb_ci:" + ci + ":support_group",
                "v1", "servicenow-cmdb-1", Instant.now(), null, null, null, "test"));
        return id;
    }

    private UUID component(UUID asset) {
        UUID upload = UUID.randomUUID();
        jdbc.update("INSERT INTO sbom_uploads (id, asset_id, format, status, original_filename, uploaded_at) VALUES (?, ?, 'CYCLONEDX', 'SUCCESS', 'b.json', now())",
                upload, asset);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO inventory_components (id, component_status, ecosystem, ingested_at, last_observed_at, package_name, purl, version, asset_id,
                    sbom_upload_id, software_identity_id)
                VALUES (?, 'ACTIVE', 'npm', now(), now(), 'lodash', 'pkg:npm/lodash@4.17.21', '4.17.21', ?, ?, ?)""", id, asset, upload, software);
        return id;
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
