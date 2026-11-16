package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomVisibilityDtos.InventoryItem;
import com.prototype.vulnwatch.service.InventoryService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.cbom.CbomVisibilityService;
import com.prototype.vulnwatch.service.cbom.CbomVisibilityService.InventoryFilter;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.State;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.service.ownership.OwnershipCutoverService.Qualification;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.OccurrenceTable;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/**
 * Real-PostgreSQL proof for the CLOUD_BOM authority switch (Phase 0B §2.6, §3.6): its gates and evidence, the
 * re-resolution of cloud claims at the go decision, and the BOM and CBOM owner filters and per-occurrence assignment
 * that become available once CLOUD_BOM is canonical (§3.7).
 */
@PostgresIntegrationTest
class CloudBomCutoverPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("cloud_bom_cutover");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.read-waves.inventory", () -> "*");
    }

    @Autowired private OwnershipCutoverService cutover;
    @Autowired private OwnershipResolutionService resolution;
    @Autowired private OwnershipSubjectService subjects;
    @Autowired private OwnershipReadAdapter reads;
    @Autowired private ManualAssignmentService assignments;
    @Autowired private OwnershipClaimService claims;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private InventoryService inventoryService;
    @Autowired private CbomVisibilityService cbom;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID identity;

    @BeforeEach
    void setUp() {
        String slug = "cbcut-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        authority("CORE", "CANONICAL");
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
        identity = teams.createTeam("Identity", null, null, "admin").id();
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void theSwitchNeedsCoreCanonicalRegisteredOccurrencesAndAnApprovedHash() {
        authority("CORE", "DARK");
        enter();
        cutover.transition(Domain.CLOUD_BOM, State.DARK, null, "admin");
        enter();
        assertThat(cutover.qualify(Domain.CLOUD_BOM).blockers()).anyMatch(b -> b.startsWith("coreNotCanonical"));
        assertThatThrownBy(() -> cutover.qualify(Domain.AI_GRID)).isInstanceOf(ResponseStatusException.class);

        authority("CORE", "CANONICAL");
        enter();
        UUID host = host(payments);
        UUID component = component(host, "lodash");
        Qualification blocked = cutover.qualify(Domain.CLOUD_BOM);
        assertThat(blocked.blockers()).anyMatch(b -> b.startsWith("unregisteredOccurrences must be 0"));

        subjects.registerOccurrences(100);
        // Dark evidence: a cloud-only resource that would become owned, and a tag that disagrees with a host's ServiceNow owner.
        UUID resource = asset("CLOUD_RESOURCE");
        claims.recordClaim(claim(inventory.subjectForAsset(resource).orElseThrow(), identity, "AWS", "CLOUD_TAG", "aws:" + resource));
        claims.recordClaim(claim(inventory.subjectForAsset(host).orElseThrow(), identity, "AWS", "CLOUD_TAG", "aws:" + host));
        Qualification ready = cutover.qualify(Domain.CLOUD_BOM);
        assertThat(ready.passed()).as(String.valueOf(ready.blockers())).isTrue();
        assertThat(ready.checks()).containsEntry("evidence.cloudClaims", 2L).containsEntry("evidence.cloudResourcesNewlyOwned", 1L)
                .containsEntry("evidence.hostsWhoseOwnerWouldChange", 1L).containsEntry("evidence.claimsDisagreeingWithCurrentOwner", 1L);
        assertThat(ownerOf(resource)).as("cloud claims own nothing while CLOUD_BOM is dark").isNull();

        assertThatThrownBy(() -> cutover.transition(Domain.CLOUD_BOM, State.CANONICAL, "stale-hash", "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(409));
        cutover.transition(Domain.CLOUD_BOM, State.CANONICAL, ready.reportHash(), "approver");
        enter();
        assertThat(resolution.drainQueue(100, "system")).as("every subject with a cloud claim was queued").isGreaterThanOrEqualTo(2);
        assertThat(ownerOf(resource)).isEqualTo(identity);
        assertThat(ownerOf(host)).as("a host's ServiceNow owner outranks a cloud tag").isEqualTo(payments);
        assertThatThrownBy(() -> cutover.transition(Domain.CLOUD_BOM, State.LEGACY, null, "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getReason()).contains("rollback window is closed"));
        assertThat(component).isNotNull();
    }

    @Test
    void anAdapterThatWouldChangeAnOwnerBlocksTheSwitch() {
        authority("CLOUD_BOM", "DARK");
        enter();
        UUID host = host(payments);
        UUID component = component(host, "lodash");
        subjects.registerOccurrences(100);
        UUID finding = vulnerabilityFinding(host, component);
        // A defect the report must catch: the occurrence resolves to another team than its asset.
        claims.recordClaim(claim(occurrenceOf(component), identity, "SERVICENOW", "SERVICENOW", "occurrence-defect"));
        assertThat(finding).isNotNull();
        Qualification report = cutover.qualify(Domain.CLOUD_BOM);
        assertThat(report.passed()).isFalse();
        assertThat(report.blockers()).anyMatch(b -> b.startsWith("findingAdapterOwnerChanges"));
    }

    @Test
    void ownerFiltersAndPerOccurrenceAssignmentNeedCanonicalCloudBomAndNeverTouchSiblings() {
        UUID host = host(payments);
        UUID first = component(host, "lodash");
        UUID second = component(host, "requests");
        subjects.registerOccurrences(100);

        assertThatThrownBy(() -> reads.occurrenceIds(OccurrenceTable.INVENTORY_COMPONENTS, payments, null))
                .as("legacy labels cannot be filtered by canonical team")
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(409));

        authority("CLOUD_BOM", "CANONICAL");
        enter();
        assertThat(reads.occurrenceIds(OccurrenceTable.INVENTORY_COMPONENTS, payments, null)).containsExactlyInAnyOrder(first, second);
        assertThat(reads.occurrenceIds(OccurrenceTable.INVENTORY_COMPONENTS, identity, null)).isEmpty();
        assertThatThrownBy(() -> reads.occurrenceIds(OccurrenceTable.INVENTORY_COMPONENTS, null, "MAYBE"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));

        // Assign one occurrence: the preview names its findings, the assignment applies to that row only.
        UUID finding = vulnerabilityFinding(host, first);
        jdbc.update("UPDATE findings SET ownership_subject_id = ? WHERE id = ?", occurrenceOf(first), finding);
        var preview = assignments.preview(occurrenceOf(first), identity);
        assertThat(preview.affectedFindings()).isEqualTo(1);
        assignments.assign(occurrenceOf(first), "COMPONENT_OCCURRENCE", identity, "Owned by identity", null, "k1", "admin", null);
        assertThat(reads.occurrenceIds(OccurrenceTable.INVENTORY_COMPONENTS, identity, null)).containsExactly(first);
        assertThat(reads.occurrenceIds(OccurrenceTable.INVENTORY_COMPONENTS, payments, null)).containsExactly(second);
        assertThat(reads.occurrenceIds(OccurrenceTable.INVENTORY_COMPONENTS, null, "UNOWNED")).isEmpty();

        // The paged BOM list takes the same filter.
        var page = inventoryService.listComponentsPage(tenant, null, null, null, null, null, null, identity, null, 0, 25);
        assertThat(page.items()).extracting(i -> i.id()).containsExactly(first);
        assertThat(inventoryService.listComponentsPage(tenant, null, null, null, null, null, null, null, "UNOWNED", 0, 25).items()).isEmpty();
    }

    @Test
    void theCbomInventoryFiltersByOccurrenceOwner() {
        authority("CLOUD_BOM", "CANONICAL");
        enter();
        UUID host = host(null);
        UUID owned = cbomComponent(host, "fp-owned", true);
        UUID orphan = cbomComponent(host, "fp-orphan", false);
        claims.recordClaim(claim(subjectOfCbom(owned), payments, "SERVICENOW", "SERVICENOW", "cbom-" + owned));

        assertThat(ids(cbom.inventory(tenant, filter(payments, null), 0, 50).items())).containsExactly(owned);
        assertThat(ids(cbom.inventory(tenant, filter(null, "UNOWNED"), 0, 50).items())).containsExactly(orphan);
        assertThat(ids(cbom.inventory(tenant, filter(null, null), 0, 50).items())).containsExactlyInAnyOrder(owned, orphan);
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private static InventoryFilter filter(UUID team, String status) {
        return new InventoryFilter(null, null, null, null, null, null, null, null, null, false, team, status);
    }

    private static List<UUID> ids(List<InventoryItem> items) {
        return items.stream().map(InventoryItem::id).toList();
    }

    private UUID host(UUID team) {
        UUID id = asset("HOST");
        if (team != null) claims.recordClaim(claim(inventory.subjectForAsset(id).orElseThrow(), team, "SERVICENOW", "SERVICENOW", "ci-" + id));
        return id;
    }

    private UUID asset(String type) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', ?)",
                id, "a-" + id, "a-" + id, type);
        inventory.subjectForAsset(id);
        return id;
    }

    private UUID component(UUID asset, String name) {
        UUID upload = UUID.randomUUID();
        jdbc.update("INSERT INTO sbom_uploads (id, asset_id, format, status, original_filename, uploaded_at) VALUES (?, ?, 'CYCLONEDX', 'SUCCESS', 'b.json', now())",
                upload, asset);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO inventory_components (id, tenant_id, component_status, ecosystem, ingested_at, last_observed_at, package_name, purl, version, asset_id, sbom_upload_id)
                VALUES (?, ?, 'ACTIVE', 'npm', now(), now(), ?, ?, '1.0.0', ?, ?)""", id, tenant.getId(), name, "pkg:npm/" + name + "@1.0.0", asset, upload);
        return id;
    }

    private UUID cbomComponent(UUID asset, String fingerprint, boolean withSubject) {
        UUID record = UUID.randomUUID();
        jdbc.update("INSERT INTO bom_ingestion_records (id, bom_type) VALUES (?, 'CBOM')", record);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO cbom_components (id, source_bom_id, component_fingerprint, name, asset_type, asset_id)
                VALUES (?, ?, ?, 'TLS key', 'KEY', ?)""", id, record, fingerprint, asset);
        if (withSubject) {
            UUID subject = subjects.register("COMPONENT_OCCURRENCE", "crypto:" + fingerprint, "asset:" + asset).id();
            jdbc.update("UPDATE cbom_components SET ownership_subject_id = ? WHERE id = ?", subject, id);
        }
        return id;
    }

    private UUID vulnerabilityFinding(UUID asset, UUID component) {
        UUID vulnerability = UUID.randomUUID();
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                VALUES (?, ?, 'NVD', 'Cutover fixture', 'HIGH', false, now(), now())""", vulnerability, "CVE-2026-" + (10000 + (int) (Math.random() * 89999))));
        enter();
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, confidence_score,
                    status, finding_kind, vulnerability_id, asset_id, component_id)
                VALUES (?, ?, now(), now(), 'AUTOMATIC', ?, 'CPE', 7.0, 0.9, 'OPEN', 'VULNERABILITY', ?, ?, ?)""",
                id, tenant.getId(), "F-" + id.toString().substring(0, 8), vulnerability, asset, component);
        jdbc.update("UPDATE findings SET ownership_subject_id = (SELECT ownership_subject_id FROM assets WHERE id = ?) WHERE id = ?", asset, id);
        return id;
    }

    private UUID occurrenceOf(UUID component) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM inventory_components WHERE id = ?", UUID.class, component);
    }

    private UUID subjectOfCbom(UUID component) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM cbom_components WHERE id = ?", UUID.class, component);
    }

    private UUID ownerOf(UUID asset) {
        return jdbc.query("SELECT e.owner_team_id FROM ownership_effective_assignment e JOIN assets a ON a.ownership_subject_id = e.subject_id WHERE a.id = ?",
                rs -> rs.next() ? rs.getObject(1, UUID.class) : null, asset);
    }

    private ClaimRequest claim(UUID subject, UUID team, String sourceKind, String priorityClass, String ref) {
        return new ClaimRequest(subject, team, null, sourceKind, priorityClass, null, sourceKind.toLowerCase() + ":" + ref, "v1",
                "test-1", Instant.now(), null, null, null, "test");
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
