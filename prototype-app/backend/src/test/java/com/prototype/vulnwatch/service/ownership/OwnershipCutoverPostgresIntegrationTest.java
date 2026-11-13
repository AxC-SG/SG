package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.State;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.service.ownership.OwnershipCutoverService.Qualification;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Consumer;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary;
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

/** Real-PostgreSQL proof for the domain-aware read adapter, dark populate/qualify and the CORE authority switch (§15). */
@PostgresIntegrationTest
class OwnershipCutoverPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_cutover");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.read-waves.inventory", () -> "*");
        registry.add("app.ownership.read-waves.findings", () -> "*");
    }

    @Autowired private OwnershipCutoverService cutover;
    @Autowired private OwnershipReadAdapter reads;
    @Autowired private OwnershipMaintenanceJob maintenance;
    @Autowired private OwnershipClaimService claims;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;

    @BeforeEach
    void setUp() {
        String slug = "own-cut-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void legacyRowsArePendingMigrationNeverUnowned() {
        UUID asset = asset("web-1", "Payments Legacy");
        UUID unlabelled = asset("web-2", null);
        List<Summary> rows = reads.forAssets(List.of(asset, unlabelled));
        assertThat(rows).extracting(Summary::authorityState).containsOnly("LEGACY_PENDING_MIGRATION");
        assertThat(rows.get(0).legacyOwnerLabel()).isEqualTo("Payments Legacy");
        assertThat(rows).extracting(Summary::ownershipStatus).containsOnlyNulls();
        assertThat(reads.filter(Consumer.INVENTORY, payments, null, 10, null)).isEmpty();
        assertThat(reads.coverage(Consumer.INVENTORY).authorityState()).isEqualTo("LEGACY_PENDING_MIGRATION");
    }

    @Test
    void darkPopulateQualifyThenGoMakesReadsCanonicalAndClosesRollback() {
        UUID owned = asset("web-1", "Payments");
        UUID orphan = asset("web-2", "Somebody Else");
        UUID finding = finding(owned, "VULNERABILITY");
        UUID aiFinding = finding(owned, "AI_POSTURE");
        assertThatThrownBy(() -> cutover.transition(Domain.CORE, State.CANONICAL, null, "admin")).isInstanceOf(ResponseStatusException.class);

        cutover.transition(Domain.CORE, State.DARK, null, "admin");
        enter();
        Qualification before = cutover.qualify(Domain.CORE);
        assertThat(before.passed()).isFalse();
        assertThat(before.blockers()).anyMatch(b -> b.startsWith("unlinkedAssets"));

        maintenance.runForTenant(tenant); // populate: links both assets and the finding to subjects
        enter();
        claims.recordClaim(new ClaimRequest(inventory.subjectForAsset(owned).orElseThrow(), payments, null, "SERVICENOW", "SERVICENOW",
                null, "servicenow:cmdb_ci:web-1:support_group", "1", "sn", Instant.now(), null, null, null, "sn"));
        // Still DARK: readers see legacy values.
        assertThat(reads.forAssets(List.of(owned)).get(0).authorityState()).isEqualTo("LEGACY_PENDING_MIGRATION");

        Qualification ready = cutover.qualify(Domain.CORE);
        assertThat(ready.passed()).as(String.valueOf(ready.blockers())).isTrue();
        assertThat(ready.comparison().match()).isEqualTo(1);
        assertThat(ready.comparison().legacyOnly()).isEqualTo(1);
        assertThatThrownBy(() -> cutover.transition(Domain.CORE, State.CANONICAL, "not-the-hash", "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));

        cutover.transition(Domain.CORE, State.CANONICAL, ready.reportHash(), "approver");
        enter();
        String acceptedBy = TenantContext.runAsPlatform(() -> jdbc.queryForObject(
                "SELECT accepted_by FROM platform.ownership_domain_authority WHERE tenant_id = ? AND domain = 'CORE'", String.class, tenant.getId()));
        enter();
        assertThat(acceptedBy).isEqualTo("approver");

        Summary canonical = reads.forAssets(List.of(owned)).get(0);
        assertThat(canonical.authorityState()).isEqualTo("CANONICAL");
        assertThat(canonical.ownerTeamId()).isEqualTo(payments);
        assertThat(canonical.ownerTeamName()).isEqualTo("Payments");
        assertThat(reads.forAssets(List.of(orphan)).get(0).ownershipStatus()).isEqualTo("UNOWNED");
        assertThat(reads.forFindings(List.of(finding)).get(0).ownerTeamId()).isEqualTo(payments);
        assertThat(reads.filter(Consumer.INVENTORY, payments, null, 10, null)).containsExactly(owned);
        assertThat(reads.filter(Consumer.FINDINGS, null, "OWNED", 10, null)).containsExactly(finding);

        // An AI finding on the same asset belongs to the AI Grid domain, which switches in Release 3: it was not
        // linked to the asset subject and still reads its legacy label, never Unowned, and no canonical filter returns it.
        Summary ai = reads.forFindings(List.of(aiFinding)).get(0);
        assertThat(ai.authorityDomain()).isEqualTo("AI_GRID");
        assertThat(ai.authorityState()).isEqualTo("LEGACY_PENDING_MIGRATION");
        assertThat(ai.ownershipStatus()).isNull();
        assertThat(jdbc.queryForObject("SELECT ownership_subject_id FROM findings WHERE id = ?", UUID.class, aiFinding)).isNull();
        assertThat(reads.filter(Consumer.FINDINGS, null, "UNOWNED", 10, null)).doesNotContain(aiFinding);
        assertThat(reads.coverage(Consumer.INVENTORY).owned()).isEqualTo(1);

        // Renaming the team changes the displayed name with no writes to assets or findings.
        teams.renameTeam(payments, "Payments Platform", teams.team(payments).orElseThrow().version(), "admin");
        assertThat(reads.forAssets(List.of(owned)).get(0).ownerTeamName()).isEqualTo("Payments Platform");

        assertThatThrownBy(() -> cutover.transition(Domain.CORE, State.LEGACY, null, "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getReason()).contains("rollback window is closed"));
        assertThatThrownBy(() -> cutover.transition(Domain.CLOUD_BOM, State.DARK, null, "admin")).isInstanceOf(ResponseStatusException.class);
    }

    private UUID asset(String identifier, String ownerTeam) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, owner_team)
                VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST', ?)""", id, identifier, identifier, ownerTeam);
        return id;
    }

    private UUID finding(UUID asset, String kind) {
        UUID id = UUID.randomUUID();
        UUID vulnerability = "VULNERABILITY".equals(kind) ? vulnerability() : null;
        jdbc.update("""
                INSERT INTO findings (id, created_at, creation_source, display_id, matched_by, risk_score, status, updated_at, finding_kind,
                                      asset_id, vulnerability_id)
                VALUES (?, now(), 'MANUAL', ?, 'test', 1.0, 'OPEN', now(), ?, ?, ?)""",
                id, "F-" + id.toString().substring(0, 6), kind, asset, vulnerability);
        return id;
    }

    private UUID vulnerability() {
        UUID id = UUID.randomUUID();
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                VALUES (?, ?, 'NVD', 'test vulnerability', 'HIGH', false, now(), now())""", id, "CVE-2026-" + (10000 + (int) (Math.random() * 89999))));
        enter();
        return id;
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
