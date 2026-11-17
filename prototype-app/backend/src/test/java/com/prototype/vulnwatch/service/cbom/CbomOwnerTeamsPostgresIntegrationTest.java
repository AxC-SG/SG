package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.CampaignService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.cbom.CbomEnterpriseService.PortfolioGroup;
import com.prototype.vulnwatch.service.cbom.CbomEnterpriseService.PqcCampaignProgress;
import com.prototype.vulnwatch.service.ownership.InventorySubjectAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService;
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

/**
 * Real-PostgreSQL proof that CBOM remediation reads owner teams by stable ID and the shared outcome rules (Phase 0B
 * §3.7, §4.5, §4.8, §4.12): PQC campaign progress, the remediation queue and SLA, the owner-team portfolio and the
 * ticket note's owner line, each with CLOUD_BOM canonical and with it still dark.
 */
@PostgresIntegrationTest
class CbomOwnerTeamsPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("cbom_owner_teams");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        for (String wave : List.of("inventory", "findings", "campaigns", "tickets")) {
            registry.add("app.ownership.read-waves." + wave, () -> "*");
        }
    }

    @Autowired private CbomEnterpriseService enterprise;
    @Autowired private CryptoRemediationService remediation;
    @Autowired private CampaignService campaigns;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private OwnershipClaimService claims;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID identity;

    @BeforeEach
    void setUp() {
        String slug = "cbomown-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        authority("CORE", "CANONICAL");
        authority("CLOUD_BOM", "CANONICAL");
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
    void pqcProgressCountsOnlyRemediatedAndGroupsOwnersByTeamId() {
        UUID host = host(payments, null);
        UUID open = crypto(host, "OPEN", null, true);
        UUID fixed = crypto(host, "RESOLVED", "MANUAL_FIXED", true);
        UUID accepted = crypto(host, "AUTO_CLOSED", "MANUAL_ACCEPTED_RISK", true);
        UUID retired = crypto(host, "AUTO_CLOSED", "AUTO_ASSET_RETIRED", true);
        campaigns.createFromFindings(tenant, new CampaignFromFindingsRequest("PQC wave", null, List.of(open, fixed, accepted, retired), null, null, null),
                "analyst");
        enter();

        PqcCampaignProgress wave = enterprise.pqcProgress().campaigns().get(0);
        assertThat(wave.findings()).isEqualTo(4);
        assertThat(wave.remediated()).as("accepted risk and a retired asset are not remediation").isEqualTo(1);
        assertThat(wave.active()).isEqualTo(1);
        assertThat(wave.percentComplete()).isEqualByComparingTo("0.25");
        assertThat(wave.outcomes()).containsEntry("REMEDIATED", 1L).containsEntry("ACCEPTED_RISK", 1L)
                .containsEntry("CLOSED_OTHER", 1L).containsEntry("OPEN", 1L);
        assertThat(wave.owners()).singleElement().satisfies(owner -> {
            assertThat(owner.bucket()).isEqualTo("TEAM");
            assertThat(owner.teamId()).isEqualTo(payments);
            assertThat(owner.teamName()).isEqualTo("Payments");
            assertThat(owner.members()).isEqualTo(4);
        });

        authority("CLOUD_BOM", "DARK");
        enter();
        assertThat(enterprise.pqcProgress().campaigns().get(0).owners()).singleElement()
                .satisfies(owner -> assertThat(owner.bucket()).isEqualTo("PENDING_MIGRATION"));
    }

    @Test
    void theQueueAndSlaShowTheOwnerTeamAndCountUnownedOnlyWhileCanonical() {
        UUID owned = crypto(host(payments, "Legacy Ops"), "OPEN", null, false);
        UUID unlinked = crypto(host(null, null), "OPEN", null, false);
        jdbc.update("UPDATE findings SET due_at = now() - interval '2 days'");
        jdbc.update("UPDATE findings SET assigned_to = 'alice' WHERE id = ?", owned);

        var queue = remediation.queue();
        assertThat(queue.overdue()).extracting(i -> i.findingId() + "|" + i.ownership().ownerTeamName() + "|" + i.ownership().ownershipStatus())
                .containsExactlyInAnyOrder(owned + "|Payments|OWNED", unlinked + "|null|UNOWNED");
        assertThat(queue.slaBySeverity()).singleElement().satisfies(sla -> {
            assertThat(sla.open()).isEqualTo(2);
            assertThat(sla.unassigned()).as("no workflow assignee").isEqualTo(1);
            assertThat(sla.unowned()).as("no owner team").isEqualTo(1);
        });

        authority("CLOUD_BOM", "DARK");
        enter();
        var legacy = remediation.queue();
        assertThat(legacy.slaBySeverity().get(0).unowned()).as("legacy labels cannot be counted as owners").isNull();
        assertThat(legacy.overdue()).allSatisfy(i -> assertThat(i.ownership().authorityState()).isEqualTo("LEGACY_PENDING_MIGRATION"));
    }

    @Test
    void thePortfolioGroupsByCurrentOwnerTeamIdAndKeepsLegacyRowsPendingMigration() {
        // HOST assets are CORE (canonical); a CLOUD_RESOURCE is CLOUD_BOM, which is still dark, so it keeps its legacy label.
        authority("CLOUD_BOM", "DARK");
        enter();
        componentOn(host(payments, "Legacy Ops"));
        componentOn(host(payments, "Legacy Ops"));
        componentOn(host(identity, null));
        componentOn(host(null, null));
        UUID cloud = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, owner_team)"
                + " VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'CLOUD_RESOURCE', 'Legacy Cloud Team')", cloud, "cloud-" + cloud, "cloud-" + cloud);
        componentOn(cloud);

        List<PortfolioGroup> groups = enterprise.portfolio("ownerTeam").groups();
        assertThat(groups).extracting(g -> g.group() + "|" + g.ownerBucket() + "|" + g.assets())
                .containsExactlyInAnyOrder("Payments|TEAM|2", "Identity|TEAM|1", "Unowned|UNOWNED|1", "Legacy Cloud Team|PENDING_MIGRATION|1");
        assertThat(groups).filteredOn(g -> "TEAM".equals(g.ownerBucket())).extracting(PortfolioGroup::teamId)
                .containsExactlyInAnyOrder(payments, identity);

        // A rename changes the label of the one bucket, never its membership.
        teams.renameTeam(payments, "Payments Platform", teams.team(payments).orElseThrow().version(), "admin");
        assertThat(enterprise.portfolio("ownerTeam").groups()).filteredOn(g -> payments.equals(g.teamId()))
                .singleElement().satisfies(g -> {
                    assertThat(g.group()).isEqualTo("Payments Platform");
                    assertThat(g.assets()).isEqualTo(2);
                });

        // Other groupings are unchanged and carry no owner bucket; the CMDB support group stays evidence.
        assertThat(enterprise.portfolio("supportGroup").groups()).allSatisfy(g -> assertThat(g.ownerBucket()).isNull());
    }

    @Test
    void thePortfolioShowsLegacyLabelsForEveryAssetWhileInventoryReadsAreNotCanonical() {
        authority("CORE", "DARK");
        enter();
        componentOn(host(payments, "Legacy Ops"));
        assertThat(enterprise.portfolio("ownerTeam").groups()).singleElement().satisfies(g -> {
            assertThat(g.group()).isEqualTo("Legacy Ops");
            assertThat(g.ownerBucket()).isEqualTo("PENDING_MIGRATION");
            assertThat(g.teamId()).isNull();
        });
    }

    @Test
    void theTicketNoteNamesTheCurrentOwnerTeamAndFallsBackToTheLegacyLabel() {
        UUID finding = crypto(host(payments, "Legacy Ops"), "OPEN", null, false);
        jdbc.update("UPDATE findings SET owner_group = 'Legacy Ops', assigned_to = 'alice' WHERE id = ?", finding);

        String canonical = remediation.template(finding).notes();
        assertThat(canonical).contains("ScoutGrid owner team: Payments").contains("ScoutGrid assignee: alice").doesNotContain("Legacy Ops");

        authority("CLOUD_BOM", "DARK");
        enter();
        assertThat(remediation.template(finding).notes()).contains("ScoutGrid owner team: Legacy Ops").doesNotContain("Payments");
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private UUID host(UUID team, String legacyOwnerTeam) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, owner_team)"
                + " VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST', ?)", id, "host-" + id, "host-" + id, legacyOwnerTeam);
        UUID subject = inventory.subjectForAsset(id).orElseThrow();
        if (team != null) claims.recordClaim(claim(subject, team, "ci-" + id));
        return id;
    }

    /** A CRYPTO finding on the host's asset subject; {@code quantum} marks it as a PQC migration target. */
    private UUID crypto(UUID asset, String status, String closedReason, boolean quantum) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, confidence_score,
                    status, closed_reason, finding_kind, asset_id, evidence, severity_override, reason_code, ownership_subject_id)
                SELECT ?, ?, now(), now(), 'AUTOMATIC', ?, 'CBOM_RULE', 5.0, 0.9, ?, ?, 'CRYPTO', a.id, '{}'::jsonb, 'HIGH', ?, a.ownership_subject_id
                  FROM assets a WHERE a.id = ?""",
                id, tenant.getId(), "C-" + id.toString().substring(0, 8), status, closedReason, quantum ? "QUANTUM_VULNERABLE" : "WEAK_KEY", asset);
        return id;
    }

    private void componentOn(UUID asset) {
        UUID record = UUID.randomUUID();
        jdbc.update("INSERT INTO bom_ingestion_records (id, bom_type) VALUES (?, 'CBOM')", record);
        jdbc.update("""
                INSERT INTO cbom_components (id, source_bom_id, component_fingerprint, name, asset_type, asset_id)
                VALUES (gen_random_uuid(), ?, ?, 'TLS key', 'KEY', ?)""", record, "fp-" + record, asset);
    }

    private ClaimRequest claim(UUID subject, UUID team, String ref) {
        return new ClaimRequest(subject, team, null, "SERVICENOW", "SERVICENOW", null, "servicenow:cmdb_ci:" + ref + ":support_group", "v1",
                "servicenow-cmdb-1", Instant.now(), null, null, null, "test");
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
