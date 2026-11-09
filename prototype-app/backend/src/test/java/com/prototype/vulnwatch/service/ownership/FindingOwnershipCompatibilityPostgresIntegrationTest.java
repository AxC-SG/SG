package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.service.FindingQueryService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Real-PostgreSQL proof for the findings compatibility adapter (plan §15.3 step 4, §15.4): existing finding responses
 * keep their legacy owner until the CORE domain and the findings read wave are canonical, then report the live
 * canonical team through the same fields without persisting it, while later-domain findings stay pending migration.
 */
@PostgresIntegrationTest
class FindingOwnershipCompatibilityPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("finding_ownership_compat");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.read-waves.findings", () -> "*");
    }

    @Autowired private FindingQueryService findings;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private OwnershipClaimService claims;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;

    @BeforeEach
    void setUp() {
        String slug = "own-compat-" + UUID.randomUUID().toString().substring(0, 8);
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
    void responsesSwitchFromLegacyToLiveCanonicalOwnershipPerDomain() {
        UUID asset = asset();
        UUID vulnerabilityFinding = finding(asset, "VULNERABILITY", "legacy-rule-group");
        UUID aiFinding = finding(asset, "AI_POSTURE", "ai-grid-owner");

        // Before the switch: today's values, explicitly marked as pending migration.
        Map<UUID, FindingResponse> before = latest();
        assertThat(before.get(vulnerabilityFinding).ownerGroup()).isEqualTo("legacy-rule-group");
        assertThat(before.get(vulnerabilityFinding).ownership())
                .containsEntry("displayName", "Legacy Ops")
                .containsEntry("authorityState", "LEGACY_PENDING_MIGRATION");

        UUID subject = inventory.subjectForAsset(asset).orElseThrow();
        inventory.subjectForFinding(vulnerabilityFinding);
        assertThat(inventory.subjectForFinding(aiFinding)).as("AI findings are not linked by adapter v1").isEmpty();
        claims.recordClaim(new ClaimRequest(subject, payments, null, "SERVICENOW", "SERVICENOW", null, "cmdb_ci:web-1",
                "v1", "sn", Instant.now(), null, null, null, "sn"));
        setCoreCanonical();

        Map<UUID, FindingResponse> after = latest();
        FindingResponse canonical = after.get(vulnerabilityFinding);
        assertThat(canonical.ownerGroup()).isEqualTo("Payments");
        assertThat(canonical.ownership())
                .containsEntry("displayName", "Payments")
                .containsEntry("ownerTeamId", payments.toString())
                .containsEntry("ownershipStatus", "OWNED")
                .containsEntry("authorityState", "CANONICAL")
                .containsEntry("sourceSystem", "SERVICENOW")
                .containsEntry("supportGroup", "SN-NET-OPS");

        FindingResponse ai = after.get(aiFinding);
        assertThat(ai.ownerGroup()).isEqualTo("ai-grid-owner");
        assertThat(ai.ownership()).containsEntry("authorityState", "LEGACY_PENDING_MIGRATION");

        // The adapter persists nothing: the stored legacy column is untouched and a rename shows up immediately.
        assertThat(jdbc.queryForObject("SELECT owner_group FROM findings WHERE id = ?", String.class, vulnerabilityFinding))
                .isEqualTo("legacy-rule-group");
        teams.renameTeam(payments, "Payments Platform", teams.team(payments).orElseThrow().version(), "admin");
        FindingResponse detail = findings.toResponse(findings.listEntitiesByTenantAndIds(tenant, List.of(vulnerabilityFinding)).get(0));
        assertThat(detail.ownerGroup()).isEqualTo("Payments Platform");
    }

    private Map<UUID, FindingResponse> latest() {
        return findings.listLatestByTenant(tenant, 50).stream().collect(Collectors.toMap(FindingResponse::id, r -> r));
    }

    private UUID asset() {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, owner_team, support_group)
                VALUES (?, 'HIGH', now(), 'web-1', 'web-1', 'ACTIVE', 'HOST', 'Legacy Ops', 'SN-NET-OPS')""", id);
        return id;
    }

    private UUID finding(UUID asset, String kind, String ownerGroup) {
        UUID id = UUID.randomUUID();
        UUID vulnerability = "VULNERABILITY".equals(kind) ? vulnerability() : null;
        jdbc.update("""
                INSERT INTO findings (id, created_at, creation_source, display_id, matched_by, risk_score, confidence_score, status, updated_at,
                                      finding_kind, asset_id, vulnerability_id, owner_group, tenant_id)
                VALUES (?, now(), 'MANUAL', ?, 'test', 1.0, 0.9, 'OPEN', now(), ?, ?, ?, ?, ?)""",
                id, "F-" + id.toString().substring(0, 6), kind, asset, vulnerability, ownerGroup, tenant.getId());
        return id;
    }

    private UUID vulnerability() {
        UUID id = UUID.randomUUID();
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                VALUES (?, ?, 'NVD', 'test vulnerability', 'HIGH', false, now(), now())""", id, "CVE-2026-" + id.toString().substring(0, 5)));
        enter();
        return id;
    }

    private void setCoreCanonical() {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by)
                VALUES (?, 'CORE', 'CANONICAL', 'test', now(), 'test')""", tenant.getId()));
        enter();
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
