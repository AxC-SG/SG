package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Real-PostgreSQL proof for tenant V22: additive projection and exception-snapshot columns. */
@PostgresIntegrationTest
class OwnershipProjectionColumnsPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ownership_projection");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TeamNamespaceService teams;
    @Autowired private OwnershipSubjectService subjects;
    @Autowired private OwnershipClaimService claims;
    @Autowired private OwnershipResolutionService resolution;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        String slug = "own-proj-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    void projectionAndSnapshotColumnsExistAndCarryNoOwnerNames() {
        List<String> columns = jdbc.queryForList("""
                SELECT table_name || '.' || column_name FROM information_schema.columns
                 WHERE table_schema = ? AND table_name IN ('assets','findings','finding_suppression_requests','finding_events')
                   AND (column_name LIKE 'ownership_%' OR column_name LIKE 'owner_team_id%' OR column_name = 'assignee_principal_id')
                """, String.class, tenant.getSchemaName());
        assertThat(columns).containsExactlyInAnyOrder("assets.ownership_subject_id", "findings.ownership_subject_id",
                "findings.assignee_principal_id", "finding_suppression_requests.owner_team_id_at_request",
                "finding_suppression_requests.ownership_assignment_id_at_request",
                "finding_suppression_requests.owner_team_id_at_decision",
                "finding_suppression_requests.ownership_assignment_id_at_decision",
                "finding_events.owner_team_id", "finding_events.ownership_assignment_id");
    }

    @Test
    void assetLinksToItsSubjectOnlyThroughAnExistingTenantSubject() {
        UUID asset = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type)
                VALUES (?, 'HIGH', now(), 'web-1', 'web-1', 'ACTIVE', 'HOST')""", asset);
        UUID subject = subjects.register("HOST", asset.toString(), null).id();
        jdbc.update("UPDATE assets SET ownership_subject_id = ? WHERE id = ?", subject, asset);
        assertThatThrownBy(() -> jdbc.update("UPDATE assets SET ownership_subject_id = ? WHERE id = ?", UUID.randomUUID(), asset))
                .isInstanceOf(DataIntegrityViolationException.class);

        UUID team = teams.createTeam("Payments", null, null, "admin").id();
        claims.recordClaim(new ClaimRequest(subject, team, null, "MANUAL", "MANUAL", null, "manual:" + subject, "1", "manual-1",
                Instant.now(), null, null, "confirmed", "admin"));
        UUID assignment = resolution.current(subject).orElseThrow().id();
        UUID ownerTeam = jdbc.queryForObject("""
                SELECT e.owner_team_id FROM assets a JOIN ownership_effective_assignment e ON e.subject_id = a.ownership_subject_id
                 WHERE a.id = ?""", UUID.class, asset);
        assertThat(ownerTeam).isEqualTo(team);

        UUID finding = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, created_at, creation_source, display_id, matched_by, risk_score, status, updated_at,
                                      finding_kind, asset_id, ownership_subject_id)
                VALUES (?, now(), 'MANUAL', 'F-1', 'test', 1.0, 'OPEN', now(), 'AI_POSTURE', ?, ?)""", finding, asset, subject);
        UUID event = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO finding_events (id, actor, created_at, event_type, summary, finding_id, owner_team_id, ownership_assignment_id)
                VALUES (?, 'admin', now(), 'SUPPRESSED', 'suppressed', ?, ?, ?)""", event, finding, team, assignment);
        assertThatThrownBy(() -> jdbc.update("UPDATE finding_events SET owner_team_id = ? WHERE id = ?", UUID.randomUUID(), event))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE findings SET assignee_principal_id = ? WHERE id = ?", UUID.randomUUID(), finding))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
