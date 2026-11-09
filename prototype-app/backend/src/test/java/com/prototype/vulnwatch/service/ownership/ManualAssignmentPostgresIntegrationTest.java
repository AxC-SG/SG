package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.ManualAssignmentService.Preview;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/** Real-PostgreSQL proof for manual subject assignment (plan §6.10, design §4). */
@PostgresIntegrationTest
class ManualAssignmentPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_manual");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private ManualAssignmentService assignments;
    @Autowired private OwnershipSubjectService subjects;
    @Autowired private OwnershipClaimService claims;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private TeamNamespaceService teams;
    @Autowired private AppUserRepository users;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID identity;

    @BeforeEach
    void setUp() {
        String slug = "own-man-" + UUID.randomUUID().toString().substring(0, 8);
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
    void previewSeparatesWouldChangeBlockedAndAlreadyEffectiveDescendants() {
        UUID app = subjects.register("APPLICATION", "checkout", null).id();
        UUID inherits = subjects.register("HOST", "h-inherit", null).id();
        UUID blocked = subjects.register("HOST", "h-blocked", null).id();
        UUID underBlocked = subjects.register("HOST", "h-under", null).id();
        subjects.setParent(inherits, app, "admin");
        subjects.setParent(blocked, app, "admin");
        subjects.setParent(underBlocked, blocked, "admin");
        claims.recordClaim(new ClaimRequest(blocked, identity, null, "SERVICENOW", "SERVICENOW", null, "ci:b", "1", "sn", Instant.now(),
                null, null, null, "sn"));
        finding(inherits, null);
        finding(inherits, null);

        Preview preview = assignments.preview(app, payments);
        assertThat(preview.wouldChange()).isEqualTo(1);
        assertThat(preview.blockedByDirectClaim()).isEqualTo(1);
        assertThat(preview.affectedFindings()).isEqualTo(2);

        assignments.assign(app, "APPLICATION", payments, "service review", null, "key-1", "admin", null);
        assertThat(owner(inherits)).isEqualTo(payments);
        assertThat(owner(underBlocked)).isEqualTo(identity);
        assertThat(assignments.preview(app, payments).alreadyEffective()).isEqualTo(1);

        // Replaying the same idempotency key creates nothing.
        int claimRows = jdbc.queryForObject("SELECT count(*) FROM ownership_claim", Integer.class);
        assignments.assign(app, "APPLICATION", payments, "service review", null, "key-1", "admin", null);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_claim", Integer.class)).isEqualTo(claimRows);

        assignments.revoke(app, "APPLICATION", "admin", "done");
        assertThat(jdbc.queryForObject("SELECT ownership_status FROM ownership_effective_assignment WHERE subject_id = ?", String.class, inherits))
                .isEqualTo("UNOWNED");
    }

    @Test
    void analystsAreScopedToTheirFindingsCappedAt30DaysAndAlerted() {
        UUID analyst = analystUser();
        UUID asset = asset();
        UUID host = inventory.subjectForAsset(asset).orElseThrow();
        assertThatThrownBy(() -> assignments.assign(host, "HOST", payments, "triage", null, null, analyst.toString(), analyst))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(403));

        finding(host, analyst);
        assertThatThrownBy(() -> assignments.assign(host, "HOST", payments, "triage", Instant.now().plus(Duration.ofDays(31)), null,
                analyst.toString(), analyst)).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(400));
        assertThatThrownBy(() -> assignments.assign(host, "HOST", payments, " ", null, null, analyst.toString(), analyst))
                .isInstanceOf(ResponseStatusException.class);

        assignments.assign(host, "HOST", payments, "triage", null, null, analyst.toString(), analyst);
        assertThat(owner(host)).isEqualTo(payments);
        Instant expiry = jdbc.queryForObject("SELECT expires_at FROM ownership_claim WHERE source_kind = 'MANUAL' AND status = 'ACTIVE'",
                java.sql.Timestamp.class).toInstant();
        assertThat(expiry).isBefore(Instant.now().plus(Duration.ofDays(30)).plusSeconds(5));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_event WHERE event_type = 'OWNERSHIP_ANALYST_ASSIGNMENT'", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE action = 'ownership.analyst_assignment' AND outcome = 'ALERT'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void legacyAndDarkDomainsRejectCanonicalManualWrites() {
        UUID host = inventory.subjectForAsset(asset()).orElseThrow();
        for (String state : java.util.List.of("LEGACY", "DARK")) {
            authority("CORE", state);
            enter();
            assertThatThrownBy(() -> assignments.assign(host, "HOST", payments, "x", null, null, "admin", null))
                    .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));
        }
    }

    private UUID owner(UUID subject) {
        return jdbc.queryForObject("SELECT owner_team_id FROM ownership_effective_assignment WHERE subject_id = ?", UUID.class, subject);
    }

    private UUID asset() {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')",
                id, id.toString(), id.toString());
        return id;
    }

    private void finding(UUID subject, UUID assignee) {
        jdbc.update("""
                INSERT INTO findings (id, created_at, creation_source, display_id, matched_by, risk_score, status, updated_at, finding_kind,
                                      ownership_subject_id, assignee_principal_id)
                VALUES (?, now(), 'MANUAL', ?, 'test', 1.0, 'OPEN', now(), 'AI_POSTURE', ?, ?)""",
                UUID.randomUUID(), "F-" + UUID.randomUUID().toString().substring(0, 6), subject, assignee);
    }

    private UUID analystUser() {
        AppUser user = new AppUser();
        user.setExternalSubject("analyst-" + UUID.randomUUID() + "@example.test");
        user.setEmail(user.getExternalSubject());
        user.setDisplayName("Analyst");
        user.setStatus("ACTIVE");
        user.setPlatformOwner(false);
        UUID id = TenantContext.runAsPlatform(() -> users.save(user).getId());
        enter();
        return id;
    }

    private void authority(String domain, String state) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by)
                VALUES (?, ?, ?, 'test', now(), 'test')
                ON CONFLICT (tenant_id, domain) DO UPDATE SET state = EXCLUDED.state""", tenant.getId(), domain, state));
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
