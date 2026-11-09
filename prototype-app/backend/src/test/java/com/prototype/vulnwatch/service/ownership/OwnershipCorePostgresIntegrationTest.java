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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/** Real-PostgreSQL proof for tenant V21: claims, direct resolution, bounded inheritance and isolation. */
@PostgresIntegrationTest
class OwnershipCorePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ownership_core");
    private static final List<String> V21_TABLES = List.of("ownership_subject", "ownership_subject_edge", "ownership_claim",
            "ownership_assignment", "ownership_review_item", "ownership_event", "ownership_effective_cache", "ownership_resolution_queue",
            "ownership_cache_invalidation");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TeamNamespaceService teams;
    @Autowired private OwnershipSubjectService subjects;
    @Autowired private OwnershipClaimService claims;
    @Autowired private OwnershipResolutionService resolution;
    @Autowired private OwnershipMaintenanceJob maintenance;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private Tenant other;
    private UUID payments;
    private UUID identity;

    @BeforeEach
    void setUp() {
        tenant = newTenant();
        other = newTenant();
        enter(tenant);
        payments = teams.createTeam("Payments", null, null, "admin").id();
        identity = teams.createTeam("Identity", null, null, "admin").id();
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_kill_switches WHERE tenant_id IN (?, ?)",
                tenant.getId(), other.getId()));
    }

    @Test
    void everyV21TableForcesRlsWithTenantInclusiveForeignKeysAndTheViewIsSecurityInvoker() {
        for (String table : V21_TABLES) {
            Boolean forced = jdbc.queryForObject("""
                    SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = ? AND c.relname = ?""", Boolean.class, tenant.getSchemaName(), table);
            assertThat(forced).as(table + " forces RLS").isTrue();
        }
        List<String> nonInclusive = jdbc.queryForList("""
                SELECT con.conname FROM pg_constraint con
                  JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_class r ON r.oid = con.confrelid JOIN pg_namespace rn ON rn.oid = r.relnamespace
                 WHERE con.contype = 'f' AND n.nspname = ? AND c.relname = ANY (?) AND rn.nspname = n.nspname
                   AND (SELECT attname FROM pg_attribute WHERE attrelid = con.conrelid AND attnum = con.conkey[1]) <> 'tenant_id'
                """, String.class, tenant.getSchemaName(), V21_TABLES.toArray(String[]::new));
        assertThat(nonInclusive).isEmpty();
        Integer cascades = jdbc.queryForObject("""
                SELECT count(*) FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE con.contype = 'f' AND n.nspname = ? AND c.relname = ANY (?) AND con.confdeltype = 'c'
                """, Integer.class, tenant.getSchemaName(), V21_TABLES.toArray(String[]::new));
        assertThat(cascades).isZero();
        String options = jdbc.queryForObject("""
                SELECT array_to_string(c.reloptions, ',') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = ? AND c.relname = 'ownership_effective_assignment'""", String.class, tenant.getSchemaName());
        assertThat(options).contains("security_invoker=true");
    }

    @Test
    void manualBeatsServiceNowAndReplayWritesNothing() {
        UUID host = host("web-1");
        var sn = claims.recordClaim(serviceNow(host, payments, "ci-1", "v1"));
        assertOwned(host, payments, 0);

        var manual = claims.recordClaim(manual(host, identity, null));
        var assignment = resolution.current(host).orElseThrow();
        assertThat(assignment.teamId()).isEqualTo(identity);
        assertThat(assignment.winningPriority()).isEqualTo(1);

        long version = assignment.version();
        int events = count("ownership_event");
        assertThat(claims.recordClaim(serviceNow(host, payments, "ci-1", "v1")).created()).isFalse();
        resolution.resolveSubject(host, "test");
        assertThat(resolution.current(host).orElseThrow().version()).isEqualTo(version);
        assertThat(count("ownership_event")).isEqualTo(events);

        claims.revokeClaim(manual.claimId(), "admin", "handover finished");
        assertThat(resolution.current(host).orElseThrow().winningClaimId()).isEqualTo(sn.claimId());
        assertOwned(host, payments, 0);
    }

    @Test
    void newObservationSupersedesThePreviousOneFromTheSameSourceReference() {
        UUID host = host("web-2");
        var first = claims.recordClaim(serviceNow(host, payments, "ci-2", "v1"));
        claims.recordClaim(serviceNow(host, identity, "ci-2", "v2"));
        assertThat(jdbc.queryForObject("SELECT status FROM ownership_claim WHERE id = ?", String.class, first.claimId())).isEqualTo("SUPERSEDED");
        assertOwned(host, identity, 0);
        assertThatThrownBy(() -> claims.recordClaim(serviceNow(host, payments, "ci-2", "v2")))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));
    }

    @Test
    void differentTeamsAtOnePriorityConflictAndRaiseOneReviewItem() {
        UUID host = host("web-3");
        claims.recordClaim(serviceNow(host, payments, "ci-a", "v1"));
        claims.recordClaim(serviceNow(host, identity, "ci-b", "v1"));
        var assignment = resolution.current(host).orElseThrow();
        assertThat(assignment.status()).isEqualTo("CONFLICT");
        assertThat(assignment.conflictTeamIds()).containsExactlyInAnyOrder(payments, identity);
        assertThat(effective(host).get("ownership_status")).isEqualTo("CONFLICT");
        resolution.resolveSubject(host, "test");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_review_item WHERE item_type = 'CONFLICT' AND subject_id = ?",
                Integer.class, host)).isEqualTo(1);
    }

    @Test
    void descendantsInheritWithoutCopiedRowsAndAnyDirectClaimBeatsInheritance() {
        UUID app = subject("APPLICATION", "checkout");
        UUID account = subject("CLOUD_ACCOUNT", "111122223333");
        UUID resource = subject("CLOUD_RESOURCE", "i-0abc");
        subjects.setParent(account, app, "admin");
        subjects.setParent(resource, account, "admin");
        claims.recordClaim(manual(app, payments, null));

        assertThat(effective(resource)).containsEntry("ownership_status", "OWNED").containsEntry("owner_team_id", payments)
                .containsEntry("resolution", "INHERITED").containsEntry("ownership_origin_subject_id", app);
        assertThat(((Number) effective(resource).get("inheritance_depth")).intValue()).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_assignment", Integer.class)).isEqualTo(1);

        // A reviewed cloud tag directly on the resource beats the manual claim inherited from the application.
        claims.recordClaim(new ClaimRequest(resource, identity, null, "AWS", "CLOUD_TAG", null, "tag:team", "v1", "aws-1",
                Instant.now(), null, null, null, "aws-producer"));
        assertOwned(resource, identity, 0);
        assertThat(effective(account)).containsEntry("owner_team_id", payments);

        UUID orphan = subject("HOST", "lonely");
        assertThat(effective(orphan)).containsEntry("ownership_status", "UNOWNED").containsEntry("resolution", "NO_ELIGIBLE_CLAIM");
    }

    @Test
    void topologyWritesRejectCyclesAndChainsLongerThanSixHops() {
        List<UUID> chain = new ArrayList<>();
        for (int i = 0; i <= 6; i++) chain.add(subject("HOST", "h" + i));
        for (int i = 1; i <= 6; i++) subjects.setParent(chain.get(i), chain.get(i - 1), "admin");
        UUID tooDeep = subject("HOST", "h7");
        assertBadRequest(() -> subjects.setParent(tooDeep, chain.get(6), "admin"));
        assertBadRequest(() -> subjects.setParent(chain.get(0), chain.get(3), "admin"));
        claims.recordClaim(manual(chain.get(0), payments, null));
        assertThat(effective(chain.get(6))).containsEntry("owner_team_id", payments).containsEntry("resolution", "INHERITED");
    }

    @Test
    void viewTurnsCyclesAndRetiredParentsIntoConflictsEvenIfTopologyIsCorrupted() {
        UUID a = subject("HOST", "ca");
        UUID b = subject("HOST", "cb");
        subjects.setParent(a, b, "admin");
        // Bypass the service to simulate a corrupted topology.
        jdbc.update("INSERT INTO ownership_subject_edge (id, child_subject_id, parent_subject_id, created_by) VALUES (?, ?, ?, 'test')",
                UUID.randomUUID(), b, a);
        assertThat(effective(a)).containsEntry("ownership_status", "CONFLICT").containsEntry("resolution", "CYCLE");

        UUID child = subject("HOST", "rc");
        UUID parent = subject("HOST", "rp");
        subjects.setParent(child, parent, "admin");
        jdbc.update("UPDATE ownership_subject SET lifecycle_status = 'RETIRED', retired_at = now() WHERE id = ?", parent);
        assertThat(effective(child)).containsEntry("ownership_status", "CONFLICT").containsEntry("resolution", "MISSING_PARENT");
    }

    @Test
    void archivingATeamReResolvesItsSubjectsAndRaisesInactiveOwner() {
        UUID host = host("web-4");
        claims.recordClaim(serviceNow(host, payments, "ci-4", "v1"));
        claims.recordClaim(new ClaimRequest(host, identity, null, "AWS", "CLOUD_TAG", null, "tag:team", "v1", "aws-1",
                Instant.now(), null, null, null, "aws-producer"));
        var team = teams.team(payments).orElseThrow();
        teams.setStatus(payments, "ARCHIVED", team.version(), "admin");
        // Archiving only queues the work; the stored result changes when the maintenance job drains the queue.
        assertThat(count("ownership_resolution_queue")).isEqualTo(1);
        assertThat(resolution.current(host).orElseThrow().teamId()).isEqualTo(payments);
        maintenance.runForTenant(tenant);
        enter(tenant);
        assertThat(count("ownership_resolution_queue")).isZero();
        assertOwned(host, identity, 0);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_review_item WHERE item_type = 'INACTIVE_OWNER'", Integer.class)).isEqualTo(1);
        assertBadRequest(() -> claims.recordClaim(serviceNow(host, payments, "ci-5", "v1")));
    }

    @Test
    void pausedSourceCannotPublishAndItsClaimsStopCounting() {
        UUID host = host("web-5");
        claims.recordClaim(serviceNow(host, payments, "ci-6", "v1"));
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_kill_switches (id, source_kind, tenant_id, state, reason, updated_by)
                VALUES (?, 'SERVICENOW', ?, 'PAUSED', 'anomaly', 'sre')""", UUID.randomUUID(), tenant.getId()));
        enter(tenant);
        assertThatThrownBy(() -> claims.recordClaim(serviceNow(host, identity, "ci-7", "v1")))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));
        resolution.resolveSubject(host, "test");
        assertThat(resolution.current(host).orElseThrow().status()).isEqualTo("NONE");
        assertThat(effective(host)).containsEntry("ownership_status", "UNOWNED");
    }

    @Test
    void expiredManualClaimsAreSweptAndOwnershipFallsBack() {
        UUID host = host("web-6");
        claims.recordClaim(serviceNow(host, payments, "ci-8", "v1"));
        Instant observed = Instant.now().minus(Duration.ofHours(2));
        claims.recordClaim(manual(host, identity, observed.plus(Duration.ofHours(1))));
        // The claim was already past expiry when recorded, so the resolver ignored it.
        assertOwned(host, payments, 0);
        assertThat(claims.expireDue(100)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_claim WHERE status = 'EXPIRED'", Integer.class)).isEqualTo(1);
        assertOwned(host, payments, 0);
    }

    @Test
    void staleClaimsAreFlaggedAtReadTimeWithoutRewritingTheAssignment() {
        UUID host = host("web-8");
        Instant observed = Instant.now().minus(Duration.ofDays(3));
        claims.recordClaim(new ClaimRequest(host, payments, null, "SERVICENOW", "SERVICENOW", null, "cmdb_ci:stale", "v1", "sn-cmdb-1",
                observed, observed.plus(Duration.ofDays(1)), observed.plus(Duration.ofDays(7)), null, "servicenow-producer"));
        assertThat(effective(host)).containsEntry("ownership_status", "OWNED").containsEntry("ownership_stale", true);
        long version = resolution.current(host).orElseThrow().version();
        claims.reobserve(List.of(resolution.current(host).orElseThrow().winningClaimId()), Instant.now(),
                Instant.now().plus(Duration.ofDays(2)), Instant.now().plus(Duration.ofDays(7)));
        assertThat(effective(host)).containsEntry("ownership_stale", false);
        resolution.resolveSubject(host, "test");
        assertThat(resolution.current(host).orElseThrow().version()).isEqualTo(version);
    }

    @Test
    void ownershipRowsAreInvisibleAcrossTenantsAndEventsAreAppendOnly() {
        UUID host = host("web-7");
        claims.recordClaim(serviceNow(host, payments, "ci-9", "v1"));
        enter(other);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_effective_assignment", Integer.class)).isZero();
        UUID theirHost = host("web-7");
        assertThatThrownBy(() -> claims.recordClaim(serviceNow(theirHost, payments, "ci-9", "v1")))
                .isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> resolution.resolveSubject(host, "test")).isInstanceOf(ResponseStatusException.class);
        enter(tenant);
        assertThatThrownBy(() -> jdbc.update("UPDATE ownership_event SET actor = 'x'")).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.update("DELETE FROM ownership_event")).isInstanceOf(DataAccessException.class);
    }

    private void assertOwned(UUID subject, UUID team, int depth) {
        Map<String, Object> row = effective(subject);
        assertThat(row).containsEntry("ownership_status", "OWNED").containsEntry("owner_team_id", team);
        assertThat(((Number) row.get("inheritance_depth")).intValue()).isEqualTo(depth);
    }

    private Map<String, Object> effective(UUID subject) {
        return jdbc.queryForMap("SELECT * FROM ownership_effective_assignment WHERE subject_id = ?", subject);
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM " + table, Integer.class);
    }

    private UUID host(String name) {
        return subject("HOST", name);
    }

    private UUID subject(String type, String sourceId) {
        return subjects.register(type, sourceId, null).id();
    }

    private static ClaimRequest serviceNow(UUID subject, UUID team, String ci, String observation) {
        Instant now = Instant.now();
        return new ClaimRequest(subject, team, null, "SERVICENOW", "SERVICENOW", null, "cmdb_ci:" + ci, observation, "sn-cmdb-1",
                now, now.plus(Duration.ofHours(12)), now.plus(Duration.ofDays(7)), null, "servicenow-producer");
    }

    private static ClaimRequest manual(UUID subject, UUID team, Instant expiresAt) {
        Instant observed = expiresAt != null && expiresAt.isBefore(Instant.now()) ? expiresAt.minus(Duration.ofHours(1)) : Instant.now();
        return new ClaimRequest(subject, team, null, "MANUAL", "MANUAL", null, "manual:" + subject, UUID.randomUUID().toString(),
                "manual-1", observed, null, expiresAt, "service owner confirmed in review", "admin");
    }

    private Tenant newTenant() {
        String slug = "own-core-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        return tenantService.resolveTenantUuid(created.getId());
    }

    private void enter(Tenant t) {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(t.getId());
        TenantContext.setCurrentSchemaName(t.getSchemaName());
    }

    private static void assertBadRequest(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(400));
    }
}
