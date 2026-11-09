package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.State;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Consumer;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Coverage;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.sql.Timestamp;
import java.time.Duration;
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
 * Real-PostgreSQL proof for the effective-ownership cache (plan §7.5, design §7): it converges to the live walk after
 * assignment and topology changes, invalidates by path in bounded pages, never fans assignments out to descendants,
 * feeds filters/coverage with an explicit refreshing count, gates the authority switch and stays tenant-scoped.
 */
@PostgresIntegrationTest
class OwnershipEffectiveCachePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_effective_cache");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.effective-cache.enabled", () -> "true");
        registry.add("app.ownership.read-waves.inventory", () -> "*");
        registry.add("app.ownership.read-waves.findings", () -> "*");
    }

    @Autowired private OwnershipEffectiveCacheService cache;
    @Autowired private OwnershipSubjectService subjects;
    @Autowired private OwnershipClaimService claims;
    @Autowired private OwnershipMaintenanceJob maintenance;
    @Autowired private OwnershipReadAdapter reads;
    @Autowired private OwnershipCutoverService cutover;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private TeamNamespaceService teams;
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
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id IN (?, ?)",
                tenant.getId(), other.getId()));
    }

    @Test
    void cacheConvergesToTheLiveWalkAcrossAssignmentAndTopologyChangesWithoutFanOut() {
        UUID app = subject("APPLICATION", "checkout");
        UUID app2 = subject("APPLICATION", "identity-portal");
        UUID host = subject("HOST", "web-1");
        UUID occurrence = subject("COMPONENT_OCCURRENCE", "openssl@web-1");
        subjects.setParent(host, app, "admin");
        subjects.setParent(occurrence, host, "admin");
        claims.recordClaim(serviceNow(app, payments, "app-1"));
        claims.recordClaim(serviceNow(app2, identity, "app-2"));
        drain();
        assertCacheMatchesLive();
        assertCached(occurrence, "OWNED", payments, 2);

        var manual = claims.recordClaim(manual(host, identity));
        drain();
        assertCacheMatchesLive();
        assertCached(occurrence, "OWNED", identity, 1);
        assertCached(app, "OWNED", payments, 0);

        claims.revokeClaim(manual.claimId(), "admin", "handover finished");
        drain();
        assertCacheMatchesLive();
        assertCached(occurrence, "OWNED", payments, 2);

        subjects.setParent(host, app2, "admin");
        drain();
        assertCacheMatchesLive();
        assertCached(host, "OWNED", identity, 1);
        assertCached(occurrence, "OWNED", identity, 2);

        subjects.clearParent(occurrence, "admin");
        drain();
        assertCacheMatchesLive();
        assertCached(occurrence, "UNOWNED", null, 0);

        // Inheritance is never materialised: only subjects with claims have assignment rows.
        assertThat(jdbc.queryForList("SELECT subject_id FROM ownership_assignment", UUID.class)).containsExactlyInAnyOrder(app, app2, host);
        assertThat(cache.backlog().total()).isZero();

        // Team names are not cached, so a rename refreshes nothing.
        List<Timestamp> before = jdbc.queryForList("SELECT refreshed_at FROM ownership_effective_cache ORDER BY subject_id", Timestamp.class);
        teams.renameTeam(payments, "Payments Platform", teams.team(payments).orElseThrow().version(), "admin");
        drain();
        assertThat(jdbc.queryForList("SELECT refreshed_at FROM ownership_effective_cache ORDER BY subject_id", Timestamp.class))
                .isEqualTo(before);
    }

    @Test
    void invalidationIsPagedAndARequeueReinvalidatesRowsRefreshedBeforeIt() {
        UUID app = subject("APPLICATION", "checkout");
        for (int i = 0; i < 5; i++) subjects.setParent(subject("HOST", "web-" + i), app, "admin");
        drain();
        assertThat(count("ownership_effective_cache")).isEqualTo(6);

        claims.recordClaim(serviceNow(app, payments, "app-1"));   // queues app: six rows have it on their path
        assertThat(cache.expandBatch(2)).isEqualTo(2);
        assertThat(count("ownership_cache_invalidation")).as("a full page keeps the subject queued").isEqualTo(1);
        assertThat(invalidated()).isEqualTo(2);

        assertThat(cache.refreshBatch(10)).isEqualTo(2);
        cache.enqueue(app, "ASSIGNMENT_CHANGED");                 // re-queued after those two refreshed
        assertThat(cache.expandBatch(100)).as("all six rows were refreshed before the re-queue").isEqualTo(6);
        assertThat(count("ownership_cache_invalidation")).isZero();

        drain();
        assertCacheMatchesLive();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_effective_cache WHERE owner_team_id = ?", Integer.class, payments))
                .isEqualTo(6);
    }

    @Test
    void filtersAndCoverageReadTheCacheAndReportRowsAwaitingRefresh() {
        setCoreCanonical();
        UUID asset = asset("web-1");
        UUID subject = inventory.subjectForAsset(asset).orElseThrow();
        claims.recordClaim(serviceNow(subject, payments, "web-1"));
        drain();
        assertThat(reads.filter(Consumer.INVENTORY, payments, null, 10, null)).containsExactly(asset);
        assertThat(reads.coverage(Consumer.INVENTORY)).isEqualTo(new Coverage("CANONICAL", 1, 0, 0, 0, 0));

        claims.recordClaim(manual(subject, identity));
        // Detail reads are live and see the change at once.
        assertThat(reads.forAssets(List.of(asset)).get(0).ownerTeamId()).isEqualTo(identity);
        // List reads serve the previous result, flagged as refreshing, until the row refreshes.
        cache.expandBatch(100);
        assertThat(reads.filter(Consumer.INVENTORY, payments, null, 10, null)).containsExactly(asset);
        assertThat(reads.coverage(Consumer.INVENTORY).refreshing()).isEqualTo(1);

        assertThat(reads.forAllAssets().get(asset).ownerTeamId()).as("bulk list read lags with the cache").isEqualTo(payments);

        cache.refreshBatch(100);
        assertThat(reads.forAllAssets().get(asset).ownerTeamName()).isEqualTo("Identity");
        assertThat(reads.filter(Consumer.INVENTORY, payments, null, 10, null)).isEmpty();
        assertThat(reads.filter(Consumer.INVENTORY, identity, null, 10, null)).containsExactly(asset);
        assertThat(reads.coverage(Consumer.INVENTORY)).isEqualTo(new Coverage("CANONICAL", 1, 0, 0, 0, 0));

        UUID unlinked = asset("web-2");
        assertThat(reads.filter(Consumer.INVENTORY, null, "UNOWNED", 10, null)).containsExactly(unlinked);
    }

    @Test
    void qualificationIsBlockedUntilTheCacheReflectsEveryRecordedChange() {
        asset("web-1");
        cutover.transition(Domain.CORE, State.DARK, null, "admin");
        enter(tenant);
        maintenance.runForTenant(tenant);
        enter(tenant);
        var ready = cutover.qualify(Domain.CORE);
        assertThat(ready.checks()).containsEntry("effectiveCacheBacklog", 0L);
        assertThat(ready.passed()).as(String.valueOf(ready.blockers())).isTrue();

        subject("APPLICATION", "late-arrival");
        var blocked = cutover.qualify(Domain.CORE);
        assertThat(blocked.passed()).isFalse();
        assertThat(blocked.blockers()).anyMatch(b -> b.startsWith("effectiveCacheBacklog"));
    }

    @Test
    void reconciliationRebuildsMissingRows() {
        UUID host = subject("HOST", "web-1");
        drain();
        jdbc.update("DELETE FROM ownership_effective_cache WHERE subject_id = ?", host);
        assertThat(cache.backlog().missingRows()).isEqualTo(1);

        assertThat(cache.reconcileMissing(100)).isEqualTo(1);
        assertThat(cache.reconcileMissing(100)).as("already queued").isZero();
        drain();
        assertThat(cache.backlog().total()).isZero();
        assertCacheMatchesLive();
    }

    @Test
    void cacheWorkStaysInsideItsTenant() {
        enter(other);
        UUID foreign = subject("HOST", "web-1");
        enter(tenant);
        subject("HOST", "web-1");
        drain();
        assertThat(count("ownership_effective_cache")).isEqualTo(1);

        enter(other);
        assertThat(jdbc.queryForList("SELECT subject_id FROM ownership_cache_invalidation", UUID.class)).containsExactly(foreign);
        assertThat(count("ownership_effective_cache")).isZero();
    }

    private void drain() {
        maintenance.runForTenant(tenant);
        enter(tenant);
    }

    private void assertCacheMatchesLive() {
        List<UUID> drift = jdbc.queryForList("""
                SELECT s.id FROM ownership_subject s
                  JOIN ownership_effective_assignment e ON e.subject_id = s.id
                  LEFT JOIN ownership_effective_cache c ON c.subject_id = s.id
                 WHERE s.lifecycle_status = 'ACTIVE'
                   AND (c.subject_id IS NULL OR c.invalidated_at IS NOT NULL
                        OR c.ownership_status IS DISTINCT FROM e.ownership_status
                        OR c.owner_team_id IS DISTINCT FROM CASE WHEN e.ownership_status = 'OWNED' THEN e.owner_team_id END
                        OR c.origin_subject_id IS DISTINCT FROM e.ownership_origin_subject_id
                        OR c.inheritance_path <> e.inheritance_path
                        OR c.inheritance_depth <> e.inheritance_depth)
                """, UUID.class);
        assertThat(drift).isEmpty();
    }

    private void assertCached(UUID subject, String status, UUID team, int depth) {
        var row = jdbc.queryForMap("SELECT ownership_status, owner_team_id, inheritance_depth FROM ownership_effective_cache WHERE subject_id = ?",
                subject);
        assertThat(row.get("ownership_status")).isEqualTo(status);
        assertThat(row.get("owner_team_id")).isEqualTo(team);
        assertThat(((Number) row.get("inheritance_depth")).intValue()).isEqualTo(depth);
    }

    private int invalidated() {
        return jdbc.queryForObject("SELECT count(*) FROM ownership_effective_cache WHERE invalidated_at IS NOT NULL", Integer.class);
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM " + table, Integer.class);
    }

    private UUID subject(String type, String sourceId) {
        return subjects.register(type, sourceId, null).id();
    }

    private UUID asset(String identifier) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type)
                VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')""", id, identifier, identifier);
        return id;
    }

    private void setCoreCanonical() {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by)
                VALUES (?, 'CORE', 'CANONICAL', 'test', now(), 'test')""", tenant.getId()));
        enter(tenant);
    }

    private static ClaimRequest serviceNow(UUID subject, UUID team, String ci) {
        Instant now = Instant.now();
        return new ClaimRequest(subject, team, null, "SERVICENOW", "SERVICENOW", null, "cmdb_ci:" + ci, "v1", "sn-cmdb-1",
                now, now.plus(Duration.ofHours(12)), now.plus(Duration.ofDays(7)), null, "servicenow-producer");
    }

    private static ClaimRequest manual(UUID subject, UUID team) {
        return new ClaimRequest(subject, team, null, "MANUAL", "MANUAL", null, "manual:" + subject, UUID.randomUUID().toString(),
                "manual-1", Instant.now(), null, null, "service owner confirmed in review", "admin");
    }

    private Tenant newTenant() {
        String slug = "own-cache-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        return tenantService.resolveTenantUuid(created.getId());
    }

    private void enter(Tenant t) {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(t.getId());
        TenantContext.setCurrentSchemaName(t.getSchemaName());
    }
}
