package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.ServiceNowOwnershipProducer.Result;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Real-PostgreSQL proof for the ServiceNow CMDB ownership producer (plan §6.4, §6.8, §12.3). */
@PostgresIntegrationTest
class ServiceNowOwnershipProducerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_servicenow");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private ServiceNowOwnershipProducer producer;
    @Autowired private TeamNamespaceService teams;
    @Autowired private OwnershipResolutionService resolution;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID identity;

    @BeforeEach
    void setUp() {
        String slug = "own-sn-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, updated_by) VALUES (?, 'CORE', 'DARK', 'test')""",
                tenant.getId()));
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
        identity = teams.createTeam("Identity", null, null, "admin").id();
        teams.addAlias(payments, "PAY-SUPPORT", "SERVICENOW", null, "admin");
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_kill_switches WHERE tenant_id = ?", tenant.getId()));
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void mapsSupportGroupsByNameOrAliasAndSendsUnmappedValuesToReview() {
        Instant run = Instant.now().minusSeconds(1);
        UUID web = ci("sn-web", "PAY-SUPPORT");
        UUID db = ci("sn-db", "Identity");
        UUID odd = ci("sn-odd", "Mystery Ops");
        Result result = producer.publish(tenant.getId(), run, true, false);
        enter();
        assertThat(result.created()).isEqualTo(2);
        assertThat(result.unmapped()).isEqualTo(1);
        assertThat(ownerOf(web)).isEqualTo(payments);
        assertThat(ownerOf(db)).isEqualTo(identity);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM team", Integer.class)).isEqualTo(2);
        String stored = jdbc.queryForObject("SELECT unresolved_value_enc FROM ownership_review_item WHERE item_type = 'UNMAPPED_VALUE'", String.class);
        assertThat(stored).startsWith("enc:t1:").doesNotContain("Mystery");
        assertThat(jdbc.queryForObject("SELECT ownership_subject_id IS NOT NULL FROM assets WHERE id = ?", Boolean.class, odd)).isTrue();
    }

    @Test
    void unchangedRerunReobservesWithoutWritesAndAChangedGroupMovesOwnership() {
        UUID web = ci("sn-web", "Payments");
        producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        UUID subject = subjectOf(web);
        long version = resolution.current(subject).orElseThrow().version();
        int claimRows = count("ownership_claim");

        touch("sn-web", "Payments");
        Result again = producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        assertThat(again.reobserved()).isEqualTo(1);
        assertThat(count("ownership_claim")).isEqualTo(claimRows);
        assertThat(resolution.current(subject).orElseThrow().version()).isEqualTo(version);

        touch("sn-web", "Identity");
        Result changed = producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        assertThat(changed.changed()).isEqualTo(1);
        assertThat(ownerOf(web)).isEqualTo(identity);
    }

    @Test
    void absentCisEndClaimsOnlyAfterACompleteScan() {
        UUID web = ci("sn-web", "Payments");
        ci("sn-db", "Payments");
        producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        Instant later = Instant.now().plusSeconds(1);
        touch("sn-db", "Payments", later.plusSeconds(1)); // only sn-db is seen by the next run

        producer.publish(tenant.getId(), later, false, false);
        enter();
        assertThat(ownerOf(web)).isEqualTo(payments);

        Result complete = producer.publish(tenant.getId(), later, true, false);
        enter();
        assertThat(complete.ended()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT ownership_status FROM ownership_effective_assignment WHERE subject_id = ?", String.class,
                subjectOf(web))).isEqualTo("UNOWNED");
    }

    @Test
    void aRunThatWouldChangeTooManyClaimsPausesWithAReviewItem() {
        for (int i = 0; i < 60; i++) ci("sn-" + i, "Payments");
        producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        Instant run = Instant.now().plusSeconds(1);
        for (int i = 0; i < 60; i++) touch("sn-" + i, i < 20 ? "Identity" : "Payments", run.plusSeconds(1));

        Result paused = producer.publish(tenant.getId(), run, true, false);
        enter();
        assertThat(paused.paused()).isTrue();
        assertThat(paused.pauseReason()).isEqualTo("ANOMALY");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_claim WHERE team_id = ?", Integer.class, identity)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_review_item WHERE item_type = 'PRODUCER_ANOMALY'", Integer.class)).isEqualTo(1);

        Result approved = producer.publish(tenant.getId(), run, true, true);
        enter();
        assertThat(approved.changed()).isEqualTo(20);
    }

    @Test
    void aLegacyDomainPublishesNothing() {
        ci("sn-web", "Payments");
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
        Result result = producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        assertThat(result.pauseReason()).isEqualTo("DOMAIN_LEGACY");
        assertThat(count("ownership_claim")).isZero();
    }

    @Test
    void aPausedSourcePublishesNothing() {
        ci("sn-web", "Payments");
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_kill_switches (id, source_kind, tenant_id, state, reason, updated_by)
                VALUES (?, 'SERVICENOW', ?, 'PAUSED', 'test', 'sre')""", UUID.randomUUID(), tenant.getId()));
        Result result = producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        assertThat(result.pauseReason()).isEqualTo("SOURCE_PAUSED");
        assertThat(count("ownership_claim")).isZero();
    }

    private UUID ci(String sysId, String supportGroup) {
        UUID asset = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, support_group, last_cmdb_sync_at)
                VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST', ?, now())""", asset, sysId, sysId, supportGroup);
        jdbc.update("""
                INSERT INTO cis (id, business_criticality, created_at, display_name, sys_id, updated_at, asset_id, support_group, last_cmdb_sync_at)
                VALUES (?, 'HIGH', now(), ?, ?, now(), ?, ?, now())""", UUID.randomUUID(), sysId, sysId, asset, supportGroup);
        return asset;
    }

    private void touch(String sysId, String supportGroup) {
        touch(sysId, supportGroup, Instant.now());
    }

    private void touch(String sysId, String supportGroup, Instant at) {
        jdbc.update("UPDATE cis SET support_group = ?, last_cmdb_sync_at = ? WHERE sys_id = ?", supportGroup, Timestamp.from(at), sysId);
    }

    private UUID subjectOf(UUID asset) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM assets WHERE id = ?", UUID.class, asset);
    }

    private UUID ownerOf(UUID asset) {
        return jdbc.queryForObject("""
                SELECT e.owner_team_id FROM assets a JOIN ownership_effective_assignment e ON e.subject_id = a.ownership_subject_id
                 WHERE a.id = ?""", UUID.class, asset);
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM " + table, Integer.class);
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
