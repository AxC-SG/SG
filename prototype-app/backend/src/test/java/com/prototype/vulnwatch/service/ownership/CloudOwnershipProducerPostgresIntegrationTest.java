package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.AccountRead;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Provider;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Result;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Run;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Scope;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.sql.Timestamp;
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

/** Real-PostgreSQL proof for the AWS/GCP ownership producer (Phase 0B §2.1–§2.8). */
@PostgresIntegrationTest
class CloudOwnershipProducerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_cloud");
    private static final String ACCOUNT = "111122223333";

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private CloudOwnershipProducer producer;
    @Autowired private CloudOwnershipSourceService sources;
    @Autowired private TeamNamespaceService teams;
    @Autowired private OwnershipResolutionService resolution;
    @Autowired private OwnershipSubjectService subjects;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID identity;

    @BeforeEach
    void setUp() {
        String slug = "own-cloud-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        authority("CORE", "CANONICAL");
        authority("CLOUD_BOM", "DARK");
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
        identity = teams.createTeam("Identity", null, null, "admin").id();
        jdbc.update("""
                INSERT INTO aws_discovery_configs (id, auth_type, auto_sync_enabled, created_at, enabled, interval_minutes, regions_json,
                    resource_types_json, source_system, updated_at)
                VALUES (gen_random_uuid(), 'INSTANCE_METADATA', false, now(), true, 60, '[]', '[]', 'aws', now())""");
        jdbc.update("INSERT INTO gcp_discovery_configs (id, interval_minutes) VALUES (gen_random_uuid(), 1440)");
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_kill_switches WHERE tenant_id = ?", tenant.getId()));
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void resourceTagsBecomeClaimsThatOwnNothingUntilCloudBomIsCanonical() {
        UUID web = ec2("i-web", "us-east-1", "{\"Owner \":\"Payments\",\"Name\":\"web\"}");
        Result result = producer.publish(tenant.getId(), aws(scope("us-east-1")));
        enter();
        assertThat(result.created()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT source_ref || '|' || priority_class || '|' || producer_version FROM ownership_claim", String.class))
                .isEqualTo("aws:asset:" + web + ":tag:owner|CLOUD_TAG|aws-ownership-1");
        // CORE is canonical, but an AWS claim must not move a canonical host's owner while CLOUD_BOM is DARK (§2.6).
        assertThat(ownerOf(web)).isNull();
        // Every resource hangs under its account subject.
        UUID account = subjects.find("CLOUD_ACCOUNT", "aws:" + ACCOUNT, "").orElseThrow().id();
        assertThat(subjects.currentParent(subjectOf(web))).contains(account);

        authority("CLOUD_BOM", "CANONICAL");
        enter();
        resolution.resolveSubject(subjectOf(web), "test");
        assertThat(ownerOf(web)).isEqualTo(payments);
    }

    @Test
    void reobservesUnchangedValuesThenFollowsAChangeAndEndsAClearedKey() {
        authority("CLOUD_BOM", "CANONICAL");
        UUID web = ec2("i-web", "us-east-1", "{\"team\":\"Payments\"}");
        producer.publish(tenant.getId(), aws(scope("us-east-1")));
        enter();
        int rows = count("ownership_claim");

        touch(web, "{\"team\":\"Payments\"}");
        assertThat(producer.publish(tenant.getId(), aws(scope("us-east-1"))).reobserved()).isEqualTo(1);
        enter();
        assertThat(count("ownership_claim")).isEqualTo(rows);

        touch(web, "{\"team\":\"Identity\"}");
        assertThat(producer.publish(tenant.getId(), aws(scope("us-east-1"))).changed()).isEqualTo(1);
        enter();
        assertThat(ownerOf(web)).isEqualTo(identity);

        // The provider reported the resource without the key: an authoritative observation that ends the claim.
        touch(web, "{\"Name\":\"web\"}");
        assertThat(producer.publish(tenant.getId(), aws(scope("us-east-1"))).ended()).isEqualTo(1);
        enter();
        assertThat(activeClaims()).isZero();
    }

    @Test
    void absentResourcesEndOnlyInsideScopesTheRunListedCompletely() {
        UUID east = ec2("i-east", "us-east-1", "{\"team\":\"Payments\"}");
        UUID west = ec2("i-west", "eu-west-1", "{\"team\":\"Payments\"}");
        producer.publish(tenant.getId(), aws(scope("us-east-1"), scope("eu-west-1")));
        enter();
        assertThat(activeClaims()).isEqualTo(2);

        // Neither instance was seen again; only us-east-1 was listed completely (eu-west-1 failed).
        age(east);
        age(west);
        Result result = producer.publish(tenant.getId(), aws(scope("us-east-1")));
        enter();
        assertThat(result.ended()).isEqualTo(1);
        assertThat(jdbc.queryForList("SELECT source_ref FROM ownership_claim WHERE status = 'ACTIVE'", String.class))
                .containsExactly("aws:asset:" + west + ":tag:team");
    }

    @Test
    void unmappedAndOversizedValuesGoToReviewEncryptedAndCreateNoTeam() {
        ec2("i-mail", "us-east-1", "{\"owner\":\"alice@example.com\"}");
        ec2("i-long", "us-east-1", "{\"team\":\"" + "x".repeat(300) + "\"}");
        Result result = producer.publish(tenant.getId(), aws(scope("us-east-1")));
        enter();
        assertThat(result.unmapped()).isEqualTo(2);
        assertThat(activeClaims()).isZero();
        assertThat(count("team")).isEqualTo(2);
        assertThat(jdbc.queryForList("SELECT unresolved_value_enc FROM ownership_review_item WHERE item_type = 'UNMAPPED_VALUE'", String.class))
                .hasSize(2).allSatisfy(value -> assertThat(value).startsWith("enc:t1:").doesNotContain("alice"));
    }

    @Test
    void projectLabelsClaimTheProjectAndAFailedReadChangesNothing() {
        authority("CLOUD_BOM", "CANONICAL");
        UUID vm = gce("vm-1", "proj-1", "{}");
        producer.publish(tenant.getId(), gcp(List.of(new AccountRead("proj-1", Map.of("team", "payments")))));
        enter();
        UUID project = subjects.find("CLOUD_ACCOUNT", "gcp:proj-1", "").orElseThrow().id();
        assertThat(jdbc.queryForObject("SELECT priority_class || '|' || source_ref FROM ownership_claim WHERE subject_id = ?", String.class, project))
                .isEqualTo("CLOUD_STRUCTURED|gcp:project:proj-1:label:team");
        // The VM has no label of its own, so it inherits the project's owner (§2.7).
        assertThat(ownerOf(vm)).isEqualTo(payments);

        touch(vm, "{}");
        producer.publish(tenant.getId(), gcp(List.of(new AccountRead("proj-1", null))));
        enter();
        assertThat(activeClaims()).isEqualTo(1);

        touch(vm, "{}");
        assertThat(producer.publish(tenant.getId(), gcp(List.of(new AccountRead("proj-1", Map.of())))).ended()).isEqualTo(1);
        enter();
        assertThat(activeClaims()).isZero();
    }

    @Test
    void aParentSetElsewhereIsKeptAndRaisesAnInheritanceError() {
        UUID web = ec2("i-web", "us-east-1", "{}");
        enter();
        UUID child = new InventorySubjectAdapterAccess(jdbc).subjectOf(web, subjects);
        UUID app = subjects.register("APPLICATION", "app:checkout", null).id();
        subjects.setParent(child, app, "admin");

        producer.publish(tenant.getId(), aws(scope("us-east-1")));
        enter();
        assertThat(subjects.currentParent(child)).contains(app);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_review_item WHERE item_type = 'INHERITANCE_ERROR'", Integer.class))
                .isEqualTo(1);
    }

    @Test
    void aMassRetagPausesTheSourceUntilAnAdminResumesIt() {
        List<UUID> assets = new java.util.ArrayList<>();
        for (int i = 0; i < 120; i++) assets.add(ec2("i-" + i, "us-east-1", "{\"team\":\"Payments\"}"));
        assertThat(producer.publish(tenant.getId(), aws(scope("us-east-1"))).created()).as("baseline load").isEqualTo(120);
        enter();

        assets.forEach(asset -> touch(asset, "{\"team\":\"Identity\"}"));
        Result tripped = producer.publish(tenant.getId(), aws(scope("us-east-1")));
        enter();
        assertThat(tripped.pauseReason()).isEqualTo("ANOMALY");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_claim WHERE status = 'ACTIVE' AND team_id = ?", Integer.class, payments))
                .isEqualTo(120);
        assertThat(sources.status(Provider.AWS).paused()).isTrue();
        assertThat(producer.publish(tenant.getId(), aws(scope("us-east-1"))).pauseReason()).isEqualTo("SOURCE_PAUSED");
        enter();

        sources.resume(Provider.AWS, "admin");
        assets.forEach(asset -> touch(asset, "{\"team\":\"Identity\"}"));
        assertThat(producer.publish(tenant.getId(), aws(scope("us-east-1"))).changed()).as("approved once").isEqualTo(120);
        enter();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_review_item WHERE item_type = 'PRODUCER_ANOMALY' AND state = 'OPEN'",
                Integer.class)).isZero();
    }

    @Test
    void switchingAKeyOffEndsItsClaimsAndTheProducerIgnoresIt() {
        ec2("i-web", "us-east-1", "{\"owner\":\"Payments\",\"team\":\"Identity\"}");
        producer.publish(tenant.getId(), aws(scope("us-east-1")));
        enter();
        assertThat(activeClaims()).isEqualTo(2);

        sources.updateSettings(Provider.AWS, new CloudOwnershipSourceService.SettingsRequest(false, null, null), "admin");
        assertThat(jdbc.queryForList("SELECT source_ref FROM ownership_claim WHERE status = 'ACTIVE'", String.class))
                .singleElement().satisfies(ref -> assertThat(ref).endsWith(":tag:team"));
        assertThat(count("ownership_resolution_queue")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE action = 'ownership.cloud_producer.settings_updated'",
                Integer.class)).isEqualTo(1);
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    /** Registers the asset's subject the way the producer would, so a test can set a foreign parent first. */
    private record InventorySubjectAdapterAccess(JdbcTemplate jdbc) {
        UUID subjectOf(UUID asset, OwnershipSubjectService subjects) {
            UUID subject = subjects.register("HOST", asset.toString(), null).id();
            jdbc.update("UPDATE assets SET ownership_subject_id = ? WHERE id = ?", subject, asset);
            return subject;
        }
    }

    private Run aws(Scope... scopes) {
        return new Run(Provider.AWS, Instant.now().minusSeconds(5), List.of(scopes), List.of());
    }

    private Run gcp(List<AccountRead> reads) {
        return new Run(Provider.GCP, Instant.now().minusSeconds(5), List.of(new Scope("proj-1", "compute.googleapis.com/Instance", null)), reads);
    }

    private static Scope scope(String region) {
        return new Scope(ACCOUNT, "EC2", region);
    }

    private UUID ec2(String id, String region, String tags) {
        return cloudAsset("aws", ACCOUNT, "EC2", region, "arn:aws:ec2:" + region + ":" + ACCOUNT + ":instance/" + id, tags);
    }

    private UUID gce(String id, String project, String labels) {
        return cloudAsset("gcp", project, "compute.googleapis.com/Instance", "us-central1",
                "//compute.googleapis.com/projects/" + project + "/zones/us-central1-a/instances/" + id, labels);
    }

    private UUID cloudAsset(String provider, String account, String type, String region, String identifier, String tags) {
        enter();
        UUID asset = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, cloud_provider, cloud_account_id,
                    cloud_resource_type, cloud_region, cloud_tags_json, last_cmdb_sync_at)
                VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST', ?, ?, ?, ?, ?, now())""",
                asset, identifier, identifier, provider, account, type, region, tags);
        return asset;
    }

    private void touch(UUID asset, String tags) {
        enter();
        jdbc.update("UPDATE assets SET cloud_tags_json = ?, last_cmdb_sync_at = now() WHERE id = ?", tags, asset);
    }

    private void age(UUID asset) {
        enter();
        jdbc.update("UPDATE assets SET last_cmdb_sync_at = ? WHERE id = ?", Timestamp.from(Instant.now().minusSeconds(3600)), asset);
    }

    private void authority(String domain, String state) {
        boolean canonical = "CANONICAL".equals(state);
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by)
                VALUES (?, ?, ?, ?, CASE WHEN ? THEN now() END, 'test')
                ON CONFLICT (tenant_id, domain) DO UPDATE SET state = EXCLUDED.state, accepted_by = EXCLUDED.accepted_by,
                       accepted_at = EXCLUDED.accepted_at""", tenant.getId(), domain, state, canonical ? "test" : null, canonical));
    }

    private UUID subjectOf(UUID asset) {
        return jdbc.queryForObject("SELECT ownership_subject_id FROM assets WHERE id = ?", UUID.class, asset);
    }

    private UUID ownerOf(UUID asset) {
        return jdbc.query("""
                SELECT e.owner_team_id FROM assets a JOIN ownership_effective_assignment e ON e.subject_id = a.ownership_subject_id
                 WHERE a.id = ?""", rs -> rs.next() ? rs.getObject(1, UUID.class) : null, asset);
    }

    private int activeClaims() {
        return jdbc.queryForObject("SELECT count(*) FROM ownership_claim WHERE status = 'ACTIVE'", Integer.class);
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
