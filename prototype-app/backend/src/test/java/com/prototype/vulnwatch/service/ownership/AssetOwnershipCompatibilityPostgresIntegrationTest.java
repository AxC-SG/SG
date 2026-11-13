package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AssetResponse;
import com.prototype.vulnwatch.dto.HostAssetDetailResponse;
import com.prototype.vulnwatch.service.AssetQueryService;
import com.prototype.vulnwatch.service.HostInventoryReadService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
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
 * Real-PostgreSQL proof for the inventory compatibility read (plan §9.3, §9.4, §15.4): asset list and host detail
 * carry a resolved-ownership envelope next to the untouched raw evidence once CORE inventory is canonical, and an
 * asset type from a later domain stays pending migration.
 */
@PostgresIntegrationTest
class AssetOwnershipCompatibilityPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("asset_ownership_compat");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.read-waves.inventory", () -> "*");
    }

    @Autowired private AssetQueryService assets;
    @Autowired private HostInventoryReadService hosts;
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
        String slug = "own-asset-" + UUID.randomUUID().toString().substring(0, 8);
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
    void assetListAndHostDetailCarryTheCanonicalEnvelopeBesideRawEvidence() {
        UUID host = asset("web-1", "HOST");
        UUID bucket = asset("bucket-1", "CLOUD_RESOURCE");
        ci(host);

        // Nothing canonical yet: no envelope, raw fields unchanged.
        assertThat(list().get(host).ownership()).isNull();
        assertThat(hosts.getHostDetail(tenant, host, null).ownership()).isNull();

        UUID subject = inventory.subjectForAsset(host).orElseThrow();
        inventory.subjectForAsset(bucket);
        claims.recordClaim(new ClaimRequest(subject, payments, null, "SERVICENOW", "SERVICENOW", null, "cmdb_ci:web-1",
                "v1", "sn", Instant.now(), null, null, null, "sn"));
        setCoreCanonical();

        Map<UUID, AssetResponse> after = list();
        AssetResponse hostRow = after.get(host);
        assertThat(hostRow.ownerTeam()).as("raw evidence is kept, not relabelled").isEqualTo("Legacy Ops");
        assertThat(hostRow.ownership().authorityState()).isEqualTo("CANONICAL");
        assertThat(hostRow.ownership().ownerTeamId()).isEqualTo(payments);
        assertThat(hostRow.ownership().ownerTeamName()).isEqualTo("Payments");
        assertThat(hostRow.ownership().ownershipStatus()).isEqualTo("OWNED");

        // CLOUD_RESOURCE belongs to the Release-2 domain: pending migration with its legacy label, never Unowned.
        AssetResponse bucketRow = after.get(bucket);
        assertThat(bucketRow.ownership().authorityDomain()).isEqualTo("CLOUD_BOM");
        assertThat(bucketRow.ownership().authorityState()).isEqualTo("LEGACY_PENDING_MIGRATION");
        assertThat(bucketRow.ownership().ownershipStatus()).isNull();
        assertThat(bucketRow.ownership().legacyOwnerLabel()).isEqualTo("Legacy Ops");

        HostAssetDetailResponse detail = hosts.getHostDetail(tenant, host, null);
        assertThat(detail.ownership().ownerTeamName()).isEqualTo("Payments");
        assertThat(detail.host().supportGroup()).isEqualTo("SN-NET-OPS");
    }

    private Map<UUID, AssetResponse> list() {
        return assets.listAssets(tenant).stream().collect(Collectors.toMap(AssetResponse::id, r -> r));
    }

    private UUID asset(String identifier, String type) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, owner_team, support_group)
                VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', ?, 'Legacy Ops', 'SN-NET-OPS')""", id, identifier, identifier, type);
        return id;
    }

    private void ci(UUID asset) {
        jdbc.update("""
                INSERT INTO cis (id, business_criticality, created_at, display_name, sys_id, updated_at, asset_id, support_group)
                VALUES (?, 'HIGH', now(), 'web-1', ?, now(), ?, 'SN-NET-OPS')""", UUID.randomUUID(), "sys-" + asset, asset);
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
