package com.prototype.vulnwatch.service.fix;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FixControlRequest;
import com.prototype.vulnwatch.dto.FixDetailResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.fix.FixIntelligenceQueryService.ListFilter;
import com.prototype.vulnwatch.service.patch.PatchIngestionService;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/** Patch ingestion and the fix lifecycle against two real tenant schemas. */
@PostgresIntegrationTest
class FixIntelligenceTenantScopingPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("fix_intelligence_tenant_scoping");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private FixIntelligenceQueryService queries;
    @Autowired private FixManagementService management;
    @Autowired private PatchIngestionService ingestion;
    @Autowired private AssetRepository assets;

    @Test
    void controlsAreInvisibleAndImmutableFromAnotherTenant() {
        Tenant first = tenant();
        Tenant second = tenant();
        UUID fixId = tenantExecution.run(first, () -> management.create(first, "alice", new FixControlRequest(
                "COMPENSATING_CONTROL", "Block SMB at the perimeter", null, "HIGH", "WINDOWS", null, null, null, null,
                "NETWORK", null, null, "LOW", null, List.of("CVE-2024-21412"), List.of(), true, null)));

        assertEquals(HttpStatus.NOT_FOUND, status(() -> tenantExecution.run(second, () -> queries.detail(second, fixId))));
        assertEquals(HttpStatus.NOT_FOUND, status(() -> tenantExecution.run(second, () -> {
            management.approve(second, "bob", fixId);
            return null;
        })));
        assertEquals(0, tenantExecution.run(second, () -> queries.list(second, filter("all"), 0, 50)).totalItems());
        assertEquals(0, tenantExecution.run(second, () -> queries.summary(second, "all")).totalFixes());

        // The proposer cannot approve their own control; someone else can.
        assertEquals(HttpStatus.FORBIDDEN, status(() -> tenantExecution.run(first, () -> {
            management.approve(first, "alice", fixId);
            return null;
        })));
        tenantExecution.run(first, () -> {
            management.approve(first, "bob", fixId);
            return null;
        });
        FixDetailResponse approved = tenantExecution.run(first, () -> queries.detail(first, fixId));
        assertEquals(FixRecord.Status.ACTIVE.name(), approved.status());
        assertEquals("bob", approved.approvedBy());
        assertEquals(1, tenantExecution.run(first, () -> queries.list(first, filter("compensating-controls"), 0, 50)).totalItems());
        assertEquals(1, tenantExecution.run(first, () -> queries.context(first, "CVE-2024-21412", null)).fixes().size());
        assertEquals(0, tenantExecution.run(second, () -> queries.context(second, "CVE-2024-21412", null)).fixes().size());
    }

    @Test
    void patchIngestionMatchesAndCreatesDevicesOnlyWithinTheTenant() {
        Tenant first = tenant();
        Tenant second = tenant();
        PatchSnapshot snapshot = new PatchSnapshot(
                List.of(new PatchSnapshot.Device("16777220", "WS-01.corp.example.com", "SN-1", "Windows 11")),
                List.of(new PatchSnapshot.Patch("16801234", "5034441", null, "2026-10 Cumulative Update", "Microsoft", null,
                        "Security Updates", "Critical", "CRITICAL", FixRecord.Ecosystem.WINDOWS, Instant.now(), false,
                        "https://support.microsoft.com/kb/5034441", List.of("CVE-2024-20666"))),
                List.of(),
                List.of(new PatchSnapshot.Status("16777220", "16801234", FixAssetStatus.MISSING, null, null, null, null, null)),
                true, List.of());

        PatchIngestionService.Result firstRun = tenantExecution.run(first, () -> ingestion.ingest(first, PatchProviderType.SCCM, snapshot));
        PatchIngestionService.Result secondRun = tenantExecution.run(second, () -> ingestion.ingest(second, PatchProviderType.SCCM, snapshot));

        // The same device identity in another tenant is a different host there, never a match.
        assertEquals(1, firstRun.hostsCreated());
        assertEquals(1, secondRun.hostsCreated());
        UUID firstAsset = tenantExecution.run(first, () -> assets.findAll().get(0).getId());
        UUID secondAsset = tenantExecution.run(second, () -> assets.findAll().get(0).getId());
        assertNotEquals(firstAsset, secondAsset);

        // A rerun matches the existing identity instead of creating another host.
        PatchIngestionService.Result rerun = tenantExecution.run(first, () -> ingestion.ingest(first, PatchProviderType.SCCM, snapshot));
        assertEquals(0, rerun.hostsCreated());
        assertEquals(1, rerun.devicesMatched());

        var patches = tenantExecution.run(first, () -> queries.list(first, filter("patches"), 0, 50));
        assertEquals(1, patches.totalItems());
        assertEquals(1, tenantExecution.run(first, () -> queries.context(first, null, firstAsset)).fixes().size());
        assertEquals(0, tenantExecution.run(second, () -> queries.context(second, null, firstAsset)).fixes().size());

        // Patch-tool records are read-only to analysts.
        UUID patchId = patches.items().get(0).id();
        assertEquals(HttpStatus.CONFLICT, status(() -> tenantExecution.run(first, () -> {
            management.retire(first, patchId);
            return null;
        })));
    }

    private Tenant tenant() {
        String slug = "fix-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        return tenants.resolveTenantUuid(tenant.getId());
    }

    private static ListFilter filter(String view) {
        return new ListFilter(view, null, null, null, null);
    }

    private static HttpStatus status(Runnable call) {
        ResponseStatusException failure = assertThrows(ResponseStatusException.class, call::run);
        return HttpStatus.valueOf(failure.getStatusCode().value());
    }
}
