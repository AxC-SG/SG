package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class SccmInventoryCapturePostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("sccm_inventory_capture");
    private static final CmdbIngestionService.HostInventorySourceDescriptor DESCRIPTOR =
            new CmdbIngestionService.HostInventorySourceDescriptor(
                    "sccm-test", "sccm-jdbc", "sccm", "inventory", null, "application/json", null);

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaExecutionService schemas;
    @Autowired private SyncRunRepository runs;
    @Autowired private AssetRepository assets;
    @Autowired private InventoryComponentRepository components;
    @Autowired private TransactionTemplate transactions;
    @Autowired private SccmInventoryCaptureService captures;
    @MockitoSpyBean private SccmQueryService query;
    @MockitoSpyBean private CmdbIngestionService inventory;

    @Test
    void restartingUnsealedCollectionDoesNotMergeRowsFromTheFailedAttempt() throws Exception {
        var tenant = tenants.getDefaultTenant();
        var config = config(tenant);
        UUID run = schemas.run(tenant, () -> run(tenant));
        var firstTry = new AtomicBoolean(true);
        doAnswer(call -> {
            var page = call.<Consumer<List<Map<String, String>>>>getArgument(1);
            if (firstTry.getAndSet(false)) {
                page.accept(List.of(install("11", "unverified")));
                throw new IllegalStateException("Cursor was interrupted");
            }
            page.accept(List.of(install("11", "approved")));
            page.accept(List.of(install("11", "second-product"), install("12", "approved")));
            return null;
        }).when(query).forEachInstallPage(eq(config), any());

        schemas.run(tenant, () -> {
            assertThrows(IllegalStateException.class,
                    () -> captures.collectAndIngest(config, run, "sccm", DESCRIPTOR, ignored -> {}));
            assertFalse(assets.findByIdentifier("ci:11").isPresent());
            var result = assertDoesNotThrow(() ->
                    captures.collectAndIngest(config, run, "sccm", DESCRIPTOR, ignored -> {}));
            assertEquals(3, result.installRowsProcessed());
            assertEquals(2, result.discoveryRowsProcessed());
            assertEquals(2, result.assetsIngested());
            var host = assets.findByIdentifier("ci:11").orElseThrow();
            assertEquals(List.of("approved", "second_product"), components.findByAsset_IdIn(List.of(host.getId()))
                    .stream().map(component -> component.getPackageName()).sorted().toList());
            transactions.executeWithoutResult(status -> captures.finish(run));
            assertFalse(captures.exists(run));
        });
    }

    @Test
    void resumingASealedRunReusesItsCaptureAndCommittedCounts() throws Exception {
        var tenant = tenants.getDefaultTenant();
        var config = config(tenant);
        UUID run = schemas.run(tenant, () -> run(tenant));
        doAnswer(call -> {
            call.<Consumer<List<Map<String, String>>>>getArgument(1)
                    .accept(List.of(install("21", "cached"), install("22", "pending")));
            return null;
        }).when(query).forEachInstallPage(eq(config), any());
        var interrupt = new AtomicBoolean(true);
        doAnswer(call -> {
            var rows = call.<List<Map<String, String>>>getArgument(2);
            if (!rows.isEmpty() && "22".equals(rows.get(0).get("sys_id")) && interrupt.getAndSet(false)) {
                throw new AssertionError("Worker was interrupted");
            }
            return call.callRealMethod();
        }).when(inventory).ingestRows(eq(tenant), eq("sccm"), any(), any(), eq(DESCRIPTOR));

        schemas.run(tenant, () -> {
            assertThrows(AssertionError.class,
                    () -> captures.collectAndIngest(config, run, "sccm", DESCRIPTOR, ignored -> {}));
            var accepted = assets.findByIdentifier("ci:21").orElseThrow();
            var originalUpload = components.findByAsset_IdIn(List.of(accepted.getId())).get(0).getSbomUpload().getId();
            assertFalse(assets.findByIdentifier("ci:22").isPresent());

            var completed = assertDoesNotThrow(() ->
                    captures.collectAndIngest(config, run, "sccm", DESCRIPTOR, ignored -> {}));
            var replayed = assertDoesNotThrow(() ->
                    captures.collectAndIngest(config, run, "sccm", DESCRIPTOR, ignored -> {}));
            assertEquals(completed, replayed);
            assertEquals(2, completed.assetsIngested());
            assertEquals(2, completed.discoveryRowsProcessed());
            assertEquals(originalUpload, components.findByAsset_IdIn(List.of(accepted.getId()))
                    .get(0).getSbomUpload().getId());
            transactions.executeWithoutResult(status -> captures.finish(run));
        });
        verify(query).forEachInstallPage(eq(config), any());
    }

    private UUID run(Tenant tenant) {
        var run = new SyncRun();
        run.setTenant(tenant);
        run.setStatus("running");
        run.setSyncType("SCCM_CMDB");
        run.setRunScope("TENANT_INVENTORY");
        return runs.save(run).getId();
    }

    private static SccmCmdbConfig config(Tenant tenant) {
        var config = new SccmCmdbConfig();
        config.setTenant(tenant);
        return config;
    }

    private static Map<String, String> install(String resource, String product) {
        return Map.of("sys_id", resource, "computer_name", "sccm-" + resource,
                "display_name", product, "publisher", "fixture", "version", "1");
    }
}
