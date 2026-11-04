package com.prototype.vulnwatch.service.cbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Large-tenant budgets from the CBOM plan (section 9): paginated inventory queries within p95
 * 750 ms for a tenant with 1,000,000 CBOM components, and a 10,000-asset semantic diff within
 * 30 seconds. Data is bulk-loaded with SQL so the test measures the read paths, not ingestion.
 */
@PostgresIntegrationTest
class CbomLargeTenantPerformancePostgresIntegrationTest {
    private static final Logger LOG = LoggerFactory.getLogger(CbomLargeTenantPerformancePostgresIntegrationTest.class);
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cbom_large_tenant");
    private static final int FLEET_COMPONENTS = 1_000_000;
    private static final int DIFF_COMPONENTS = 10_000;
    private static final long INVENTORY_P95_BUDGET_MS = 750;
    private static final long DIFF_BUDGET_MS = 30_000;

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private JdbcTemplate jdbc;
    @Autowired private TenantService tenantService;
    @Autowired private CbomVisibilityService visibility;
    @Autowired private CbomSemanticDiffService diffs;

    @Test
    void inventoryAndDiffMeetLargeTenantBudgets() {
        Tenant tenant = tenantService.getDefaultTenant();
        UUID asset = UUID.randomUUID();
        UUID fleetBom = UUID.randomUUID();
        UUID before = UUID.randomUUID();
        UUID after = UUID.randomUUID();
        inTenant(tenant, () -> {
            jdbc.update("insert into assets (id, business_criticality, created_at, identifier, name, state, type, environment, tenant_id)"
                    + " values (?, 'HIGH', now(), ?, 'checkout', 'ACTIVE', 'APPLICATION', 'production', ?)", asset, "app:" + asset, tenant.getId());
            insertBom(tenant, fleetBom, asset, "ACTIVE", null);
            insertBom(tenant, before, asset, "SUPERSEDED", null);
            insertBom(tenant, after, asset, "ACTIVE", before);
            // Fleet: 1M active components, a fifth of them with an open finding.
            jdbc.update("""
                    insert into cbom_components (id, tenant_id, asset_id, source_bom_id, bom_ref, component_fingerprint, name,
                        asset_type, primitive, key_size, storage_location, risk_score, active, created_at, updated_at)
                    select gen_random_uuid(), ?, ?, ?, 'fleet-' || g, 'fleet-' || g, 'component-' || g,
                           (array['ALGORITHM','CERTIFICATE','PROTOCOL','RELATED_CRYPTO_MATERIAL'])[1 + g % 4],
                           (array['rsa','aes','sha1','ecdsa','ml-kem'])[1 + g % 5], (array[1024,2048,3072,4096])[1 + g % 4],
                           (array['hsm','kms','env','file'])[1 + g % 4], (g % 1000) / 100.0, true, now(), now()
                      from generate_series(1, ?) g
                    """, tenant.getId(), asset, fleetBom, FLEET_COMPONENTS);
            jdbc.update("""
                    insert into cbom_risk_findings (id, tenant_id, cbom_component_id, rule_id, rule_version, finding_fingerprint,
                        risk_class, severity, title, status, evidence_state, first_seen_at, last_seen_at, created_at)
                    select gen_random_uuid(), c.tenant_id, c.id, 'CBOM-WEAK-ALGO', '1', 'f-' || c.id, 'WEAK_ALGORITHM',
                           (array['CRITICAL','HIGH','MEDIUM','LOW'])[1 + (abs(hashtext(c.bom_ref)) % 4)], 'Weak primitive',
                           'OPEN', 'SUPPORTED', now(), now(), now()
                      from cbom_components c where c.source_bom_id = ? and abs(hashtext(c.bom_ref)) % 5 = 0
                    """, fleetBom);
            // Diff pair: the new version omits 500, adds 500 and changes the key size of every tenth component.
            jdbc.update("""
                    insert into cbom_components (id, tenant_id, asset_id, source_bom_id, bom_ref, component_fingerprint, name,
                        asset_type, primitive, key_size, risk_score, active, created_at, updated_at)
                    select gen_random_uuid(), ?, ?, ?, 'ref-' || g, 'before-' || g, 'diff-' || g, 'ALGORITHM', 'rsa', 2048, 5.0, false, now(), now()
                      from generate_series(1, ?) g
                    """, tenant.getId(), asset, before, DIFF_COMPONENTS);
            jdbc.update("""
                    insert into cbom_components (id, tenant_id, asset_id, source_bom_id, bom_ref, component_fingerprint, name,
                        asset_type, primitive, key_size, risk_score, active, created_at, updated_at)
                    select gen_random_uuid(), ?, ?, ?, 'ref-' || g, 'after-' || g, 'diff-' || g, 'ALGORITHM', 'rsa',
                           case when g % 10 = 0 then 3072 else 2048 end, 5.0, true, now(), now()
                      from generate_series(501, ?) g
                    """, tenant.getId(), asset, after, DIFF_COMPONENTS + 500);
            jdbc.update("""
                    insert into cbom_risk_findings (id, tenant_id, cbom_component_id, rule_id, rule_version, finding_fingerprint,
                        risk_class, severity, title, status, evidence_state, first_seen_at, last_seen_at, created_at)
                    select gen_random_uuid(), c.tenant_id, c.id, 'CBOM-QUANTUM-VULNERABLE', '1', 'q-' || c.id, 'QUANTUM_VULNERABLE',
                           'MEDIUM', 'Quantum-vulnerable algorithm', 'OPEN', 'SUPPORTED', now(), now(), now()
                      from cbom_components c where c.source_bom_id in (?, ?)
                    """, before, after);
            jdbc.execute("analyze cbom_components");
            jdbc.execute("analyze cbom_risk_findings");
            return null;
        });

        long defaultPage = p95(tenant, new CbomVisibilityService.InventoryFilter(null, null, null, null, null, null, null, null, null, false), 0);
        long typed = p95(tenant, new CbomVisibilityService.InventoryFilter("CERTIFICATE", null, null, null, null, null, null, null, null, false), 0);
        long severe = p95(tenant, new CbomVisibilityService.InventoryFilter(null, null, "CRITICAL", null, null, null, null, null, null, false), 0);
        long deep = p95(tenant, new CbomVisibilityService.InventoryFilter("ALGORITHM", null, null, null, null, "production", asset, null, null, false), 20);
        LOG.info("CBOM inventory p95 ms over {} components: default={} assetType={} severity={} deepPage={}",
                FLEET_COMPONENTS, defaultPage, typed, severe, deep);
        assertTrue(defaultPage < INVENTORY_P95_BUDGET_MS, "default inventory page p95 " + defaultPage + "ms");
        assertTrue(typed < INVENTORY_P95_BUDGET_MS, "asset-type filter p95 " + typed + "ms");
        assertTrue(severe < INVENTORY_P95_BUDGET_MS, "severity filter p95 " + severe + "ms");
        assertTrue(deep < INVENTORY_P95_BUDGET_MS, "filtered page 20 p95 " + deep + "ms");

        long started = System.nanoTime();
        var diff = inTenant(tenant, () -> diffs.diff(tenant, after, null));
        long diffMs = (System.nanoTime() - started) / 1_000_000;
        LOG.info("CBOM semantic diff of {} components took {} ms", DIFF_COMPONENTS, diffMs);
        assertTrue(diffMs < DIFF_BUDGET_MS, "10k-asset diff took " + diffMs + "ms");
        assertEquals(500, diff.componentSummary().get("NOT_OBSERVED"));
        assertEquals(500, diff.componentSummary().get("ADDED"));
        assertEquals(950, diff.componentSummary().get("CHANGED"), "every tenth component present in both versions changed key size");
        assertEquals(500, diff.findingSummary().get("NOT_OBSERVED"));
        assertEquals(500, diff.findingSummary().get("INTRODUCED"));
    }

    private long p95(Tenant tenant, CbomVisibilityService.InventoryFilter filter, int page) {
        inTenant(tenant, () -> visibility.inventory(tenant, filter, page, 50));
        List<Long> samples = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            long started = System.nanoTime();
            var result = inTenant(tenant, () -> visibility.inventory(tenant, filter, page, 50));
            samples.add((System.nanoTime() - started) / 1_000_000);
            assertTrue(result.items().size() <= 50);
        }
        Collections.sort(samples);
        return samples.get((int) Math.ceil(samples.size() * 0.95) - 1);
    }

    private void insertBom(Tenant tenant, UUID id, UUID asset, String status, UUID previous) {
        jdbc.update("insert into bom_ingestion_records (id, tenant_id, asset_id, bom_type, status, previous_bom_id, document_name, ingested_at)"
                + " values (?, ?, ?, 'CBOM', ?, ?, ?, now())", id, tenant.getId(), asset, status, previous, "perf-" + id);
    }

    private <T> T inTenant(Tenant tenant, Supplier<T> work) {
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        try {
            return work.get();
        } finally {
            TenantContext.clear();
        }
    }
}
