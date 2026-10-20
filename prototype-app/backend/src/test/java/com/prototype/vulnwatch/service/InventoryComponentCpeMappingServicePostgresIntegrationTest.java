package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentCpeMap;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

/**
 * Regression coverage for a cross-transaction FK violation: {@link InventoryComponentCpeMappingService}
 * used to run its writes in a brand-new {@code PROPAGATION_REQUIRES_NEW} transaction. When called from
 * a caller whose own outer transaction is still open (e.g. {@code BomIngestionOrchestrator} during a
 * first-time SBOM upload for a new asset), the just-inserted, not-yet-committed {@link InventoryComponent}
 * row is invisible to that second transaction's connection, so the {@code inventory_component_cpe_map}
 * insert fails its FK check against {@code inventory_components} — surfaced to callers as a generic
 * "[BAD_REQUEST] Request conflicts with existing data." response.
 *
 * <p>The {@code @Transactional} on this test class reproduces exactly that shape: the component insert
 * below and the call to {@code syncComponentMappings} share one still-open transaction, just like the
 * real ingestion path.
 */
@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@Transactional
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class InventoryComponentCpeMappingServicePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("inventory_component_cpe_mapping");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;

    @Autowired
    private InventoryComponentCpeMappingService inventoryComponentCpeMappingService;

    @org.springframework.test.context.transaction.BeforeTransaction
    void selectCustomerBeforeTransaction() {
        Tenant tenant = tenantService.getDefaultTenant();
        com.prototype.vulnwatch.service.TenantContext.setCurrentTenantId(tenant.getId());
        com.prototype.vulnwatch.service.TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }

    @org.springframework.test.context.transaction.AfterTransaction
    void clearCustomerAfterTransaction() {
        com.prototype.vulnwatch.service.TenantContext.clear();
    }

    @Test
    void syncComponentMappingsSeesComponentInsertedEarlierInTheSameOpenTransaction() {
        Tenant tenant = tenantService.getDefaultTenant();

        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.APPLICATION);
        asset.setName("cpe-mapping-fk-regression");
        asset.setIdentifier("pkg:npm/cpe-mapping-fk-regression@1.0.0");
        asset = assetRepository.save(asset);

        SbomUpload sbomUpload = new SbomUpload();
        sbomUpload.setTenant(tenant);
        sbomUpload.setAsset(asset);
        sbomUpload.setFormat(SbomFormat.CYCLONEDX);
        sbomUpload.setOriginalFilename("cpe-mapping-fk-regression.json");
        sbomUpload = sbomUploadRepository.save(sbomUpload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(sbomUpload);
        component.setEcosystem("npm");
        component.setPackageName("cpe-mapping-fk-regression");
        component.setVersion("1.0.0");
        component.setPurl("pkg:npm/cpe-mapping-fk-regression@1.0.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        // Saved (and, depending on Hibernate's flush timing, not even flushed to the DB yet) but never
        // committed — the outer @Transactional keeps this uncommitted until the test ends, exactly like
        // the still-open BomIngestionOrchestrator transaction in production.
        component = inventoryComponentRepository.save(component);

        String cpe = "cpe:2.3:a:cpe-mapping-fk-regression:cpe-mapping-fk-regression:1.0.0:*:*:*:*:*:*:*";
        inventoryComponentCpeMappingService.syncComponentMappings(
                List.of(component),
                Map.of(component.getId(), List.of(cpe))
        );

        List<InventoryComponentCpeMap> maps = inventoryComponentCpeMapRepository.findByComponent_Id(component.getId());
        assertEquals(1, maps.size());
    }
}
