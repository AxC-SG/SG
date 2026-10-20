package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@Transactional
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class OrgCveRecordServicePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("org_cve_record_service");

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
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Autowired
    private OrgCveRecordService orgCveRecordService;

    @Autowired
    private OrgCveRecordRepository orgCveRecordRepository;

    @org.springframework.test.context.transaction.BeforeTransaction
    void selectCustomerBeforeTransaction() {
        Tenant tenant = tenantService.getDefaultTenant();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }

    @org.springframework.test.context.transaction.AfterTransaction
    void clearCustomerAfterTransaction() {
        TenantContext.clear();
    }

    @Test
    void refreshIgnoresRetiredComponentImpactWhenComputingOrgExposure() {
        Tenant tenant = tenantService.getDefaultTenant();
        Vulnerability vulnerability = createVulnerability("CVE-2099-0401");

        InventoryComponent activeComponent = createComponent(tenant, "active-host", InventoryComponentStatus.ACTIVE);
        InventoryComponent retiredComponent = createComponent(tenant, "retired-host", InventoryComponentStatus.RETIRED);

        componentVulnerabilityStateRepository.save(createState(
                tenant,
                activeComponent,
                vulnerability,
                ApplicabilityState.APPLICABLE,
                ImpactState.NOT_IMPACTED
        ));
        componentVulnerabilityStateRepository.save(createState(
                tenant,
                retiredComponent,
                vulnerability,
                ApplicabilityState.APPLICABLE,
                ImpactState.IMPACTED
        ));

        int refreshed = orgCveRecordService.refreshForTenantAndVulnerabilities(tenant, List.of(vulnerability.getId()));

        assertEquals(1, refreshed);

        OrgCveRecord record = orgCveRecordRepository.findByVulnerability_Id(vulnerability.getId())
                .orElseThrow();
        assertNotNull(record.getLastEvaluatedAt());
        assertEquals(ApplicabilityState.APPLICABLE, record.getApplicabilityState());
        assertEquals(ImpactState.NOT_IMPACTED, record.getImpactState());
        assertFalse(record.isImpacted());
        assertEquals(1L, record.getMatchedComponentCount());
        assertEquals(1L, record.getMatchedSoftwareCount());
    }

    @Test
    void refreshForTenantCreatesNotApplicableRecordsForUnmatchedVulnerabilities() {
        Tenant tenant = tenantService.getDefaultTenant();
        Vulnerability matchedVulnerability = createVulnerability("CVE-2099-0501");
        Vulnerability unmatchedVulnerability = createVulnerability("CVE-2099-0502");

        InventoryComponent activeComponent = createComponent(tenant, "matched-host", InventoryComponentStatus.ACTIVE);
        componentVulnerabilityStateRepository.save(createState(
                tenant,
                activeComponent,
                matchedVulnerability,
                ApplicabilityState.APPLICABLE,
                ImpactState.IMPACTED
        ));

        int refreshed = orgCveRecordService.refreshForTenant(tenant);

        assertTrue(refreshed >= 2);

        OrgCveRecord matchedRecord = orgCveRecordRepository.findByVulnerability_Id(matchedVulnerability.getId())
                .orElseThrow();
        assertEquals(ApplicabilityState.APPLICABLE, matchedRecord.getApplicabilityState());
        assertEquals(ImpactState.IMPACTED, matchedRecord.getImpactState());
        assertEquals(1L, matchedRecord.getMatchedSoftwareCount());

        OrgCveRecord unmatchedRecord = orgCveRecordRepository.findByVulnerability_Id(unmatchedVulnerability.getId())
                .orElseThrow();
        assertEquals(ApplicabilityState.NOT_APPLICABLE, unmatchedRecord.getApplicabilityState());
        assertEquals(ImpactState.NOT_IMPACTED, unmatchedRecord.getImpactState());
        assertFalse(unmatchedRecord.isImpacted());
        assertEquals(0L, unmatchedRecord.getMatchedComponentCount());
        assertEquals(0L, unmatchedRecord.getMatchedSoftwareCount());
    }

    @Test
    void refreshPrefersUnderInvestigationWhenApplicableComponentsAreAwaitingExactResolution() {
        Tenant tenant = tenantService.getDefaultTenant();
        Vulnerability vulnerability = createVulnerability("CVE-2099-0601");

        InventoryComponent activeComponent = createComponent(tenant, "under-investigation-host", InventoryComponentStatus.ACTIVE);
        componentVulnerabilityStateRepository.save(createState(
                tenant,
                activeComponent,
                vulnerability,
                ApplicabilityState.APPLICABLE,
                ImpactState.UNDER_INVESTIGATION
        ));

        int refreshed = orgCveRecordService.refreshForTenantAndVulnerabilities(tenant, List.of(vulnerability.getId()));

        assertEquals(1, refreshed);

        OrgCveRecord record = orgCveRecordRepository.findByVulnerability_Id(vulnerability.getId())
                .orElseThrow();
        assertEquals(ApplicabilityState.APPLICABLE, record.getApplicabilityState());
        assertEquals(ImpactState.UNDER_INVESTIGATION, record.getImpactState());
        assertFalse(record.isImpacted());
    }

    private Vulnerability createVulnerability(String externalId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("Regression test vulnerability");
        vulnerability.setSeverity("HIGH");
        vulnerability.setCvssScore(8.1);
        vulnerability.setLastModifiedAt(Instant.now());
        return vulnerabilityRepository.save(vulnerability);
    }

    private InventoryComponent createComponent(Tenant tenant, String nameSuffix, InventoryComponentStatus status) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.HOST);
        asset.setName(nameSuffix);
        asset.setIdentifier("asset:" + nameSuffix);
        asset = assetRepository.save(asset);

        SbomUpload sbomUpload = new SbomUpload();
        sbomUpload.setTenant(tenant);
        sbomUpload.setAsset(asset);
        sbomUpload.setFormat(SbomFormat.CYCLONEDX);
        sbomUpload.setOriginalFilename(nameSuffix + ".json");
        sbomUpload = sbomUploadRepository.save(sbomUpload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(sbomUpload);
        component.setEcosystem("maven");
        component.setPackageName("log4j-core");
        component.setVersion(status == InventoryComponentStatus.ACTIVE ? "2.17.0" : "2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@" + component.getVersion());
        component.setComponentStatus(status);
        if (status == InventoryComponentStatus.RETIRED) {
            component.setRetiredAt(Instant.now());
        }
        return inventoryComponentRepository.save(component);
    }

    private ComponentVulnerabilityState createState(
            Tenant tenant,
            InventoryComponent component,
            Vulnerability vulnerability,
            ApplicabilityState applicabilityState,
            ImpactState impactState
    ) {
        ComponentVulnerabilityState state = new ComponentVulnerabilityState();
        state.setTenant(tenant);
        state.setComponent(component);
        state.setVulnerability(vulnerability);
        state.setApplicabilityState(applicabilityState);
        state.setImpactState(impactState);
        state.setLastEvaluatedAt(Instant.now());
        return state;
    }
}
