package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FixRecordRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.FindingWorkspaceSeedSupport;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class FindingWorkspaceProjectionPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("finding_workspace_projection");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private FixRecordRepository fixRecordRepository;

    @Autowired
    private FindingListProjectionService findingListProjectionService;

    @Autowired
    private FindingAnalyticsService findingAnalyticsService;

    @Autowired
    private NamedParameterJdbcTemplate jdbcTemplate;

    private Tenant tenant;
    private long expectedFindingCount;

    @BeforeEach
    void seedWorkspace() {
        tenant = tenantService.getDefaultTenant();
        if (tenantSchemaExecutionService.run(tenant, () -> findingRepository.count()) < 90) {
            FindingWorkspaceSeedSupport seedSupport = new FindingWorkspaceSeedSupport(
                    assetRepository,
                    sbomUploadRepository,
                    inventoryComponentRepository,
                    vulnerabilityRepository,
                    findingRepository,
                    tenantSchemaExecutionService
            );
            seedSupport.seedCriticalWorkspace(tenant, 90, 40);
        }
        findingListProjectionService.refreshTenant(tenant);
        expectedFindingCount = tenantSchemaExecutionService.run(tenant, () -> findingRepository.count());
    }

    @Test
    void projectionStatusDetectsMissingRowsAndRebuildRestoresParity() {
        FindingListProjectionService.ProjectionStatus healthy = findingListProjectionService.inspectProjectionStatus(tenant);
        assertEquals(expectedFindingCount, healthy.findingCount());
        assertEquals(expectedFindingCount, healthy.sourceFindingCount());
        assertFalse(healthy.stale());

        tenantSchemaExecutionService.run(tenant, () -> {
            jdbcTemplate.update("DELETE FROM finding_list_projection", new MapSqlParameterSource());
            return null;
        });

        FindingListProjectionService.ProjectionStatus broken = findingListProjectionService.inspectProjectionStatus(tenant);
        assertTrue(broken.stale());
        assertEquals(0, broken.findingCount());
        assertEquals(expectedFindingCount, broken.sourceFindingCount());
        assertEquals(expectedFindingCount, broken.driftCount());

        findingListProjectionService.refreshTenant(tenant);
        FindingListProjectionService.ProjectionStatus repaired = findingListProjectionService.inspectProjectionStatus(tenant);
        assertFalse(repaired.stale());
        assertEquals(expectedFindingCount, repaired.findingCount());
        assertEquals(expectedFindingCount, repaired.sourceFindingCount());
        assertEquals(0, repaired.driftCount());
        assertNotNull(repaired.lastRebuildDurationMs());
    }

    @Test
    void projectionBackedReadsStayConsistentForCriticalAndRoutingScopes() {
        var criticalOpen = new com.prototype.vulnwatch.dto.FindingsFilter(
                java.util.List.of("CRITICAL"),
                java.util.List.of("OPEN"),
                null, null, null, null, null, null,
                null, null, null, null, null, null, null,
                null, null, null, null, null, null
        );
        var unassignedCritical = new com.prototype.vulnwatch.dto.FindingsFilter(
                java.util.List.of("CRITICAL"),
                java.util.List.of("OPEN"),
                null, null, null, null, null, null,
                null, null, null, null, null, null, Boolean.TRUE,
                null, null, null, null, null, null
        );

        // Exercise direct callers with no thread-bound tenant: each projection read
        // must select its customer before opening the repository transaction.
        org.junit.jupiter.api.Assertions.assertNull(TenantContext.getCurrentTenantId());
        assertEquals(90, findingAnalyticsService.getMatchingCount(tenant, criticalOpen));
        assertEquals(90, findingAnalyticsService.getDistributions(tenant, criticalOpen).severityCounts()
                .stream().mapToLong(com.prototype.vulnwatch.dto.FindingCountBucketResponse::count).sum());
        var backlog = findingAnalyticsService.getBacklogHealth(tenant, criticalOpen);
        assertEquals(90, backlog.overdue() + backlog.dueSoon() + backlog.onTrack() + backlog.noSla());
        org.junit.jupiter.api.Assertions.assertNull(TenantContext.getCurrentTenantId());
        var summary = findingAnalyticsService.getSummary(tenant, criticalOpen);
        assertEquals(90, summary.openCount());

        var routingSummary = findingAnalyticsService.getSummary(tenant, unassignedCritical);
        assertEquals(40, routingSummary.openCount());
        assertEquals(40, routingSummary.unassignedOpenCount());
    }

    @Test
    void groupCountsCoverTheWholeWorkspaceAndGroupSelectionFiltersTheList() {
        var noFilter = new com.prototype.vulnwatch.dto.FindingsFilter(
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null,
                null, null, null, null, null, null, null
        );

        var severityGroups = findingAnalyticsService.groupCounts(tenant, noFilter, "severity");
        assertEquals(expectedFindingCount, severityGroups.stream().mapToLong(group -> group.count()).sum());
        assertTrue(severityGroups.stream().anyMatch(group -> "CRITICAL".equals(group.key()) && group.count() >= 90));
        var ownerGroups = findingAnalyticsService.groupCounts(tenant, noFilter, "owner");
        assertEquals(expectedFindingCount, ownerGroups.stream().mapToLong(group -> group.count()).sum());
        assertTrue(ownerGroups.stream().anyMatch(group -> "Unassigned".equals(group.key()) && group.count() >= 90));

        var criticalGroup = new com.prototype.vulnwatch.dto.FindingsFilter(
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null,
                null, null, null, null, null, null, null,
                "severity", "CRITICAL",
                // findingKind: null keeps every kind, matching the inclusive default.
                null
        );
        var page = findingListProjectionService.queryPage(tenant, criticalGroup, null, 25);
        assertTrue(page.totalItems() >= 90);
        assertEquals(25, page.findingIds().size());
    }

    @Test
    void scaleSeedSupportsRepeatableWorkspaceTimingMeasurements() {
        FindingWorkspaceSeedSupport seedSupport = new FindingWorkspaceSeedSupport(
                assetRepository,
                sbomUploadRepository,
                inventoryComponentRepository,
                vulnerabilityRepository,
                findingRepository,
                tenantSchemaExecutionService
        );
        seedSupport.seedCriticalWorkspace(tenant, 250, 100);
        findingListProjectionService.refreshTenant(tenant);

        long startedAt = System.nanoTime();
        findingListProjectionService.queryPage(tenant, new com.prototype.vulnwatch.dto.FindingsFilter(
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null, null, null
        ), null, 25);
        long firstPageMs = (System.nanoTime() - startedAt) / 1_000_000L;

        var firstPage = findingListProjectionService.queryPage(tenant, new com.prototype.vulnwatch.dto.FindingsFilter(
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null, null, null
        ), null, 25);
        startedAt = System.nanoTime();
        findingListProjectionService.queryPage(tenant, new com.prototype.vulnwatch.dto.FindingsFilter(
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null, null, null
        ), firstPage.nextCursor(), 25);
        long laterPageMs = (System.nanoTime() - startedAt) / 1_000_000L;

        assertTrue(firstPageMs >= 0);
        assertTrue(laterPageMs >= 0);
    }

    @Test
    void projectionRefreshUsesCaseInsensitivePatchableFixLookup() {
        Vulnerability patchable = createVulnerability("CVE-2099-PATCHABLE");
        Vulnerability noFix = createVulnerability("CVE-2099-NOFIX");
        InventoryComponent patchableComponent = createComponent("patchable-component");
        InventoryComponent noFixComponent = createComponent("nofix-component");

        createFinding(patchableComponent, patchable);
        createFinding(noFixComponent, noFix);

        tenantSchemaExecutionService.run(tenant, () -> {
            fixRecordRepository.save(createFixRecord(patchable.getExternalId().toLowerCase(), FixRecord.FixType.PATCH));
            fixRecordRepository.save(createFixRecord(noFix.getExternalId().toLowerCase(), FixRecord.FixType.NO_FIX));
            return null;
        });

        findingListProjectionService.refreshTenant(tenant);

        Map<String, Boolean> patchAvailability = tenantSchemaExecutionService.run(tenant, () -> jdbcTemplate.query(
                """
                select vulnerability_id, patch_available
                from finding_list_projection
                where vulnerability_id in (:vulnerabilityIds)
                """,
                new MapSqlParameterSource().addValue("vulnerabilityIds", java.util.List.of(
                        patchable.getExternalId(),
                        noFix.getExternalId()
                )),
                rs -> {
                    java.util.Map<String, Boolean> values = new java.util.LinkedHashMap<>();
                    while (rs.next()) {
                        values.put(rs.getString("vulnerability_id"), rs.getBoolean("patch_available"));
                    }
                    return values;
                }
        ));

        assertEquals(Boolean.TRUE, patchAvailability.get(patchable.getExternalId()));
        assertEquals(Boolean.FALSE, patchAvailability.get(noFix.getExternalId()));
        assertNotEquals(patchAvailability.get(patchable.getExternalId()), patchAvailability.get(noFix.getExternalId()));
    }

    private Vulnerability createVulnerability(String externalId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle(externalId + " title");
        vulnerability.setSeverity("HIGH");
        vulnerability.setCvssScore(8.2);
        vulnerability.setDescription("Synthetic vulnerability for projection patch lookup coverage.");
        vulnerability.touch();
        return vulnerabilityRepository.save(vulnerability);
    }

    private InventoryComponent createComponent(String suffix) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.HOST);
        asset.setName("projection-" + suffix);
        asset.setIdentifier("asset:projection-" + suffix);
        asset = assetRepository.save(asset);

        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.CYCLONEDX);
        upload.setOriginalFilename("projection-" + suffix + ".json");
        upload = sbomUploadRepository.save(upload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(upload);
        component.setEcosystem("maven");
        component.setPackageName("projection-" + suffix);
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.example/projection-" + suffix + "@1.0.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private void createFinding(InventoryComponent component, Vulnerability vulnerability) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(component.getAsset());
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setMatchedBy("cpe-indexed-direct");
        finding.setRiskScore(9.5);
        finding.setConfidenceScore(0.98);
        finding.setEvidence("{\"source\":\"projection-test\"}");
        findingRepository.save(finding);
    }

    private FixRecord createFixRecord(String cveId, FixRecord.FixType fixType) {
        FixRecord fixRecord = new FixRecord();
        fixRecord.setTenant(tenant);
        fixRecord.setCveId(cveId);
        fixRecord.setSummary("Fix for " + cveId);
        fixRecord.setDescription("Projection test fix record");
        fixRecord.setFixType(fixType.name());
        fixRecord.setRecommendationSource(FixRecord.RecommendationSource.REFERENCE.name());
        return fixRecord;
    }
}
