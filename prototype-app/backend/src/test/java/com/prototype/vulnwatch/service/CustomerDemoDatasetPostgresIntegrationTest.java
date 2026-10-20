package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.BomSourceType;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomComponentSummaryResponse;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import java.util.List;
import java.util.UUID;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class CustomerDemoDatasetPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("customer_demo_dataset");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private CustomerDemoDatasetService datasetService;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private BomIngestionRecordRepository bomIngestionRecordRepository;

    @Autowired
    private BomInventoryReadService bomInventoryReadService;

    @Autowired
    private HostInventoryReadService hostInventoryReadService;

    @Autowired private DemoDatasetProvisioningService provisioning;

    @Test
    void provisioningCommitsRealSeedDataAndCompletionInsideTheSelectedTenant() {
        Tenant tenant=tenantService.getDefaultTenant();
        jdbcTemplate.update("update platform.tenants set demo_source=? where id=?",
                DemoDatasetProvisioningService.SEEDING_MARKER,tenant.getId());
        var first=provisioning.seedIfReady(tenant.getId());
        var second=provisioning.seedIfReady(tenant.getId());
        assertEquals(first,second);
        assertEquals(DemoDatasetProvisioningService.SEEDED_MARKER,
                jdbcTemplate.queryForObject("select demo_source from platform.tenants where id=?",String.class,tenant.getId()));
        tenantSchemaExecutionService.run(tenant,() -> assertEquals(10,count("assets")));
    }

    @Test
    void seedsCompleteDatasetIdempotentlyInsideTheSelectedTenant() {
        Tenant tenant = tenantService.getDefaultTenant();

        assertTrue(datasetService.needsRepair(tenant));
        var first = datasetService.seed(tenant);
        tenantSchemaExecutionService.run(tenant, () -> jdbcTemplate.update("""
                UPDATE bom_ingestion_records
                   SET source_type = 'GITHUB_REPO'
                 WHERE bom_type IN ('AI_BOM', 'CBOM')
                """));
        tenantSchemaExecutionService.run(tenant, () -> jdbcTemplate.update("""
                UPDATE bom_component_workflows
                   SET workflow_status = 'IN_PROGRESS'
                """));
        assertEquals(true, datasetService.needsRepair(tenant));
        var second = datasetService.seed(tenant);
        assertEquals(false, datasetService.needsRepair(tenant));

        assertEquals(first, second);
        assertEquals(10, first.assets());
        assertEquals(10, first.sboms());
        assertEquals(40, first.components());
        assertEquals(26, first.findings());
        assertEquals(8, first.cves());
        assertEquals(2, first.campaigns());
        assertEquals(2, first.aiBoms());
        assertEquals(8, first.aiComponents());
        assertEquals(5, first.aiFindings());
        assertEquals(2, first.cboms());
        assertEquals(8, first.cbomComponents());
        assertEquals(9, first.cbomFindings());

        tenantSchemaExecutionService.run(tenant, () -> {
            assertEquals(10, count("assets"));
            assertEquals(4, jdbcTemplate.queryForObject(
                    "SELECT count(*) FROM assets WHERE type = 'HOST'", Integer.class));
            assertEquals(10, count("sbom_uploads"));
            assertEquals(4, jdbcTemplate.queryForObject(
                    "SELECT count(*) FROM sbom_uploads WHERE format = 'HOST_INVENTORY'", Integer.class));
            assertEquals(10, count("bom_ingestion_records"));
            assertEquals(16, count("bom_components"));
            assertEquals(16, count("bom_component_evidence"));
            assertEquals(5, count("bom_component_vulnerability_links"));
            assertEquals(5, count("bom_component_workflows"));
            assertEquals(8, count("cbom_components"));
            assertEquals(9, count("cbom_risk_findings"));
            assertEquals(2, count("cbom_posture_summary"));
            assertEquals(0, jdbcTemplate.queryForObject("""
                    SELECT count(*)
                      FROM bom_ingestion_records
                     WHERE source_type = 'GITHUB_REPO'
                    """, Integer.class));
            assertEquals(0, jdbcTemplate.queryForObject("""
                    SELECT count(*)
                      FROM bom_component_workflows
                     WHERE workflow_status = 'IN_PROGRESS'
                    """, Integer.class));
            assertEquals(5, jdbcTemplate.queryForObject("""
                    SELECT count(*)
                      FROM bom_component_workflows
                     WHERE workflow_status = 'UNDER_INVESTIGATION'
                    """, Integer.class));
            assertEquals(4, bomIngestionRecordRepository
                    .findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE).stream()
                    .filter(record -> record.getBomType().name().equals("AI_BOM")
                            || record.getBomType().name().equals("CBOM"))
                    .filter(record -> record.getSourceType() == BomSourceType.GITHUB_REPOSITORY)
                    .count());
            assertEquals(40, count("inventory_components"));
            assertEquals(26, count("findings"));
            assertEquals(26, jdbcTemplate.queryForObject("""
                    SELECT count(*)
                      FROM findings f
                      JOIN component_vulnerability_states cvs
                        ON cvs.tenant_id = f.tenant_id
                       AND cvs.component_id = f.component_id
                       AND cvs.vulnerability_id = f.vulnerability_id
                     WHERE f.tenant_id = ?
                       AND f.evidence->>'source' IN ('customer-demo', 'customer-demo-host-inventory')
                    """, Integer.class, tenant.getId()));
            assertTrue(jdbcTemplate.queryForObject("""
                    SELECT EXISTS (
                        SELECT 1
                          FROM component_vulnerability_states cvs
                          JOIN org_cve_records o ON o.vulnerability_id = cvs.vulnerability_id
                         WHERE cvs.tenant_id = ?
                           AND o.external_id = 'CVE-2021-44228'
                           AND cvs.applicability_state = 'APPLICABLE'
                    )
                    """, Boolean.class, tenant.getId()));
            assertEquals(26, count("finding_events"));
            assertEquals(26, count("finding_comments"));
            assertEquals(4, count("cis"));
            assertEquals(4, count("ci_aliases"));
            assertEquals(20, count("software_instances"));
            assertEquals(8, count("org_cve_records"));
            assertEquals(4, count("fix_records"));
            assertEquals(2, count("campaigns"));
            assertEquals(4, count("campaign_vulnerabilities"));
            assertEquals(6, jdbcTemplate.queryForObject("""
                    SELECT count(*)
                      FROM audit_events
                     WHERE target_type = 'demo-dataset'
                       AND details_json @> '{"synthetic":true}'::jsonb
                    """, Integer.class));
        });

        UUID aiBomId = tenantSchemaExecutionService.run(tenant, () -> jdbcTemplate.queryForObject("""
                SELECT id
                  FROM bom_ingestion_records
                 WHERE tenant_id = ?
                   AND bom_type = 'AI_BOM'
                 ORDER BY document_name
                 LIMIT 1
                """, UUID.class, tenant.getId()));
        var aiBomDetail = tenantSchemaExecutionService.run(
                tenant,
                () -> bomInventoryReadService.getDetail(tenant, aiBomId)
        );
        assertEquals("AI_BOM", aiBomDetail.bomType());
        assertEquals(4, aiBomDetail.components().size());
        assertTrue(aiBomDetail.workflowSummary().stream()
                .anyMatch(summary -> summary.workflowStatus().equals("UNDER_INVESTIGATION")));

        List<BomComponentSummaryResponse> componentSummaries = tenantSchemaExecutionService.run(
                tenant,
                () -> bomInventoryReadService.getBomComponentSummaries(tenant, 0, 2000)
        );
        assertTrue(componentSummaries.stream()
                .anyMatch(component -> component.packageName().equals("kanra-fraud-detector")
                        && component.ecosystem().equals("AI/ML")
                        && component.bomTypes().equals(List.of("AI_BOM"))));
        assertTrue(componentSummaries.stream()
                .anyMatch(component -> component.packageName().equals("Legacy payment signing key")
                        && component.ecosystem().equals("CRYPTO")
                        && component.bomTypes().equals(List.of("CBOM"))));
        assertTrue(componentSummaries.stream()
                .filter(component -> component.packageName().equals("log4j-core"))
                .allMatch(component -> component.bomTypes().equals(List.of("SBOM"))));

        UUID hostAssetId = tenantSchemaExecutionService.run(tenant, () -> jdbcTemplate.queryForObject("""
                SELECT id
                  FROM assets
                 WHERE tenant_id = ?
                   AND identifier = 'kanra-prod-web-01'
                """, UUID.class, tenant.getId()));
        var hostDetail = tenantSchemaExecutionService.run(
                tenant,
                () -> hostInventoryReadService.getHostDetail(tenant, hostAssetId, null)
        );
        assertEquals("kanra-prod-web-01", hostDetail.host().identifier());
        assertEquals(5, hostDetail.software().size());
        assertEquals(2, hostDetail.findings().size());
        assertTrue(hostDetail.software().stream()
                .anyMatch(software -> software.displayName().equals("Ubuntu Server 22.04 LTS")
                        && software.softwareIdentity().equals("Ubuntu Server 22.04 LTS")));
    }

    private int count(String table) {
        return jdbcTemplate.queryForObject("SELECT count(*) FROM " + table, Integer.class);
    }
}
