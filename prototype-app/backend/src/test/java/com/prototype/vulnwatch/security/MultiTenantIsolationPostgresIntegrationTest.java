package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FixRecordResponse;
import com.prototype.vulnwatch.repo.FixRecordRepository;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.FixRecordService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
class MultiTenantIsolationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("multi_tenant_isolation");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private TenantSchemaMigrationService tenantSchemaMigrationService;

    @Autowired
    private FixRecordRepository fixRecordRepository;

    @Autowired
    private FixRecordService fixRecordService;

    @Autowired
    @Qualifier("platformJdbcTemplate")
    private JdbcTemplate platformJdbcTemplate;

    @MockitoBean
    private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void createsTenantSchemasAndKeepsTenantLocalRecordsIsolated() {
        Tenant tenantA = tenantService.createTenant("Customer A", "customer-a", "pilot", null);
        Tenant tenantB = tenantService.createTenant("Customer B", "customer-b", "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenantA);
        tenantSchemaMigrationService.provisionNewTenant(tenantB);

        assertTenantSchemaProvisioned(tenantA.getSchemaName());
        assertTenantSchemaProvisioned(tenantB.getSchemaName());

        tenantSchemaExecutionService.run(tenantA, () -> {
            fixRecordRepository.saveAndFlush(buildFixRecord(tenantA, "CVE-2099-3001", "nginx"));
            return null;
        });
        tenantSchemaExecutionService.run(tenantB, () -> {
            fixRecordRepository.saveAndFlush(buildFixRecord(tenantB, "CVE-2099-3002", "apache"));
            return null;
        });

        List<FixRecordResponse> tenantAMatches = fixRecordService.getFixRecordsBySoftware(tenantA, "nginx");
        List<FixRecordResponse> tenantBMatches = fixRecordService.getFixRecordsBySoftware(tenantB, "nginx");
        List<FixRecordResponse> tenantBApacheMatches = fixRecordService.getFixRecordsBySoftware(tenantB, "apache");

        assertEquals(1, tenantAMatches.size());
        assertEquals("CVE-2099-3001", tenantAMatches.get(0).cveId());
        assertTrue(tenantBMatches.isEmpty());
        assertEquals(1, tenantBApacheMatches.size());
        assertEquals("CVE-2099-3002", tenantBApacheMatches.get(0).cveId());
    }

    private void assertTenantSchemaProvisioned(String schemaName) {
        Integer assetsTableCount = platformJdbcTemplate.queryForObject("""
                SELECT count(*)
                FROM information_schema.tables
                WHERE table_schema = ?
                  AND table_name = 'assets'
                """, Integer.class, schemaName);
        Integer fixRecordsTableCount = platformJdbcTemplate.queryForObject("""
                SELECT count(*)
                FROM information_schema.tables
                WHERE table_schema = ?
                  AND table_name = 'fix_records'
                """, Integer.class, schemaName);

        assertEquals(1, assetsTableCount);
        assertEquals(1, fixRecordsTableCount);
    }

    private FixRecord buildFixRecord(Tenant tenant, String cveId, String softwareName) {
        FixRecord fixRecord = new FixRecord();
        fixRecord.setTenant(tenant);
        fixRecord.setCveId(cveId);
        fixRecord.setRelatedCveIdsJson("[]");
        fixRecord.setSummary("Upgrade " + softwareName);
        fixRecord.setDescription("{\"primary_fix\":{\"target_version\":\"1.0.0\"}}");
        fixRecord.setFixType(FixRecord.FixType.PATCH.name());
        fixRecord.setSoftwareEntitiesJson("[{\"name\":\"" + softwareName + "\",\"ecosystem\":\"deb\",\"version\":\"1.0.0\",\"assetCount\":1}]");
        fixRecord.setRecommendationSource(FixRecord.RecommendationSource.ANALYST.name());
        fixRecord.setSourceUrlsJson("[\"https://vendor.example/advisory\"]");
        fixRecord.setGeneratedAt(Instant.now());
        return fixRecord;
    }
}
