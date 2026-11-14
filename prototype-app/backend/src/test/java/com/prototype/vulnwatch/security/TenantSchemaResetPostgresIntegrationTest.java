package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FixRecordRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantSchemaService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Supplier;
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
class TenantSchemaResetPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("tenant_schema_reset");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantSchemaService tenantSchemaService;

    @Autowired
    private TenantSchemaMigrationService tenantSchemaMigrationService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private FixRecordRepository fixRecordRepository;

    @Autowired
    @Qualifier("platformJdbcTemplate")
    private JdbcTemplate platformJdbcTemplate;

    @MockitoBean
    private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void resetTenantSchemaClearsTenantOwnedDataAndLeavesTenantRegistryIntact() {
        Tenant tenant = tenantService.createTenant("Reset Customer", "reset-customer", "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);

        tenantSchemaExecutionService.run(tenant, () -> {
            fixRecordRepository.saveAndFlush(buildFixRecord(tenant, "CVE-2099-4001", "openssl"));
            return null;
        });

        long beforeReset = tenantSchemaExecutionService.run(tenant, (Supplier<Long>) fixRecordRepository::count);
        assertEquals(1L, beforeReset);

        tenantSchemaService.resetTenantSchema(tenant.getSchemaName());

        Tenant registryTenant = tenantRepository.findById(tenant.getId()).orElseThrow();
        assertNotNull(registryTenant);
        assertEquals(tenant.getSchemaName(), registryTenant.getSchemaName());

        long afterReset = tenantSchemaExecutionService.run(tenant, (Supplier<Long>) fixRecordRepository::count);
        assertEquals(0L, afterReset);

        tenantSchemaExecutionService.run(tenant, () -> {
            fixRecordRepository.saveAndFlush(buildFixRecord(tenant, "CVE-2099-4002", "curl"));
            return null;
        });

        long afterReuse = tenantSchemaExecutionService.run(tenant, (Supplier<Long>) fixRecordRepository::count);
        assertEquals(1L, afterReuse);
    }

    @Test
    void dropTenantSchemaRemovesTenantSchemaPermanently() {
        Tenant tenant = tenantService.createTenant("Drop Customer", "drop-customer", "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);

        assertSchemaExists(tenant.getSchemaName());

        tenantSchemaService.dropTenantSchema(tenant.getSchemaName());

        assertSchemaMissing(tenant.getSchemaName());
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

    private void assertSchemaExists(String schemaName) {
        Integer count = platformJdbcTemplate.queryForObject("""
                select count(*)
                from information_schema.schemata
                where schema_name = ?
                """, Integer.class, schemaName);
        assertEquals(1, count);
    }

    private void assertSchemaMissing(String schemaName) {
        Integer count = platformJdbcTemplate.queryForObject("""
                select count(*)
                from information_schema.schemata
                where schema_name = ?
                """, Integer.class, schemaName);
        assertEquals(0, count);
    }
}
