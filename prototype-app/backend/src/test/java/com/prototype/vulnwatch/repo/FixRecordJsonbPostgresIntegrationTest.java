package com.prototype.vulnwatch.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
@Transactional
class FixRecordJsonbPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("fix_record_jsonb");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private FixRecordRepository fixRecordRepository;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private FindingDeltaQueueService findingDeltaQueueService;

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
    void persistsJsonbFieldsAndSearchesSoftwareNamesStructurally() {
        ensureDefaultTenant();
        Tenant tenant = tenantService.getDefaultTenant();

        tenantSchemaExecutionService.run(tenant, () -> {
            FixRecord fixRecord = new FixRecord();
            fixRecord.setTenant(tenant);
            fixRecord.setCveId("CVE-2099-2001");
            fixRecord.setRelatedCveIdsJson("[\"CVE-2099-2002\"]");
            fixRecord.setSummary("Upgrade nginx");
            fixRecord.setDescription("{\"primary_fix\":{\"target_version\":\"1.25.5\"}}");
            fixRecord.setFixType(FixRecord.FixType.PATCH.name());
            fixRecord.setSoftwareEntitiesJson("[{\"name\":\"nginx\",\"ecosystem\":\"deb\",\"version\":\"1.25.4\",\"assetCount\":3}]");
            fixRecord.setRecommendationSource(FixRecord.RecommendationSource.ANALYST.name());
            fixRecord.setSourceUrlsJson("[\"https://vendor.example/advisory\"]");
            fixRecord.setGeneratedAt(Instant.now());

            fixRecordRepository.saveAndFlush(fixRecord);
            return null;
        });
        entityManager.clear();

        FixRecord reloaded = tenantSchemaExecutionService.run(
                tenant, () -> fixRecordRepository.findByCveIdOrderByCreatedAtAsc("CVE-2099-2001").get(0));
        List<FixRecord> matches = tenantSchemaExecutionService.run(tenant, () -> fixRecordRepository.findBySoftwareNameContaining("NGINX"));

        assertJsonEquals("[\"CVE-2099-2002\"]", reloaded.getRelatedCveIdsJson());
        assertJsonEquals(
                "[{\"name\":\"nginx\",\"ecosystem\":\"deb\",\"version\":\"1.25.4\",\"assetCount\":3}]",
                reloaded.getSoftwareEntitiesJson()
        );
        assertJsonEquals("[\"https://vendor.example/advisory\"]", reloaded.getSourceUrlsJson());
        assertEquals(1, matches.size());
        assertNotNull(matches.get(0).getId());
    }

    private void ensureDefaultTenant() {
        tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME).orElseGet(() -> {
            Tenant tenant = new Tenant();
            tenant.setName(TenantService.DEFAULT_TENANT_NAME);
            return tenantRepository.save(tenant);
        });
    }

    private void assertJsonEquals(String expected, String actual) {
        try {
            JsonNode expectedNode = objectMapper.readTree(expected);
            JsonNode actualNode = objectMapper.readTree(actual);
            assertEquals(expectedNode, actualNode);
        } catch (Exception exception) {
            throw new AssertionError("Unable to compare JSON", exception);
        }
    }
}
