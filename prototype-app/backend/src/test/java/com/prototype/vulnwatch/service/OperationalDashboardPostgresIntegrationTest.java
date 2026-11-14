package com.prototype.vulnwatch.service;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.security.creator-key=test-creator-key",
        "app.tenancy.require-tenant-context=false",
        "app.correlation.backfill-targets-on-startup=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class OperationalDashboardPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("operational_dashboard");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantService tenantService;

    @Test
    void operationsDashboardExposesEndpointTimingMetricsOnPostgres() throws Exception {
        String tenantId = tenantService.getDefaultTenant().getId().toString();
        mockMvc.perform(get("/api/vulnerability-intelligence?page=0&size=5")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Tenant-ID", tenantId)
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/vulnerability-intelligence/filters")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Tenant-ID", tenantId)
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/dashboard")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Tenant-ID", tenantId)
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/operations/dashboard")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-Tenant-ID", tenantId)
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.executiveHealth.ingestionSuccessRateLast24h").isNumber())
                .andExpect(jsonPath("$.normalizationQuality.activeComponents").isNumber())
                .andExpect(jsonPath("$.apiReadPath.summaryReadModelReady").isBoolean())
                .andExpect(jsonPath("$.apiReadPath.filterCacheActive").isBoolean())
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[0].key").value("vulnerability-intelligence-list"))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[0].requestCount").value(1))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[1].key").value("vulnerability-intelligence-filters"))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[1].requestCount").value(1))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[2].key").value("dashboard-overview"))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[2].requestCount").value(1))
                .andExpect(jsonPath("$.metricCatalog").isArray());
    }
}
