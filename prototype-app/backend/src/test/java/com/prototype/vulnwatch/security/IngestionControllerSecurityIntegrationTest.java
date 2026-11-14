package com.prototype.vulnwatch.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.IngestionController;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.dto.VexAssertionRepairSummaryResponse;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.SbomIngestionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.VulnerabilityIngestionService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
        controllers = IngestionController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
                "app.security.api-key=test-api-key",
                "app.security.creator-key=test-creator-key",
                "spring.mvc.throw-exception-if-no-handler-found=true",
                "spring.web.resources.add-mappings=false"
        })
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class IngestionControllerSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TenantService tenantService;

    @MockitoBean
    private TenantRepository tenantRepository;

    @MockitoBean
    private WorkspaceService workspaceService;

    @MockitoBean
    private SbomIngestionService sbomIngestionService;

    @MockitoBean
    private VulnerabilityIngestionService vulnerabilityIngestionService;

    @MockitoBean
    private IngestionJobService ingestionJobService;

    @MockitoBean
    private OperationalMetricsService operationalMetricsService;

    @MockitoBean
    private AuditEventService auditEventService;

    @MockitoBean
    private TenantSupportGrantService tenantSupportGrantService;

    private UUID defaultTenantId;

    @BeforeEach
    void setUp() {
        Tenant defaultTenant = new Tenant();
        defaultTenant.setName("Default Workspace");
        defaultTenantId = UUID.fromString("00000000-0000-0000-0000-000000000001");
        defaultTenant.setId(defaultTenantId);
        when(tenantService.getDefaultTenant()).thenReturn(defaultTenant);
        when(workspaceService.getWorkspace()).thenReturn(defaultTenant);
    }

    @Test
    void rejectsIngestionRequestsWithoutApiKey() throws Exception {
        mockMvc.perform(post("/api/ingestion/nvd-sync"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void preservesNvdSyncTriggerContract() throws Exception {
        UUID runId = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        when(vulnerabilityIngestionService.triggerNvdSync(12))
                .thenReturn(new SyncTriggerResponse(runId, "queued", "NVD incremental sync queued"));

        mockMvc.perform(post("/api/ingestion/nvd-sync")
                        .queryParam("lookbackHours", "12")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.runId").value(runId.toString()))
                .andExpect(jsonPath("$.status").value("queued"))
                .andExpect(jsonPath("$.message").value("NVD incremental sync queued"));
    }

    @Test
    void centralFeedSyncRequiresPlatformOwnerRole() throws Exception {
        mockMvc.perform(post("/api/ingestion/nvd-sync")
                        .queryParam("lookbackHours", "12")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isForbidden());
    }

    @Test
    void preservesAdvisoryAndSummaryContracts() throws Exception {
        when(vulnerabilityIngestionService.ingestAdvisories(any()))
                .thenReturn(new IngestionResult("ok", 1, 1, 0, "Advisories ingested"));
        when(vulnerabilityIngestionService.getVexAssertionRepairSummary())
                .thenReturn(new VexAssertionRepairSummaryResponse(
                        10,
                        8,
                        6,
                        2,
                        Set.of("redhat", "microsoft"),
                        true,
                        true,
                        true,
                        true,
                        null,
                        null,
                        null,
                        null,
                        null,
                        Instant.parse("2026-03-27T00:00:00Z")
                ));

        mockMvc.perform(post("/api/ingestion/advisories")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .contentType("application/json")
                        .content("{\"advisories\":[{\"externalId\":\"ADV-1\",\"title\":\"Test advisory\",\"rules\":[]}]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.fetched").value(1))
                .andExpect(jsonPath("$.inserted").value(1))
                .andExpect(jsonPath("$.updated").value(0))
                .andExpect(jsonPath("$.message").value("Advisories ingested"));

        mockMvc.perform(get("/api/ingestion/vex-assertion-repair/summary")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vexLikeTargetCount").value(10))
                .andExpect(jsonPath("$.persistedAssertionCount").value(8))
                .andExpect(jsonPath("$.vexRolloutBackfillEnabled").value(true));
    }
}
