package com.prototype.vulnwatch.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.aisecurity.controller.AiGridController;
import com.prototype.vulnwatch.aisecurity.service.AiExposureIntelligenceService;
import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyPortfolioService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.AuthenticatedTenantActor;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;

@WebMvcTest(controllers = AiGridController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {"spring.mvc.throw-exception-if-no-handler-found=true",
                "spring.web.resources.add-mappings=false"})
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class,
        ApiExceptionHandler.class, RequestActorService.class})
class AiGridEvidenceAuthorizationIntegrationTest {
    @Autowired private MockMvc mockMvc;
    @MockitoBean private TenantService tenantService;
    @MockitoBean private TenantRepository tenantRepository;
    @MockitoBean private WorkspaceService workspaceService;
    @MockitoBean private AiSecurityAccessService accessService;
    @MockitoBean private AiGridApiService apiService;
    @MockitoBean private AiGridPolicyPortfolioService policyPortfolioService;
    @MockitoBean private AiExposureIntelligenceService intelligenceService;
    @MockitoBean private JwtDecoder jwtDecoder;
    @MockitoBean private JwtTenantAuthenticationService jwtAuthentication;
    @MockitoBean private TenantSupportGrantService tenantSupportGrantService;
    @MockitoBean private OperationalMetricsService operationalMetricsService;

    private Tenant tenant;
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("AI Grid tenant");
        tenant.setStatus("ACTIVE");
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(apiService.systemFacts(any(), any())).thenReturn(List.of());
    }

    @Test
    void operatorCannotReadGovernedEvidenceFacts() throws Exception {
        authenticate("operator.jwt", "operator", "OPERATOR");
        mockMvc.perform(get("/api/ai-systems/{id}/facts", UUID.randomUUID())
                        .header("Authorization", "Bearer operator.jwt"))
                .andExpect(status().isForbidden());
    }

    @Test
    void readOnlyAuditorCanReadGovernedEvidenceFacts() throws Exception {
        authenticate("auditor.jwt", "auditor", "READ_ONLY_AUDITOR");
        mockMvc.perform(get("/api/ai-systems/{id}/facts", UUID.randomUUID())
                        .header("Authorization", "Bearer auditor.jwt"))
                .andExpect(status().isOk());
    }

    @Test
    void frameworkCoverageUsesTheEntitledTenantBoundary() throws Exception {
        authenticate("auditor.jwt", "auditor", "READ_ONLY_AUDITOR");
        when(policyPortfolioService.frameworkCoverage(eq(tenant), eq("OWASP_AGENTIC_TOP_10"), eq("2026"),
                org.mockito.ArgumentMatchers.isNull()))
                .thenReturn(new AiGridPolicyPortfolioService.FrameworkCoverage(
                        "OWASP_AGENTIC_TOP_10", "2026", null, null, true, List.of(), List.of(),
                        new AiGridPolicyPortfolioService.LegacyCompatibility(21, 21, 13, 0, 8)));

        mockMvc.perform(get("/api/ai-framework-coverage")
                        .queryParam("framework", "OWASP_AGENTIC_TOP_10")
                        .queryParam("version", "2026")
                        .header("Authorization", "Bearer auditor.jwt"))
                .andExpect(status().isOk());

        verify(accessService).assertEntitled(tenant);
        verify(policyPortfolioService).frameworkCoverage(tenant, "OWASP_AGENTIC_TOP_10", "2026", null);
    }

    @Test
    void platformOwnerCanReadGlobalFrameworkRegistryWithoutTenantContext() throws Exception {
        authenticate("platform.jwt", "platform-owner", "PLATFORM_OWNER");
        when(workspaceService.getWorkspace()).thenThrow(new IllegalStateException("tenant context required"));
        when(policyPortfolioService.frameworks()).thenReturn(List.of());

        mockMvc.perform(get("/api/ai-frameworks")
                        .header("Authorization", "Bearer platform.jwt"))
                .andExpect(status().isOk());

        verify(policyPortfolioService).frameworks();
        verify(workspaceService, never()).getWorkspace();
        verify(accessService, never()).assertEntitled(any());
    }

    @Test
    void tenantAdminCanEnableAllDistributedPoliciesThroughTheTenantBoundary() throws Exception {
        authenticate("admin.jwt", "admin", "TENANT_ADMIN");
        when(apiService.enableAllDistributedPolicies(eq(tenant), eq("admin"), anyString()))
                .thenReturn(new AiGridApiService.BulkPolicySelectionResult(159, 103, 127, 32));

        mockMvc.perform(post("/api/ai-policies/enable-all")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"Program 2 pilot\"}")
                        .header("Authorization", "Bearer admin.jwt"))
                .andExpect(status().isOk());

        verify(accessService).assertEntitled(tenant);
        verify(apiService).enableAllDistributedPolicies(tenant, "admin", "Program 2 pilot");
    }

    @Test
    void securityAnalystCannotApproveAnAgentManifest() throws Exception {
        authenticate("analyst.jwt", "analyst", "SECURITY_ANALYST");

        mockMvc.perform(put("/api/ai-approved-manifests/{id}", UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"agentArtifactId\":\"" + UUID.randomUUID()
                                + "\",\"components\":[{\"componentType\":\"TOOL\",\"artifactId\":\""
                                + UUID.randomUUID() + "\",\"digest\":\"sha256:test\"}]}")
                        .header("Authorization", "Bearer analyst.jwt"))
                .andExpect(status().isForbidden());
    }

    private void authenticate(String token, String userId, String role) {
        Jwt jwt = Jwt.withTokenValue(token).header("alg", "none").subject(userId)
                .claim("roles", List.of(role)).build();
        when(jwtDecoder.decode(token)).thenReturn(jwt);
        when(jwtAuthentication.authenticate(eq(jwt), anyString())).thenReturn(new AuthenticatedTenantActor(
                userId, UUID.randomUUID(), userId + "@example.com", userId, tenantId,
                "AI Grid tenant", null, Set.of(role)));
    }
}
