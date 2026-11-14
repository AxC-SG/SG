package com.prototype.vulnwatch.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.RiskPolicyController;
import com.prototype.vulnwatch.controller.ServiceNowCmdbConfigController;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigResponse;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.AuthenticatedTenantActor;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.RiskPolicyService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.ServiceNowCmdbConfigService;
import com.prototype.vulnwatch.service.ServiceNowCmdbSyncService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
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

@WebMvcTest(
        controllers = {
                RiskPolicyController.class,
                ServiceNowCmdbConfigController.class
        },
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
                "app.security.api-key=test-api-key",
                "spring.mvc.throw-exception-if-no-handler-found=true",
                "spring.web.resources.add-mappings=false"
        })
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class RbacControllerSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TenantService tenantService;
    @MockitoBean
    private TenantRepository tenantRepository;
    @MockitoBean
    private WorkspaceService workspaceService;
    @MockitoBean
    private RiskPolicyService riskPolicyService;
    @MockitoBean
    private com.prototype.vulnwatch.service.FindingsScoreRecomputeService findingsScoreRecomputeService;
    @MockitoBean
    private FindingWorkflowService findingWorkflowService;
    @MockitoBean
    private ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    @MockitoBean
    private ServiceNowCmdbSyncService serviceNowCmdbSyncService;
    @MockitoBean
    private AuditEventService auditEventService;
    @MockitoBean
    private OperationalMetricsService operationalMetricsService;
    @MockitoBean
    private JwtDecoder jwtDecoder;
    @MockitoBean
    private JwtTenantAuthenticationService jwtTenantAuthenticationService;
    @MockitoBean
    private TenantSupportGrantService tenantSupportGrantService;

    private UUID tenantId;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Customer A");
        tenant.setStatus("ACTIVE");
        when(tenantService.getDefaultTenant()).thenReturn(tenant);
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
    }

    @Test
    void riskPolicyUpdateRequiresTenantAdmin() throws Exception {
        authenticateJwt("analyst.jwt", "analyst-1", "SECURITY_ANALYST");

        mockMvc.perform(post("/api/risk-policy")
                        .header("Authorization", "Bearer analyst.jwt")
                        .contentType("application/json")
                .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void executeAutoCloseNowRequiresTenantAdmin() throws Exception {
        authenticateJwt("analyst.jwt", "analyst-1", "SECURITY_ANALYST");

        mockMvc.perform(post("/api/risk-policy/auto-close/execute-now")
                        .header("Authorization", "Bearer analyst.jwt"))
                .andExpect(status().isForbidden());
    }

    @Test
    void inventoryAdminCanManageConnectorConfiguration() throws Exception {
        authenticateJwt("inventory.jwt", "inventory-1", "INVENTORY_ADMIN");
        when(serviceNowCmdbConfigService.save(any(), any())).thenReturn(new ServiceNowCmdbConfigResponse(
                UUID.randomUUID(),
                "servicenow",
                true,
                "https://example.service-now.com",
                "BASIC",
                "api",
                true,
                "cmdb_sam_sw_install",
                "cmdb_sam_sw_discovery_model",
                "cmdb_ci",
                "",
                "",
                "sys_id",
                "sys_id",
                1000,
                true,
                false,
                1440,
                null,
                null,
                null,
                null
        ));
        doThrow(new RuntimeException("audit down")).when(auditEventService)
                .record(anyString(), anyString(), anyString(), any());

        mockMvc.perform(put("/api/connectors/servicenow-cmdb")
                        .header("Authorization", "Bearer inventory.jwt")
                        .contentType("application/json")
                        .content("{\"baseUrl\":\"https://example.service-now.com\",\"authType\":\"BASIC\",\"username\":\"api\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void securityAnalystCannotManageConnectorConfiguration() throws Exception {
        authenticateJwt("analyst.jwt", "analyst-1", "SECURITY_ANALYST");

        mockMvc.perform(put("/api/connectors/servicenow-cmdb")
                        .header("Authorization", "Bearer analyst.jwt")
                        .contentType("application/json")
                        .content("{\"baseUrl\":\"https://example.service-now.com\",\"authType\":\"BASIC\",\"username\":\"api\"}"))
                .andExpect(status().isForbidden());
    }

    private void authenticateJwt(String token, String subject, String role) {
        Jwt jwt = Jwt.withTokenValue(token)
                .header("alg", "none")
                .subject(subject)
                .build();
        when(jwtDecoder.decode(token)).thenReturn(jwt);
        when(jwtTenantAuthenticationService.authenticate(eq(jwt), anyString())).thenReturn(new AuthenticatedTenantActor(
                subject,
                UUID.randomUUID(),
                null,
                null,
                tenantId,
                "Customer A",
                null,
                Set.of(role)));
    }
}
