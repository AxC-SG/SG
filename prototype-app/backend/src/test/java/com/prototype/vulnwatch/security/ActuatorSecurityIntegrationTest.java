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
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.AllowedTenantContextService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
        controllers = TestActuatorController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
                "app.security.api-key=test-api-key",
                "spring.mvc.throw-exception-if-no-handler-found=true",
                "spring.web.resources.add-mappings=false"
        })
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class ActuatorSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TenantService tenantService;

    @MockitoBean
    private TenantRepository tenantRepository;

    @MockitoBean
    private WorkspaceService workspaceService;

    @MockitoBean
    private DemoLifecycleService demoLifecycleService;

    @MockitoBean
    private AllowedTenantContextService allowedTenantContextService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private JwtTenantAuthenticationService jwtTenantAuthenticationService;

    @MockitoBean
    private OperationalMetricsService operationalMetricsService;

    @MockitoBean
    private TenantSupportGrantService tenantSupportGrantService;

    @BeforeEach
    void setUp() {
        Tenant defaultTenant = new Tenant();
        defaultTenant.setId(1L);
        defaultTenant.setName("Default Workspace");
        when(tenantService.getDefaultTenant()).thenReturn(defaultTenant);
        when(workspaceService.getWorkspace()).thenReturn(defaultTenant);
        when(allowedTenantContextService.listAllowedTenants(any())).thenReturn(List.of());
    }

    @Test
    void readinessEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void prometheusEndpointIsNotPublic() throws Exception {
        mockMvc.perform(get("/actuator/prometheus"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void prometheusEndpointAcceptsConfiguredApiKey() throws Exception {
        mockMvc.perform(get("/actuator/prometheus")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk());
    }

    @Test
    void apiEndpointsStillRequireAuth() throws Exception {
        mockMvc.perform(get("/api/auth/context"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void apiKeyAuthenticatedWritesBypassCsrfRequirement() throws Exception {
        mockMvc.perform(post("/api/test/write")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"));
    }
}
