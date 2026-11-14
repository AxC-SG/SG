package com.prototype.vulnwatch.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.DashboardController;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.DashboardService;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
        controllers = DashboardController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
                "app.security.api-key=test-api-key",
                "app.security.allow-api-key-auth=false",
                "spring.mvc.throw-exception-if-no-handler-found=true",
                "spring.web.resources.add-mappings=false"
        })
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class JwtOnlySecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TenantService tenantService;
    @MockitoBean
    private TenantRepository tenantRepository;
    @MockitoBean
    private WorkspaceService workspaceService;
    @MockitoBean
    private DashboardService dashboardService;
    @MockitoBean
    private OperationalMetricsService operationalMetricsService;
    @MockitoBean
    private JwtDecoder jwtDecoder;
    @MockitoBean
    private JwtTenantAuthenticationService jwtTenantAuthenticationService;
    @MockitoBean
    private TenantSupportGrantService tenantSupportGrantService;

    @Test
    void rejectsApiKeyWhenJwtOnlyModeIsEnabled() throws Exception {
        mockMvc.perform(get("/api/dashboard").header("X-API-Key", "test-api-key"))
                .andExpect(status().isUnauthorized());
    }
}
