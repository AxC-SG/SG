package com.prototype.vulnwatch.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.AuthContextController;
import com.prototype.vulnwatch.controller.DashboardController;
import com.prototype.vulnwatch.controller.OperationalDashboardController;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OperationalQualitySummaryResponse;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.AuthenticatedTenantActor;
import com.prototype.vulnwatch.service.AllowedTenantContextService;
import com.prototype.vulnwatch.service.DashboardService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.OperationalDashboardService;
import com.prototype.vulnwatch.service.OperationalQualityReadService;
import com.prototype.vulnwatch.service.PerformanceScorecardService;
import com.prototype.vulnwatch.service.PlatformTenantAttentionService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantEntitlementService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.Set;
import java.util.List;
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
                DashboardController.class,
                OperationalDashboardController.class,
                AuthContextController.class
        },
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
        "app.security.api-key=test-api-key",
        "app.security.creator-key=test-creator-key",
        "spring.mvc.throw-exception-if-no-handler-found=true",
        "spring.web.resources.add-mappings=false"
})
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class ApiSecurityIntegrationTest {

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
    private DashboardService dashboardService;

    @MockitoBean
    private OperationalDashboardService operationalDashboardService;

    @MockitoBean
    private OperationalQualityReadService operationalQualityReadService;

    @MockitoBean
    private PlatformTenantAttentionService platformTenantAttentionService;

    @MockitoBean
    private OperationalMetricsService operationalMetricsService;

    @MockitoBean
    private PerformanceScorecardService performanceScorecardService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private JwtTenantAuthenticationService jwtTenantAuthenticationService;

    @MockitoBean
    private TenantSupportGrantService tenantSupportGrantService;

    @MockitoBean
    private TenantEntitlementService tenantEntitlementService;

    @BeforeEach
    void setUp() {
        Tenant defaultTenant = new Tenant();
        defaultTenant.setId(1L);
        defaultTenant.setName("Default Workspace");
        when(tenantService.getDefaultTenant()).thenReturn(defaultTenant);
        when(workspaceService.getWorkspace()).thenReturn(defaultTenant);
        when(allowedTenantContextService.listAllowedTenants(any())).thenReturn(List.of());
        when(dashboardService.get(any(Tenant.class))).thenReturn(null);
        when(operationalDashboardService.get()).thenReturn(null);
    }

    @Test
    void rejectsApiRequestsWithoutKey() throws Exception {
        mockMvc.perform(get("/api/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void acceptsApiRequestsWithKey() throws Exception {
        mockMvc.perform(get("/api/dashboard")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Request-ID", "req-test-123"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Request-ID", "req-test-123"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                .andExpect(header().string("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"))
                .andExpect(header().string("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"));
    }

    @Test
    void unknownApiRouteReturnsNotFoundJson() throws Exception {
        mockMvc.perform(get("/api/tenants").header("X-API-Key", "test-api-key"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("NOT_FOUND"))
                .andExpect(jsonPath("$.error").value("Resource not found"));
    }

    @Test
    void operationsDashboardIsForbiddenWithoutCreatorKey() throws Exception {
        mockMvc.perform(get("/api/operations/dashboard").header("X-API-Key", "test-api-key"))
                .andExpect(status().isForbidden());
    }

    @Test
    void operationsDashboardAllowsCreatorKey() throws Exception {
        mockMvc.perform(get("/api/operations/dashboard")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk());
    }

    @Test
    void tenantAttentionAllowsCreatorKey() throws Exception {
        when(platformTenantAttentionService.listTenantAttention()).thenReturn(List.of());
        mockMvc.perform(get("/api/operations/tenant-attention")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk());
    }

    @Test
    void connectorIssuesAreForbiddenWithoutCreatorKey() throws Exception {
        mockMvc.perform(get("/api/operations/connector-issues")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isForbidden());
    }

    @Test
    void connectorIssuesAllowCreatorKey() throws Exception {
        when(platformTenantAttentionService.listConnectorIssues()).thenReturn(List.of());
        mockMvc.perform(get("/api/operations/connector-issues")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk());
    }

    @Test
    void performanceScorecardIsForbiddenWithoutCreatorKey() throws Exception {
        mockMvc.perform(get("/api/operations/performance-scorecard")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isForbidden());
    }

    @Test
    void performanceScorecardAllowsCreatorKey() throws Exception {
        mockMvc.perform(get("/api/operations/performance-scorecard")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk());
    }

    @Test
    void authContextReflectsCreatorRole() throws Exception {
        mockMvc.perform(get("/api/auth/context")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(false))
                .andExpect(jsonPath("$.principal").value("local-analyst"))
                .andExpect(jsonPath("$.userId").value("local-analyst"))
                .andExpect(jsonPath("$.tenantId").value("00000000-0000-0000-0000-000000000001"))
                .andExpect(jsonPath("$.tenantName").value("Default Workspace"));

        mockMvc.perform(get("/api/auth/context")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(true))
                .andExpect(jsonPath("$.principal").value("local-analyst"))
                .andExpect(jsonPath("$.userId").value("local-analyst"))
                .andExpect(jsonPath("$.platformScope").value(true))
                .andExpect(jsonPath("$.tenantId").doesNotExist())
                .andExpect(jsonPath("$.tenantName").doesNotExist());

        mockMvc.perform(get("/api/me")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(false))
                .andExpect(jsonPath("$.userId").value("local-analyst"));
    }

    @Test
    void bearerJwtUsesTenantMembershipContext() throws Exception {
        UUID tenantId = UUID.randomUUID();
        Jwt jwt = Jwt.withTokenValue("test.jwt")
                .header("alg", "none")
                .subject("user-123")
                .claim("email", "analyst@example.com")
                .build();
        when(jwtDecoder.decode("test.jwt")).thenReturn(jwt);
        when(jwtTenantAuthenticationService.authenticate(jwt, "/api/auth/context")).thenReturn(new AuthenticatedTenantActor(
                "user-123",
                UUID.randomUUID(),
                "analyst@example.com",
                "Analyst User",
                tenantId,
                "Acme Security",
                null,
                Set.of("SECURITY_ANALYST", "TENANT_ADMIN")));

        mockMvc.perform(get("/api/auth/context").header("Authorization", "Bearer test.jwt"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.principal").value("user-123"))
                .andExpect(jsonPath("$.tenantId").value(tenantId.toString()))
                .andExpect(jsonPath("$.tenantName").value("Acme Security"))
                .andExpect(jsonPath("$.roles[0]").exists());
    }

    @Test
    void tenantJwtCanReadOperationalQualitySummaryInActiveWorkspace() throws Exception {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(42L);
        tenant.setName("Acme Security");
        tenant.setStatus("ACTIVE");
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(operationalQualityReadService.getSummary(tenant)).thenReturn(new OperationalQualitySummaryResponse(
                Instant.EPOCH,
                0,
                0,
                0,
                0,
                List.of()
        ));

        Jwt jwt = Jwt.withTokenValue("quality.jwt")
                .header("alg", "none")
                .subject("tenant-admin-1")
                .claim("email", "tenant.admin@example.com")
                .build();
        when(jwtDecoder.decode("quality.jwt")).thenReturn(jwt);
        when(jwtTenantAuthenticationService.authenticate(jwt, "/api/operations/quality/summary")).thenReturn(new AuthenticatedTenantActor(
                "tenant-admin-1",
                UUID.randomUUID(),
                "tenant.admin@example.com",
                "Tenant Admin",
                tenantId,
                "Acme Security",
                null,
                Set.of("TENANT_ADMIN")));

        mockMvc.perform(get("/api/operations/quality/summary").header("Authorization", "Bearer quality.jwt"))
                .andExpect(status().isOk());

        verify(workspaceService).getWorkspace();
        verify(operationalQualityReadService).getSummary(tenant);
    }
}
