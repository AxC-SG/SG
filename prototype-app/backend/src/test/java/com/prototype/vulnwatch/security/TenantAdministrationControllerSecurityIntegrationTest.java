package com.prototype.vulnwatch.security;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.TenantAdministrationController;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.AuthenticatedTenantActor;
import com.prototype.vulnwatch.service.IdentityAdministrationService;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.PlatformInventoryConnectorHealthService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAdministrationService;
import com.prototype.vulnwatch.service.TenantAccessControlService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.TenantUserInviteService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
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
        controllers = TenantAdministrationController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
                "app.security.api-key=test-api-key",
                "app.security.creator-key=test-creator-key",
                "spring.mvc.throw-exception-if-no-handler-found=true",
                "spring.web.resources.add-mappings=false"
        })
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class TenantAdministrationControllerSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TenantAdministrationService tenantAdministrationService;
    @MockitoBean
    private IdentityAdministrationService identityAdministrationService;
    @MockitoBean
    private AuditEventService auditEventService;
    @MockitoBean
    private WorkspaceService workspaceService;
    @MockitoBean
    private TenantService tenantService;
    @MockitoBean
    private TenantRepository tenantRepository;
    @MockitoBean
    private PlatformInventoryConnectorHealthService platformInventoryConnectorHealthService;
    @MockitoBean
    private TenantUserInviteService tenantUserInviteService;
    @MockitoBean
    private TenantAccessControlService tenantAccessControlService;
    @MockitoBean
    private TenantSupportGrantService tenantSupportGrantService;
    @MockitoBean
    private JwtDecoder jwtDecoder;
    @MockitoBean
    private JwtTenantAuthenticationService jwtTenantAuthenticationService;

    @MockitoBean
    private OperationalMetricsService operationalMetricsService;

    private Tenant tenant;
    private Jwt jwt;

    @BeforeEach
    void setUp() {
        tenant = new Tenant();
        tenant.setId(UUID.fromString("00000000-0000-0000-0000-000000000111"));
        tenant.setName("Acme");
        tenant.setSlug("acme");
        tenant.setStatus("ACTIVE");
        tenant.setPlanCode("enterprise");
        tenant.setMaxConnectorCount(25);
        tenant.setMaxServiceAccountCount(50);
        tenant.setMaxDailySbomUploads(250);
        tenant.setMaxExportRows(100000);
        tenant.setMaxDailyExposureRefreshes(60);
        tenant.setSbomRateLimitWindowSeconds(120);
        tenant.setMaxSbomJobsPerRateLimitWindow(12);
        tenant.setMaxActiveSbomJobs(3);
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(tenantRepository.findById(tenant.getId())).thenReturn(java.util.Optional.of(tenant));
        jwt = Jwt.withTokenValue("test-token")
                .header("alg", "none")
                .claim("sub", "test-user")
                .build();
        when(jwtDecoder.decode("test-token")).thenReturn(jwt);
    }

    @Test
    void platformOwnerCanReadTenantQuotaPolicy() throws Exception {
        when(tenantAdministrationService.getTenant(tenant.getId())).thenReturn(tenant);

        mockMvc.perform(get("/api/platform/tenants/{tenantId}", tenant.getId())
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(tenant.getId().toString()))
                .andExpect(jsonPath("$.sbomRateLimitWindowSeconds").value(120))
                .andExpect(jsonPath("$.maxSbomJobsPerRateLimitWindow").value(12))
                .andExpect(jsonPath("$.maxActiveSbomJobs").value(3));
    }

    @Test
    void platformOwnerCanUpdateTenantQuotaPolicy() throws Exception {
        when(tenantAdministrationService.updateQuotas(org.mockito.ArgumentMatchers.eq(tenant.getId()), org.mockito.ArgumentMatchers.any()))
                .thenReturn(tenant);

        mockMvc.perform(patch("/api/platform/tenants/{tenantId}/quotas", tenant.getId())
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .contentType("application/json")
                        .content("""
                                {
                                  "maxConnectorCount": 25,
                                  "maxServiceAccountCount": 50,
                                  "maxDailySbomUploads": 250,
                                  "maxExportRows": 100000,
                                  "maxDailyExposureRefreshes": 60,
                                  "sbomRateLimitWindowSeconds": 120,
                                  "maxSbomJobsPerRateLimitWindow": 12,
                                  "maxActiveSbomJobs": 3
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maxDailySbomUploads").value(250))
                .andExpect(jsonPath("$.sbomRateLimitWindowSeconds").value(120))
                .andExpect(jsonPath("$.maxSbomJobsPerRateLimitWindow").value(12))
                .andExpect(jsonPath("$.maxActiveSbomJobs").value(3));
    }

    @Test
    void platformOwnerCanExtendDemoTenantExpiry() throws Exception {
        tenant.setDemoExpiresAt(java.time.Instant.parse("2099-08-31T23:59:59Z"));
        when(tenantAdministrationService.extendDemoExpiry(
                org.mockito.ArgumentMatchers.eq(tenant.getId()),
                org.mockito.ArgumentMatchers.any(java.time.Instant.class)))
                .thenReturn(tenant);

        mockMvc.perform(patch("/api/platform/tenants/{tenantId}/demo-expiry", tenant.getId())
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .contentType("application/json")
                        .content("""
                                {"expiresAt":"2099-08-31T23:59:59Z"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.demoExpiresAt").value("2099-08-31T23:59:59Z"));
    }

    @Test
    void demoTenantExtensionRequiresPlatformOwnerPrivileges() throws Exception {
        mockMvc.perform(patch("/api/platform/tenants/{tenantId}/demo-expiry", tenant.getId())
                        .header("X-API-Key", "test-api-key")
                        .contentType("application/json")
                        .content("""
                                {"expiresAt":"2099-08-31T23:59:59Z"}
                                """))
                .andExpect(status().isForbidden());
    }

    @Test
    void tenantQuotaPolicyUpdateRequiresPlatformOwnerPrivileges() throws Exception {
        mockMvc.perform(patch("/api/platform/tenants/{tenantId}/quotas", tenant.getId())
                        .header("X-API-Key", "test-api-key")
                        .contentType("application/json")
                        .content("""
                                {
                                  "maxConnectorCount": 25,
                                  "maxServiceAccountCount": 50,
                                  "maxDailySbomUploads": 250,
                                  "maxExportRows": 100000,
                                  "maxDailyExposureRefreshes": 60
                                }
                                """))
                .andExpect(status().isForbidden());
    }

    @Test
    void platformOwnerCannotReadTenantMembers() throws Exception {
        when(jwtTenantAuthenticationService.authenticate(jwt, "/api/tenants/" + tenant.getId() + "/members"))
                .thenReturn(authenticatedActor(Set.of("PLATFORM_OWNER"), null, null));
        mockMvc.perform(get("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", "Bearer test-token"))
                .andExpect(status().isForbidden());
    }

    @Test
    void platformOwnerCannotReadTenantInvites() throws Exception {
        when(jwtTenantAuthenticationService.authenticate(jwt, "/api/tenants/" + tenant.getId() + "/invites"))
                .thenReturn(authenticatedActor(Set.of("PLATFORM_OWNER"), null, null));
        mockMvc.perform(get("/api/tenants/{tenantId}/invites", tenant.getId())
                        .header("Authorization", "Bearer test-token"))
                .andExpect(status().isForbidden());
    }

    @Test
    void tenantAdminCanReadTenantMembersWhenAuthorized() throws Exception {
        when(identityAdministrationService.listMembers(tenant.getId())).thenReturn(List.of());
        when(jwtTenantAuthenticationService.authenticate(jwt, "/api/tenants/" + tenant.getId() + "/members"))
                .thenReturn(authenticatedActor(Set.of("TENANT_ADMIN"), tenant.getId(), tenant.getName()));

        mockMvc.perform(get("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", "Bearer test-token"))
                .andExpect(status().isOk());
    }

    @Test
    void tenantAdminCanReadTenantInvitesWhenAuthorized() throws Exception {
        when(tenantUserInviteService.listInvites(tenant.getId())).thenReturn(List.of());
        when(jwtTenantAuthenticationService.authenticate(jwt, "/api/tenants/" + tenant.getId() + "/invites"))
                .thenReturn(authenticatedActor(Set.of("TENANT_ADMIN"), tenant.getId(), tenant.getName()));

        mockMvc.perform(get("/api/tenants/{tenantId}/invites", tenant.getId())
                        .header("Authorization", "Bearer test-token"))
                .andExpect(status().isOk());
    }

    private AuthenticatedTenantActor authenticatedActor(java.util.Set<String> roles, UUID tenantId, String tenantName) {
        return new AuthenticatedTenantActor(
                "test-user",
                UUID.fromString("00000000-0000-0000-0000-000000000999"),
                "test.user@example.com",
                "Test User",
                tenantId,
                tenantName,
                tenantId == null ? null : "tenant_test",
                roles
        );
    }
}
