package com.prototype.vulnwatch.controller;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.domain.AuditEvent;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAccessControlService;
import com.prototype.vulnwatch.service.TenantQuotaService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
        controllers = AuditEventController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
                "app.security.api-key=test-api-key",
                "app.security.creator-key=test-creator-key"
        })
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class AuditEventControllerPlatformAuditTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuditEventService auditEventService;
    @MockitoBean
    private TenantQuotaService tenantQuotaService;
    @MockitoBean
    private TenantAccessControlService tenantAccessControlService;
    @MockitoBean
    private OperationalMetricsService operationalMetricsService;
    @MockitoBean
    private TenantRepository tenantRepository;
    @MockitoBean
    private WorkspaceService workspaceService;
    @MockitoBean
    private TenantSupportGrantService tenantSupportGrantService;

    @Test
    void platformOwnerCanReadPlatformUserAuditEvents() throws Exception {
        AuditEvent event = new AuditEvent();
        event.setAction("platform.user.setup_issued");
        event.setTargetType("app_user");
        event.setTargetId(UUID.fromString("00000000-0000-0000-0000-000000000321").toString());
        when(auditEventService.listPlatformUserEvents()).thenReturn(List.of(event));

        mockMvc.perform(get("/api/audit-events/platform-users")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].action").value("platform.user.setup_issued"))
                .andExpect(jsonPath("$[0].targetType").value("app_user"));
    }

    @Test
    void platformUserAuditEndpointRequiresPlatformOwnerPrivileges() throws Exception {
        mockMvc.perform(get("/api/audit-events/platform-users")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isForbidden());
    }
}
