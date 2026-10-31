package com.prototype.vulnwatch.aisecurity.controller;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.aisecurity.aws.AwsPermissionPreflightService;
import com.prototype.vulnwatch.aisecurity.aws.AwsPolicyPermissionMatrix;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectorConfigResponse;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class AiSecurityConnectorControllerTest {
    private final WorkspaceService workspace = mock(WorkspaceService.class);
    private final AiSecurityAccessService access = mock(AiSecurityAccessService.class);
    private final AiSecurityAwsConnectorService connectors = mock(AiSecurityAwsConnectorService.class);
    private final Tenant tenant = new Tenant();
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        tenant.setId(UUID.randomUUID());
        when(workspace.getWorkspace()).thenReturn(tenant);
        mvc = MockMvcBuilders.standaloneSetup(new AiSecurityConnectorController(
                workspace, mock(RequestActorService.class), access, connectors,
                mock(AwsPermissionPreflightService.class), mock(AwsPolicyPermissionMatrix.class)))
                .build();
    }

    @Test
    void unconfiguredConnectorReturnsJsonNullInsteadOfAnEmptySuccessfulBody() throws Exception {
        mvc.perform(get("/api/connectors/ai-security/aws"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(content().string("null"));

        verify(access).assertEntitled(tenant);
        verify(connectors).get(tenant);
    }

    @Test
    void configuredConnectorRetainsItsResponseFields() throws Exception {
        when(connectors.get(tenant)).thenReturn(new ConnectorConfigResponse(
                UUID.randomUUID(), "123456789012", "arn:aws:iam::123456789012:role/Scout",
                "CROSS_ACCOUNT_ROLE", "external-id", List.of("us-east-1"), true,
                Instant.parse("2026-10-30T00:00:00Z"), Instant.parse("2026-10-30T00:00:00Z")));

        mvc.perform(get("/api/connectors/ai-security/aws"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.accountId").value("123456789012"))
                .andExpect(jsonPath("$.regions[0]").value("us-east-1"))
                .andExpect(jsonPath("$.enabled").value(true));
    }
}
