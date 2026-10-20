package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.mock.web.MockCookie;
import jakarta.servlet.http.Cookie;

@PostgresControllerIntegrationTest
class DemoLifecycleControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("demo_lifecycle_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.tenancy.require-tenant-context", () -> "true");
        registry.add("app.security.jwt.hmac-secret", () -> "demo-lifecycle-integration-test-signing-secret-32-bytes-minimum");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantRepository tenantRepository;

    @Test
    void demoRequestCanBeProvisionedAndActivatedWithStrictTenantContext() throws Exception {
        String requestBody = """
                {
                  "fullName": "Alex Rivera",
                  "email": "alex@example.com",
                  "company": "Example Co",
                  "roleTitle": "Security Lead",
                  "companySize": "101-1000",
                  "useCase": "SBOM validation",
                  "notes": "Need a guided evaluation",
                  "acceptedTerms": true,
                  "captchaToken": "test-captcha-token"
                }
                """;
        mockMvc.perform(post("/api/demo-requests")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.accepted").value(true));

        mockMvc.perform(post("/api/demo-requests")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.accepted").value(true));

        String queueResponse = mockMvc.perform(asPlatformOwner(authedGet("/api/platform/demo-requests")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andReturn().getResponse().getContentAsString();
        String requestId = com.jayway.jsonpath.JsonPath.read(queueResponse, "$[0].id");

        String approvalResponse = mockMvc.perform(asPlatformOwner(authedPost("/api/platform/demo-requests/{requestId}/approve", requestId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").isString())
                .andExpect(jsonPath("$.provisionedPlanCode").value("ENTERPRISE"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        String tenantId = com.jayway.jsonpath.JsonPath.read(approvalResponse, "$.tenantId");
        String inviteUrl = com.jayway.jsonpath.JsonPath.read(approvalResponse, "$.latestInvite.inviteUrl");
        String inviteToken = inviteUrl.substring(inviteUrl.indexOf("#token=") + 7);
        Tenant tenant = tenantRepository.findById(UUID.fromString(tenantId)).orElseThrow();

        org.junit.jupiter.api.Assertions.assertEquals("ENTERPRISE", tenant.getPlanCode());
        org.junit.jupiter.api.Assertions.assertNotNull(tenant.getDemoExpiresAt());
        org.junit.jupiter.api.Assertions.assertEquals("REQUEST_REVIEW", tenant.getDemoSource());
        org.junit.jupiter.api.Assertions.assertEquals("alex@example.com", tenant.getDemoOwnerEmail());
        tenant.setStatus("ACTIVE");
        tenantRepository.saveAndFlush(tenant);

        String setCookie = mockMvc.perform(post("/api/demo-invites/accept").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + inviteToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACCEPTED"))
                .andExpect(jsonPath("$.setupToken").doesNotExist())
                .andExpect(jsonPath("$.tenantId").value(tenantId))
                .andReturn().getResponse().getHeader("Set-Cookie");

        Cookie setupCookie = MockCookie.parse(setCookie);
        mockMvc.perform(post("/api/auth/setup-password").with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf())
                        .cookie(setupCookie)
                        .header("X-Scout-Setup", "1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"StrongPassword-123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isString());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"alex@example.com\",\"password\":\"StrongPassword-123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isString());
    }
}
