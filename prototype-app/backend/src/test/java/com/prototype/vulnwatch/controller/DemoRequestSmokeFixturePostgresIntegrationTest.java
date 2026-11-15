package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedDelete;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.prototype.vulnwatch.service.DemoRequestSmokeFixtureService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** The lab release smoke's disposable demo requests: platform-owner only, capped, undeliverable. */
@PostgresControllerIntegrationTest
class DemoRequestSmokeFixturePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("demo_smoke_fixtures");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.tenancy.require-tenant-context", () -> "true");
        registry.add("app.demo.smoke-fixtures-enabled", () -> "true");
    }

    @Autowired MockMvc mvc;
    @Autowired @Qualifier("platformJdbcTemplate") JdbcTemplate jdbc;

    @Test
    void platformOwnerCreatesCappedUndeliverableFixturesThatRejectAndDeleteClear() throws Exception {
        mvc.perform(authedPost("/api/platform/demo-requests/smoke-fixtures")).andExpect(status().isForbidden());

        List<String> ids = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            String body = mvc.perform(asPlatformOwner(authedPost("/api/platform/demo-requests/smoke-fixtures")))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("PENDING"))
                    .andReturn().getResponse().getContentAsString();
            ids.add(JsonPath.read(body, "$.id"));
        }
        mvc.perform(asPlatformOwner(authedPost("/api/platform/demo-requests/smoke-fixtures")))
                .andExpect(status().isConflict());

        assertEquals(5, jdbc.queryForObject("""
                select count(*) from tenant_default.demo_requests
                where company = ? and email like ? and status = 'PENDING'
                """, Integer.class, DemoRequestSmokeFixtureService.COMPANY, "%@" + DemoRequestSmokeFixtureService.EMAIL_DOMAIN));
        assertEquals(5, jdbc.queryForObject(
                "select count(*) from tenant_default.audit_events where action = 'demo.request.smoke_fixture_created'",
                Integer.class));

        mvc.perform(asPlatformOwner(authedPost("/api/platform/demo-requests/{id}/reject", ids.get(0)))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"release smoke\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("REJECTED"));
        mvc.perform(asPlatformOwner(authedDelete("/api/platform/demo-requests/{id}", ids.get(1))))
                .andExpect(status().isOk());
        mvc.perform(asPlatformOwner(authedPost("/api/platform/demo-requests/smoke-fixtures")))
                .andExpect(status().isOk());
        mvc.perform(asPlatformOwner(authedPost("/api/platform/demo-requests/smoke-fixtures")))
                .andExpect(status().isOk());
        mvc.perform(asPlatformOwner(authedPost("/api/platform/demo-requests/smoke-fixtures")))
                .andExpect(status().isConflict());
    }
}
