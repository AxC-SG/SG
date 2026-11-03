package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPut;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.cbom.CbomRuleRolloutReconciler;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Rule-package lifecycle against real PostgreSQL: the governance read model exposes the packaged
 * versions and tenant lifecycle state, the reconciler records availability under the durable lease
 * without reassessing on the baseline, and non-administrators cannot change rule configuration.
 */
@PostgresControllerIntegrationTest
class CbomRuleLifecyclePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cbom_rule_lifecycle");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private CbomRuleRolloutReconciler reconciler;
    @Autowired private TenantService tenantService;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private com.prototype.vulnwatch.service.cbom.CbomRuleLifecycleStore lifecycle;

    @Test
    void reconcilerRecordsBaselineAvailabilityUnderTheLeaseAndOnlyAdminsChangeRules() throws Exception {
        JsonNode initial = rules();
        assertEquals("scoutgrid-baseline", initial.path("packageId").asText());
        assertEquals("1.0.0", initial.path("effectiveVersion").asText());
        assertEquals("CURRENT", initial.path("pinState").asText());
        assertEquals("1.0.0", initial.path("availableVersions").get(0).path("version").asText());
        assertTrue(initial.path("availableVersions").get(0).path("pinnable").asBoolean());
        assertEquals(2048, initial.path("parameters").path("minimumRsaBits").asInt());

        var summary = reconciler.rollout();
        assertTrue(summary.tenantsVisited() >= 1);
        assertEquals(0, summary.tenantsUpgraded(), "the baseline package moves no tenant");
        assertEquals(0, summary.jobsEnqueued(), "bootstrapping on the baseline does not reassess the fleet");

        var lease = TenantContext.runAsPlatform(() -> jdbc.queryForMap(
                "select owner, stage, completed_stage, tenants_processed from platform.cbom_rule_rollout_leases where package_key = ?",
                "scoutgrid-baseline@1.0.0"));
        assertEquals(null, lease.get("owner"), "the lease is released after the run");
        assertEquals("GENERAL", lease.get("completed_stage"));
        assertEquals("EFFECTIVE", rules().path("availableVersions").get(0).path("tenantStatus").asText());
        assertEquals(0, reconciler.rollout().tenantsVisited(), "a completed stage is not revisited");

        // A pin change by a direct tenant administrator is recorded; others are refused.
        // The local API-key identity has no direct tenant membership, so it is refused with 403
        // (not 500) and nothing is recorded.
        mockMvc.perform(asPlatformOwner(authedPut("/api/bom/cbom/governance/rules"))
                        .contentType("application/json")
                        .content("{\"versionPolicy\":\"PINNED\",\"pinnedVersion\":\"1.0.0\",\"reason\":\"freeze\"}"))
                .andExpect(status().isForbidden());
        assertEquals(0L, (long) inTenant(() -> jdbc.queryForObject("select count(*) from cbom_rule_selection_history", Long.class)));

        // The selection history store itself works against the real tenant table.
        inTenant(() -> {
            lifecycle.recordHistory(tenantService.getDefaultTenant().getId(), "scoutgrid-baseline", "TENANT_UPDATE", "1.0.0", "1.0.0",
                    "PINNED", "admin", "freeze", "{\"minimumRsaBits\":3072}", null);
            return null;
        });
        JsonNode recorded = rules().path("history").get(0);
        assertEquals("TENANT_UPDATE", recorded.path("action").asText());
        assertEquals("admin", recorded.path("actor").asText());

        mockMvc.perform(asPlatformOwner(authedPut("/api/bom/cbom/governance/rules"))
                        .contentType("application/json")
                        .content("{\"versionPolicy\":\"PINNED\",\"pinnedVersion\":\"9.9.9\",\"reason\":\"bad\"}"))
                .andExpect(status().is4xxClientError());
        assertEquals(0L, (long) inTenant(() -> jdbc.queryForObject(
                "select count(*) from cbom_rule_selection_history where to_version = '9.9.9'", Long.class)));
    }

    private JsonNode rules() throws Exception {
        return objectMapper.readTree(mockMvc.perform(asPlatformOwner(authedGet("/api/bom/cbom/governance/rules")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private <T> T inTenant(Supplier<T> work) {
        Tenant tenant = tenantService.getDefaultTenant();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        try {
            return work.get();
        } finally {
            TenantContext.clear();
        }
    }
}
