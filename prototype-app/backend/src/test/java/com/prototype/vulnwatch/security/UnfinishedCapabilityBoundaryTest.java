package com.prototype.vulnwatch.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.controller.FixIntelligenceController;
import com.prototype.vulnwatch.service.FixDemoDataSeeder;
import com.prototype.vulnwatch.service.vulningestion.OsvTenantService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class UnfinishedCapabilityBoundaryTest {
    @Test
    void syntheticResultsAreUnavailableAtApiAndServiceBoundaries() {
        assertThatThrownBy(() -> new FixIntelligenceController().unavailable()).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> new FixDemoDataSeeder().generateDemoFixes()).isInstanceOf(ResponseStatusException.class);
    }
    @Test
    void unfinishedCorrelationCannotRunManuallyOrAsAStaleJob() {
        OsvTenantService service = new OsvTenantService();
        assertThatThrownBy(() -> service.correlateOsvAdvisoriesForTenant(UUID.randomUUID()))
                .isInstanceOf(ResponseStatusException.class).hasMessageContaining("OSV_TENANT_CORRELATION_UNAVAILABLE");
        assertThatCode(service::correlateOsvForAllEnabledTenants).doesNotThrowAnyException();
    }
    @Test
    void everySyntheticReadRouteReturnsGoneEvenWithoutTheSecurityChain() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(new FixIntelligenceController()).build();
        for (String path : new String[] {"/api/fix-intelligence", "/api/fix-intelligence/fixes",
                "/api/fix-intelligence/fixes/example", "/api/fix-intelligence/statistics", "/api/fix-intelligence/fixes-by-type/patch"}) {
            mvc.perform(get(path)).andExpect(status().isGone());
        }
    }
}
