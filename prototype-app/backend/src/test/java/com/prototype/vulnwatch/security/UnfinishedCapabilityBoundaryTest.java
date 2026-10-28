package com.prototype.vulnwatch.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.service.FixDemoDataSeeder;
import com.prototype.vulnwatch.service.vulningestion.OsvTenantService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class UnfinishedCapabilityBoundaryTest {
    @Test
    void syntheticFixDataCannotBeGenerated() {
        assertThatThrownBy(() -> new FixDemoDataSeeder().generateDemoFixes()).isInstanceOf(ResponseStatusException.class);
    }
    @Test
    void unfinishedCorrelationCannotRunManuallyOrAsAStaleJob() {
        OsvTenantService service = new OsvTenantService();
        assertThatThrownBy(() -> service.correlateOsvAdvisoriesForTenant(UUID.randomUUID()))
                .isInstanceOf(ResponseStatusException.class).hasMessageContaining("OSV_TENANT_CORRELATION_UNAVAILABLE");
        assertThatCode(service::correlateOsvForAllEnabledTenants).doesNotThrowAnyException();
    }
}
