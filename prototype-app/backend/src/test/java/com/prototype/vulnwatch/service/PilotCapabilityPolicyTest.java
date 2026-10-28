package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class PilotCapabilityPolicyTest {
    @Test void cohortIsExplicitAndCannotUseWildcardOrMalformedIdentity() {
        assertEquals(Set.of("slug:scoutgrid-internal-pilot"),TenantEntitlementService.parseEnforcementCohort("slug:scoutgrid-internal-pilot"));
        for (String invalid:java.util.List.of("*","slug:*","slug:","slug:another tenant","1-1-1-1-1"))
            assertThrows(IllegalStateException.class,() -> TenantEntitlementService.parseEnforcementCohort(invalid));
    }
    @Test void schemaFloorCannotBeLoweredBelowRequiredRetentionTables() {
        assertFalse(TenantSchemaCompatibility.supports(4,1,5));
        assertFalse(TenantSchemaCompatibility.supports(5,1,6));
        assertTrue(TenantSchemaCompatibility.supports(9,1,9));
    }
    @Test void generativePilotContainmentPrecedesCredentialResolution() {
        var environment=new MockEnvironment().withProperty("app.environment","production").withProperty("app.openai.enabled","true").withProperty("OPENAI_API_KEY","test-only");
        var policy=new GenerativeAssistancePolicy(environment);
        assertFalse(policy.isEnabled());assertNull(policy.configuredApiKey());
        assertFalse(GenericAzureDiscoveryPolicy.available());
        assertEquals(410,assertThrows(org.springframework.web.server.ResponseStatusException.class,GenericAzureDiscoveryPolicy::requireAvailable).getStatusCode().value());
    }
}
