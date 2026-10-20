package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.*;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.Tenant;

class AwsCustomerBindingTest {
    private static final String ROLE = "arn:aws:iam::123456789012:role/path/Discovery";
    @Test
    void generatesTenantBoundImmutableUniqueExternalIds() {
        UUID tenant = UUID.randomUUID();
        String id = AwsCustomerBinding.externalId(tenant, null, 0, null);
        assertNotEquals(id, AwsCustomerBinding.externalId(tenant, null, 0, null));
        assertEquals(id, AwsCustomerBinding.externalId(tenant, id, 1, id));
        assertThrows(IllegalArgumentException.class, () -> AwsCustomerBinding.externalId(tenant, id, 1, "other"));
        assertThrows(IllegalArgumentException.class, () -> AwsCustomerBinding.validate(UUID.randomUUID(), "123456789012", ROLE, id, 1));
        assertDoesNotThrow(() -> AwsCustomerBinding.validate(tenant, "123456789012", ROLE, id, 1));
    }
    @Test
    void rejectsAccountRoleAndEffectiveIdentityMismatch() {
        assertThrows(IllegalArgumentException.class, () -> AwsCustomerBinding.validate(UUID.randomUUID(), "999999999999", ROLE, null, 0));
        assertThrows(IllegalStateException.class, () -> AwsCustomerBinding.verifyIdentity("123456789012", ROLE, "999999999999", "arn:aws:sts::999999999999:assumed-role/Discovery/session"));
        assertThrows(IllegalStateException.class, () -> AwsCustomerBinding.verifyIdentity("123456789012", ROLE, "123456789012", "arn:aws:sts::123456789012:assumed-role/Other/session"));
        assertDoesNotThrow(() -> AwsCustomerBinding.verifyIdentity("123456789012", ROLE, "123456789012", "arn:aws:sts::123456789012:assumed-role/Discovery/session"));
    }
    @Test
    void customerNoRoleOrLegacyBindingCannotAcquireAmbientCredentials() {
        var config = new AwsDiscoveryConfig();
        var tenant = new Tenant(); tenant.setId(UUID.randomUUID()); config.setTenant(tenant);
        assertThrows(IllegalArgumentException.class, () -> AwsCredentialProvider.from(config));
        config.setCrossAccountRoleArn(ROLE); config.setAwsAccountId("123456789012"); config.setExternalId("legacy-external-id");
        assertThrows(IllegalArgumentException.class, () -> AwsCredentialProvider.from(config));
    }
}
