package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.any;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsCustomerBinding;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

class AiSecurityAwsCredentialBindingTest {
    @Test
    void skippedConnectionTestStillEnforcesEffectiveAssumedIdentity() {
        var service = spy(new AiSecurityAwsConnectorService(null, new ObjectMapper(), null, null, null, null));
        var sts = mock(StsClient.class);
        doReturn(sts).when(service).stsClient(any());
        UUID tenant = UUID.randomUUID();
        var config = new AiSecurityAwsConnectorService.ConnectorSecret(UUID.randomUUID(), "123456789012",
                "arn:aws:iam::123456789012:role/Discovery", AwsCustomerBinding.externalId(tenant, null, 0, null), List.of("us-east-1"), true, tenant, 1);
        when(sts.getCallerIdentity()).thenReturn(GetCallerIdentityResponse.builder().account("999999999999")
                .arn("arn:aws:sts::999999999999:assumed-role/Discovery/session").build());
        assertThrows(IllegalStateException.class, () -> service.credentials(config));
        when(sts.getCallerIdentity()).thenReturn(GetCallerIdentityResponse.builder().account("123456789012")
                .arn("arn:aws:sts::123456789012:assumed-role/Discovery/session").build());
        try (var handle = service.credentials(config)) { assertNotNull(handle.provider()); }
        verify(sts, times(2)).getCallerIdentity();
    }

    @Test
    void missingRoleWrongTenantAndLegacyBindingsNeverAcquireProvider() {
        var service = spy(new AiSecurityAwsConnectorService(null, new ObjectMapper(), null, null, null, null));
        UUID tenant = UUID.randomUUID();
        String externalId = AwsCustomerBinding.externalId(tenant, null, 0, null);
        assertThrows(IllegalArgumentException.class, () -> service.credentials(new AiSecurityAwsConnectorService.ConnectorSecret(
                UUID.randomUUID(), "123456789012", null, externalId, List.of("us-east-1"), true, tenant, 1)));
        assertThrows(IllegalArgumentException.class, () -> service.credentials(new AiSecurityAwsConnectorService.ConnectorSecret(
                UUID.randomUUID(), "123456789012", "arn:aws:iam::123456789012:role/Discovery", externalId, List.of("us-east-1"), true, UUID.randomUUID(), 1)));
        verify(service, never()).stsClient(any());
    }
}
