package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiAliasRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

class ServiceNowCredentialIsolationTest {

    @Test
    void unconfiguredTenantIgnoresLegacyGlobalCredentialsAndCannotTestThem() {
        var repository = mock(ServiceNowCmdbConfigRepository.class);
        var outbound = mock(OutboundHttpClient.class);
        new ApplicationContextRunner()
                .withPropertyValues("app.cmdb.servicenow.base-url=https://platform.service-now.example",
                        "app.cmdb.servicenow.username=platform-user", "app.cmdb.servicenow.password=controlled-platform-sentinel")
                .withBean(ServiceNowCmdbConfigRepository.class, () -> repository)
                .withBean(OutboundHttpClient.class, () -> outbound)
                .withBean(OutboundPolicyFactory.class, () -> mock(OutboundPolicyFactory.class))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withBean(TenantQuotaService.class, () -> mock(TenantQuotaService.class))
                .withBean(CredentialEncryptionService.class,
                        () -> new CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
                .withBean(OutboundHostPolicy.class, () -> new OutboundHostPolicy(""))
                .withBean(ServiceNowCmdbConfigService.class)
                .run(context -> {
                    ServiceNowCmdbConfigService service = context.getBean(ServiceNowCmdbConfigService.class);
                    Tenant tenant = tenant();
                    assertTrue(service.resolveRuntimeConfig(tenant).isEmpty());
                    assertEquals(400, assertThrows(ResponseStatusException.class, () -> service.test(tenant))
                            .getStatusCode().value());
                    verifyNoInteractions(outbound);
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"lookupInServiceNow", "lookupInServiceNowBySysId"})
    void ciEnrichmentCannotSubstituteGlobalCredentials(String method) {
        var config = mock(ServiceNowCmdbConfigService.class);
        var outbound = mock(OutboundHttpClient.class);
        Tenant tenant = tenant();
        when(config.resolveRuntimeConfig(tenant)).thenReturn(Optional.empty());
        CiResolutionService service = new CiResolutionService(mock(CiRepository.class), mock(CiAliasRepository.class),
                mock(AssetRepository.class), outbound, mock(OutboundPolicyFactory.class), new ObjectMapper(),
                config, mock(TenantSchemaExecutionService.class));

        assertNull(ReflectionTestUtils.invokeMethod(service, method, tenant, "controlled-ci-key"));

        verifyNoInteractions(outbound);
    }

    @Test
    void savedTenantSecretStillDecryptsOnlyForItsOwnConfiguration() {
        Tenant configured = tenant();
        var repository = mock(ServiceNowCmdbConfigRepository.class);
        var encryption = new CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        ServiceNowCmdbConfig record = new ServiceNowCmdbConfig();
        record.setTenant(configured);
        record.setBaseUrl("https://customer.service-now.example");
        record.setUsername("customer-user");
        record.setCredentialSecret(encryption.encrypt("customer-only-sentinel"));
        when(repository.findByTenant_IdAndSourceSystemIgnoreCase(configured.getId(), "servicenow"))
                .thenReturn(Optional.of(record));
        var service = new ServiceNowCmdbConfigService(repository, mock(OutboundHttpClient.class),
                mock(OutboundPolicyFactory.class), new ObjectMapper(), mock(TenantQuotaService.class), encryption);

        assertEquals("customer-only-sentinel", service.resolveRuntimeConfig(configured).orElseThrow().credentialSecret());
        assertTrue(service.resolveRuntimeConfig(tenant()).isEmpty());
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        return tenant;
    }
}
