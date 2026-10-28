package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsDiscoveryClient;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AwsDiscoveryTargetRequest;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class InventoryConnectorTenantScopingTest {

    @Mock
    AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;
    @Mock
    AwsDiscoveryClient awsDiscoveryClient;
    @Mock
    TenantQuotaService tenantQuotaService;
    @Mock
    CredentialEncryptionService credentialEncryptionService;
    @Mock
    ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;
    @Mock
    OutboundHttpClient outboundHttpClient;
    @Mock
    OutboundPolicyFactory outboundPolicyFactory;
    @Mock
    SccmCmdbConfigRepository sccmCmdbConfigRepository;
    @Mock
    SccmQueryService sccmQueryService;
    @Mock
    AwsDiscoveryTargetRepository awsDiscoveryTargetRepository;
    @Mock
    AssetRepository assetRepository;

    @Test
    void awsConfigLookupUsesTenantScopedRepositoryMethod() {
        Tenant tenant = tenant("acme");
        AwsDiscoveryConfig config = new AwsDiscoveryConfig();
        config.setTenant(tenant);
        config.setSourceSystem("aws");
        config.setAutoSyncEnabled(true);
        config.setIntervalMinutes(60);

        AwsDiscoveryConfigService service = new AwsDiscoveryConfigService(
                awsDiscoveryConfigRepository,
                awsDiscoveryTargetRepository,
                awsDiscoveryClient,
                new ObjectMapper(),
                tenantQuotaService,
                credentialEncryptionService
        );

        when(awsDiscoveryConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws"))
                .thenReturn(Optional.of(config));

        assertEquals("aws", service.get(tenant).sourceSystem());
    }

    @Test
    void serviceNowConfigLookupUsesTenantScopedRepositoryMethod() {
        Tenant tenant = tenant("acme");
        ServiceNowCmdbConfig config = new ServiceNowCmdbConfig();
        config.setTenant(tenant);
        config.setSourceSystem("servicenow");
        config.setBaseUrl("https://acme.service-now.example");

        ServiceNowCmdbConfigService service = new ServiceNowCmdbConfigService(
                serviceNowCmdbConfigRepository,
                outboundHttpClient,
                outboundPolicyFactory,
                new ObjectMapper(),
                tenantQuotaService,
                credentialEncryptionService
        );

        when(serviceNowCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow"))
                .thenReturn(Optional.of(config));

        assertEquals("https://acme.service-now.example", service.get(tenant).baseUrl());
    }

    @Test
    void sccmConfigLookupUsesTenantScopedRepositoryMethod() {
        Tenant tenant = tenant("acme");
        SccmCmdbConfig config = new SccmCmdbConfig();
        config.setTenant(tenant);
        config.setSourceSystem("sccm");
        config.setJdbcUrl("jdbc:sqlserver://acme");

        SccmCmdbConfigService service = new SccmCmdbConfigService(
                sccmCmdbConfigRepository,
                sccmQueryService,
                tenantQuotaService,
                credentialEncryptionService,
                new SccmJdbcPolicy("acme")
        );

        when(sccmCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm"))
                .thenReturn(Optional.of(config));

        assertEquals("jdbc:sqlserver://acme", service.get(tenant).jdbcUrl());
    }

    @Test
    void awsTargetUpdateRejectsCrossTenantTarget() {
        Tenant tenant = tenant("acme");
        UUID targetId = UUID.randomUUID();
        AwsDiscoveryTargetService service = new AwsDiscoveryTargetService(
                awsDiscoveryConfigRepository,
                awsDiscoveryTargetRepository,
                assetRepository,
                awsDiscoveryClient,
                new ObjectMapper(),
                tenantQuotaService,
                credentialEncryptionService
        );

        when(awsDiscoveryTargetRepository.findByIdAndTenant_Id(targetId, tenant.getId()))
                .thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.update(tenant, targetId, new AwsDiscoveryTargetRequest(
                        "123456789012",
                        "Acme",
                        "arn:aws:iam::123456789012:role/demo",
                        null,
                        true,
                        "[\"us-east-1\"]",
                        "[\"EC2\"]"
                ))
        );

        assertEquals(404, ex.getStatusCode().value());
    }

    @Test
    void awsTargetDeleteRejectsCrossTenantTarget() {
        Tenant tenant = tenant("acme");
        UUID targetId = UUID.randomUUID();
        AwsDiscoveryTargetService service = new AwsDiscoveryTargetService(
                awsDiscoveryConfigRepository,
                awsDiscoveryTargetRepository,
                assetRepository,
                awsDiscoveryClient,
                new ObjectMapper(),
                tenantQuotaService,
                credentialEncryptionService
        );

        when(awsDiscoveryTargetRepository.findByIdAndTenant_Id(targetId, tenant.getId()))
                .thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.delete(tenant, targetId));

        assertEquals(404, ex.getStatusCode().value());
    }

    @Test
    void awsTargetTestRejectsCrossTenantTarget() {
        Tenant tenant = tenant("acme");
        UUID targetId = UUID.randomUUID();
        AwsDiscoveryTargetService service = new AwsDiscoveryTargetService(
                awsDiscoveryConfigRepository,
                awsDiscoveryTargetRepository,
                assetRepository,
                awsDiscoveryClient,
                new ObjectMapper(),
                tenantQuotaService,
                credentialEncryptionService
        );

        when(awsDiscoveryTargetRepository.findByIdAndTenant_Id(targetId, tenant.getId()))
                .thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.test(tenant, targetId));

        assertEquals(404, ex.getStatusCode().value());
    }

    private Tenant tenant(String slug) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(slug.toUpperCase());
        tenant.setSlug(slug);
        return tenant;
    }
}
