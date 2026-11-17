package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.CiAlias;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiAliasRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

class CiResolutionServiceTest {

    @Test
    void batchResolvePreservesCachedOwnershipWithoutServiceNowSysIdLookup() {
        String sysId = "b4fd7c8437201000deeabfc8bcbe5dc1";
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");

        Asset cachedAsset = new Asset();
        cachedAsset.setTenant(tenant);
        cachedAsset.setIdentifier("ci:" + sysId);
        cachedAsset.setName("*ANNIE-IBM");
        cachedAsset.setOwnerEmail("Alene Rabeck");
        cachedAsset.setSupportGroup("App Engine Admins");

        Ci cachedCi = new Ci();
        cachedCi.setTenant(tenant);
        cachedCi.setAsset(cachedAsset);
        cachedCi.setSysId(sysId);
        cachedCi.setDisplayName("*ANNIE-IBM");
        cachedCi.setOwnerEmail("Alene Rabeck");
        cachedCi.setSupportGroup("App Engine Admins");

        Map<String, Ci> ciBySysId = new LinkedHashMap<>();
        ciBySysId.put(sysId, cachedCi);

        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        CiAliasRepository ciAliasRepository = mock(CiAliasRepository.class);
        ServiceNowCmdbConfigService configService = mock(ServiceNowCmdbConfigService.class);
        TenantSchemaExecutionService tenantSchemaExecutionService = mock(TenantSchemaExecutionService.class);
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciAliasRepository.save(any(CiAlias.class))).thenAnswer(invocation -> invocation.getArgument(0));
        doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(java.util.function.Supplier.class));

        RestTemplate restTemplate = new RestTemplate();
        CiResolutionService service = new CiResolutionService(
                ciRepository,
                ciAliasRepository,
                assetRepository,
                new OutboundHttpClient(restTemplate),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0L, 1, 1L, 60_000L, true, true)),
                new ObjectMapper(),
                configService,
                tenantSchemaExecutionService
        );
        CiResolutionService.BatchResolutionContext context = new CiResolutionService.BatchResolutionContext(
                tenant,
                "servicenow",
                ciBySysId,
                new LinkedHashMap<>(),
                new LinkedHashMap<>(),
                new LinkedHashMap<>()
        );

        CiResolutionService.Resolution firstResolution = service.resolve(
                context,
                tenant,
                sysId,
                "*ANNIE-IBM",
                null,
                CiResolutionService.OwnershipDetails.empty(),
                BusinessCriticality.MEDIUM,
                "servicenow"
        );
        CiResolutionService.Resolution secondResolution = service.resolve(
                context,
                tenant,
                sysId,
                "*ANNIE-IBM",
                null,
                CiResolutionService.OwnershipDetails.empty(),
                BusinessCriticality.MEDIUM,
                "servicenow"
        );

        assertEquals("Alene Rabeck", firstResolution.ci().getOwnerEmail());
        assertEquals("App Engine Admins", firstResolution.ci().getSupportGroup());
        assertEquals("Alene Rabeck", firstResolution.ci().getAsset().getOwnerEmail());
        assertEquals("App Engine Admins", firstResolution.ci().getAsset().getSupportGroup());
        assertEquals("Alene Rabeck", secondResolution.ci().getOwnerEmail());
        assertEquals("App Engine Admins", secondResolution.ci().getSupportGroup());
        verifyNoInteractions(configService);
    }

    @Test
    void supportGroupSysIdIsStoredLowerCaseBesideTheNameAndKeptWhenALaterRowOmitsIt() {
        String sysId = "c4fd7c8437201000deeabfc8bcbe5dc2";
        String groupSysId = "8A4DDE73C6112278017A6A4BAF547AA7";
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        CiRepository ciRepository = mock(CiRepository.class);
        AssetRepository assetRepository = mock(AssetRepository.class);
        CiAliasRepository ciAliasRepository = mock(CiAliasRepository.class);
        ServiceNowCmdbConfigService configService = mock(ServiceNowCmdbConfigService.class);
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciAliasRepository.save(any(CiAlias.class))).thenAnswer(invocation -> invocation.getArgument(0));
        TenantSchemaExecutionService scoped = mock(TenantSchemaExecutionService.class);
        doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(scoped).run(any(Tenant.class), any(java.util.function.Supplier.class));
        CiResolutionService service = new CiResolutionService(ciRepository, ciAliasRepository, assetRepository,
                new OutboundHttpClient(new RestTemplate()),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0L, 1, 1L, 60_000L, true, true)),
                new ObjectMapper(), configService, scoped);
        CiResolutionService.BatchResolutionContext context = new CiResolutionService.BatchResolutionContext(tenant,
                "servicenow", new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>());

        CiResolutionService.Resolution first = service.resolve(context, tenant, sysId, "pay-web-01", null,
                new CiResolutionService.OwnershipDetails(null, null, null, "Payments Support", groupSysId, null),
                BusinessCriticality.MEDIUM, "servicenow");
        assertEquals("Payments Support", first.ci().getSupportGroup());
        assertEquals(groupSysId.toLowerCase(), first.ci().getSupportGroupSysId());

        // A raw-value field list stores the reference with no display name; the name column stays clean.
        CiResolutionService.Resolution second = service.resolve(context, tenant, sysId, "pay-web-01", null,
                new CiResolutionService.OwnershipDetails(null, null, null, groupSysId, groupSysId, null),
                BusinessCriticality.MEDIUM, "servicenow");
        assertEquals("Payments Support", second.ci().getSupportGroup());
        assertEquals(groupSysId.toLowerCase(), second.ci().getSupportGroupSysId());
        verifyNoInteractions(configService);
    }

    @Test
    void resolveIgnoresCrossTenantCiAndAssetMatches() {
        String sysId = "b4fd7c8437201000deeabfc8bcbe5dc1";
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Alpha");

        Tenant otherTenant = new Tenant();
        otherTenant.setId(UUID.randomUUID());
        otherTenant.setName("Beta");

        Asset foreignAsset = new Asset();
        foreignAsset.setTenant(otherTenant);
        foreignAsset.setIdentifier("ci:" + sysId);
        foreignAsset.setName("foreign-host");

        Ci foreignCi = new Ci();
        foreignCi.setTenant(otherTenant);
        foreignCi.setAsset(foreignAsset);
        foreignCi.setSysId(sysId);
        foreignCi.setDisplayName("foreign-host");

        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        CiAliasRepository ciAliasRepository = mock(CiAliasRepository.class);
        ServiceNowCmdbConfigService configService = mock(ServiceNowCmdbConfigService.class);
        TenantSchemaExecutionService tenantSchemaExecutionService = mock(TenantSchemaExecutionService.class);

        when(ciRepository.findBySysIdIn(List.of(sysId))).thenReturn(List.of(foreignCi));
        when(assetRepository.findByIdentifierIn(List.of("ci:" + sysId))).thenReturn(List.of(foreignAsset));
        when(ciRepository.findByTenant_IdAndSysIdIn(tenant.getId(), List.of(sysId))).thenReturn(List.of());
        when(assetRepository.findByTenant_IdAndIdentifierIn(tenant.getId(), List.of("ci:" + sysId))).thenReturn(List.of());
        when(ciAliasRepository.findByTenant_IdAndNormalizedAliasNameAndSourceSystem(tenant.getId(), "host-01", "servicenow"))
                .thenReturn(java.util.Optional.empty());
        when(ciAliasRepository.findByTenant_IdAndNormalizedAliasName(tenant.getId(), "host-01")).thenReturn(List.of());
        when(ciAliasRepository.save(any(CiAlias.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));
        doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(java.util.function.Supplier.class));

        CiResolutionService service = new CiResolutionService(
                ciRepository,
                ciAliasRepository,
                assetRepository,
                new OutboundHttpClient(new RestTemplate()),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0L, 1, 1L, 60_000L, true, true)),
                new ObjectMapper(),
                configService,
                tenantSchemaExecutionService
        );

        CiResolutionService.Resolution resolution = service.resolve(
                tenant,
                sysId,
                "host-01",
                "prod",
                CiResolutionService.OwnershipDetails.empty(),
                BusinessCriticality.HIGH,
                "servicenow"
        );

        assertEquals(tenant, resolution.ci().getTenant());
        assertEquals(tenant, resolution.ci().getAsset().getTenant());
        assertNotEquals(otherTenant.getId(), resolution.ci().getAsset().getTenant().getId());
        verify(ciRepository).findByTenant_IdAndSysIdIn(tenant.getId(), List.of(sysId));
        verify(assetRepository).findByTenant_IdAndIdentifierIn(tenant.getId(), List.of("ci:" + sysId));
        verify(ciRepository, never()).findBySysIdIn(List.of(sysId));
        verify(assetRepository, never()).findByIdentifierIn(List.of("ci:" + sysId));
    }

    @Test
    void prepareBatchContextUsesTenantScopedLookups() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Alpha");

        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        CiAliasRepository ciAliasRepository = mock(CiAliasRepository.class);
        ServiceNowCmdbConfigService configService = mock(ServiceNowCmdbConfigService.class);
        TenantSchemaExecutionService tenantSchemaExecutionService = mock(TenantSchemaExecutionService.class);
        doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(java.util.function.Supplier.class));

        when(ciRepository.findByTenant_IdAndSysIdIn(eq(tenant.getId()), argThat(ids -> ids != null && ids.contains("sys-1")))).thenReturn(List.of());
        when(assetRepository.findByTenant_IdAndIdentifierIn(eq(tenant.getId()), argThat(ids -> ids != null && ids.contains("ci:sys-1")))).thenReturn(List.of());
        when(ciAliasRepository.findByTenant_IdAndNormalizedAliasNameIn(eq(tenant.getId()), argThat(ids -> ids != null && ids.contains("host-01")))).thenReturn(List.of());

        CiResolutionService service = new CiResolutionService(
                ciRepository,
                ciAliasRepository,
                assetRepository,
                new OutboundHttpClient(new RestTemplate()),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0L, 1, 1L, 60_000L, true, true)),
                new ObjectMapper(),
                configService,
                tenantSchemaExecutionService
        );

        service.prepareBatchContext(
                tenant,
                "servicenow",
                List.of(new CiResolutionService.HostLookupInput("sys-1", "host-01"))
        );

        verify(ciRepository).findByTenant_IdAndSysIdIn(eq(tenant.getId()), argThat(ids -> ids != null && ids.contains("sys-1")));
        verify(assetRepository).findByTenant_IdAndIdentifierIn(eq(tenant.getId()), argThat(ids -> ids != null && ids.contains("ci:sys-1")));
        verify(ciAliasRepository).findByTenant_IdAndNormalizedAliasNameIn(eq(tenant.getId()), argThat(ids -> ids != null && ids.contains("host-01")));
        verify(ciRepository, never()).findBySysIdIn(any());
        verify(assetRepository, never()).findByIdentifierIn(any());
        verify(ciAliasRepository, never()).findByNormalizedAliasNameIn(any());
    }
}
