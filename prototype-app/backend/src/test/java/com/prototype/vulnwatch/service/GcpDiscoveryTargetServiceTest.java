package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GcpDiscoveryClient;
import com.prototype.vulnwatch.client.GcpTokenSource;
import com.prototype.vulnwatch.domain.GcpDiscoveryConfig;
import com.prototype.vulnwatch.domain.GcpDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GcpDiscoveryTargetRequest;
import com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class GcpDiscoveryTargetServiceTest {

    private final GcpDiscoveryTargetRepository targets = mock(GcpDiscoveryTargetRepository.class);
    private final GcpDiscoveryConfigRepository configs = mock(GcpDiscoveryConfigRepository.class);
    private final GcpDiscoveryClient client = mock(GcpDiscoveryClient.class);
    private final GcpTokenSource tokens = mock(GcpTokenSource.class);
    private final TenantQuotaService quota = mock(TenantQuotaService.class);
    private final CredentialEncryptionService encryption =
            new CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    private GcpDiscoveryTargetService service;
    private Tenant tenant;
    private GcpDiscoveryConfig config;

    @BeforeEach
    void setUp() {
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        config = new GcpDiscoveryConfig();
        config.setId(UUID.randomUUID());
        config.setTenant(tenant);
        config.setServiceAccountEmail("scout-reader@acme-prod.iam.gserviceaccount.com");
        config.setCredentialSecret(encryption.encrypt(GcpDiscoveryConfigServiceTest.KEY));
        when(configs.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "gcp")).thenReturn(Optional.of(config));
        when(targets.save(any(GcpDiscoveryTarget.class))).thenAnswer(call -> call.getArgument(0));
        when(tokens.token(GcpDiscoveryConfigServiceTest.KEY)).thenReturn("tenant-token");
        GcpDiscoveryConfigService configService =
                new GcpDiscoveryConfigService(configs, targets, quota, encryption, new ObjectMapper());
        service = new GcpDiscoveryTargetService(targets, configs, configService, client, tokens, quota, new ObjectMapper());
    }

    private GcpDiscoveryTarget target(List<String> types) {
        GcpDiscoveryTarget target = new GcpDiscoveryTarget();
        target.setId(UUID.randomUUID());
        target.setTenant(tenant);
        target.setConfig(config);
        target.setProjectId("acme-prod");
        target.setResourceTypesJson(types.isEmpty() ? "[]" : "[\"" + String.join("\",\"", types) + "\"]");
        when(targets.findByIdAndTenant_Id(target.getId(), tenant.getId())).thenReturn(Optional.of(target));
        return target;
    }

    @Test
    void createNormalizesTheProjectAndDefaultsToEverySupportedType() {
        var response = service.create(tenant, new GcpDiscoveryTargetRequest(" Acme-Prod ", "Production", null, null));

        assertEquals("acme-prod", response.projectId());
        assertEquals(GcpResourceTypes.all(), response.resourceTypes());
        verify(quota).assertCanCreateConnector(tenant, "gcp-target");
    }

    @Test
    void createRejectsInvalidProjectsUnknownTypesAndDuplicates() {
        assertEquals(400, assertThrows(ResponseStatusException.class,
                () -> service.create(tenant, new GcpDiscoveryTargetRequest("projects/other", null, null, null))).getStatusCode().value());
        assertEquals(400, assertThrows(ResponseStatusException.class,
                () -> service.create(tenant, new GcpDiscoveryTargetRequest("acme-prod", null, null, List.of("EVERYTHING")))).getStatusCode().value());
        when(targets.findByConfigAndProjectId(config, "acme-prod")).thenReturn(Optional.of(new GcpDiscoveryTarget()));
        assertEquals(409, assertThrows(ResponseStatusException.class,
                () -> service.create(tenant, new GcpDiscoveryTargetRequest("acme-prod", null, null, null))).getStatusCode().value());
    }

    @Test
    void aTargetFromAnotherTenantIsNotFound() {
        UUID foreign = UUID.randomUUID();
        when(targets.findByIdAndTenant_Id(foreign, tenant.getId())).thenReturn(Optional.empty());

        assertEquals(404, assertThrows(ResponseStatusException.class, () -> service.test(tenant, foreign)).getStatusCode().value());
    }

    @Test
    void reportsEachMissingRequiredPermissionAsAFailure() {
        GcpDiscoveryTarget target = target(List.of());
        when(client.testPermissions(eq("tenant-token"), eq("acme-prod"), anyCollection()))
                .thenReturn(Set.of("resourcemanager.projects.get", "osconfig.inventories.list"));

        var response = service.test(tenant, target.getId());

        assertEquals("FAILED", response.status());
        assertTrue(response.message().contains("compute.instances.list"));
        assertTrue(response.message().contains("cloudasset.assets.searchAllResources"));
        assertTrue(response.permissions().stream().anyMatch(c -> c.permission().equals("compute.instances.list") && !c.granted()));
        assertEquals("FAILED", target.getLastTestStatus());
    }

    @Test
    void missingOnlyThePackagePermissionIsAWarningNotAFailure() {
        GcpDiscoveryTarget target = target(List.of("COMPUTE_INSTANCE"));
        when(client.testPermissions(eq("tenant-token"), eq("acme-prod"), anyCollection()))
                .thenReturn(Set.of("resourcemanager.projects.get", "compute.instances.list"));

        var response = service.test(tenant, target.getId());

        assertEquals("SUCCESS_WITH_WARNINGS", response.status());
        assertTrue(response.message().contains("roles/osconfig.inventoryViewer"));
    }

    @Test
    void anUngrantedProjectExplainsWhichRolesToGrantToWhichAccount() {
        GcpDiscoveryTarget target = target(List.of("STORAGE_BUCKET"));
        when(client.testPermissions(eq("tenant-token"), eq("acme-prod"), anyCollection()))
                .thenThrow(new GcpDiscoveryClient.GcpApiException(403, "denied"));

        var response = service.test(tenant, target.getId());

        assertEquals("FAILED", response.status());
        assertTrue(response.message().contains(config.getServiceAccountEmail()));
        assertTrue(response.message().contains("roles/cloudasset.viewer"));
        assertFalse(response.message().contains("Scout"), "the customer grants their own account, not a Scout one");
    }

    @Test
    void aConnectorWithoutAKeyFailsBeforeAnyTokenIsRequested() {
        config.setCredentialSecret(null);
        GcpDiscoveryTarget target = target(List.of());

        var response = service.test(tenant, target.getId());

        assertEquals("FAILED", response.status());
        verify(tokens, never()).token(any());
        assertFalse(response.permissions().iterator().hasNext());
    }
}
