package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GcpDiscoveryClient;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.GcpInstanceRecord;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.InventoryResult;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.ListResult;
import com.prototype.vulnwatch.client.GcpTokenSource;
import com.prototype.vulnwatch.domain.GcpDiscoveryConfig;
import com.prototype.vulnwatch.domain.GcpDiscoveryTarget;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

class GcpDiscoverySyncServiceTest {

    private final GcpDiscoveryConfigRepository configs = mock(GcpDiscoveryConfigRepository.class);
    private final GcpDiscoveryTargetRepository targets = mock(GcpDiscoveryTargetRepository.class);
    private final GcpDiscoveryClient client = mock(GcpDiscoveryClient.class);
    private final GcpTokenSource tokens = mock(GcpTokenSource.class);
    private final GcpResourceIngestionService ingestion = mock(GcpResourceIngestionService.class);
    private final SyncRunRepository runs = mock(SyncRunRepository.class);
    private final TenantSchemaExecutionService tenantExecution = mock(TenantSchemaExecutionService.class);
    private final TransactionTemplate transactions = mock(TransactionTemplate.class);
    private final CredentialEncryptionService encryption =
            new CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    private GcpDiscoverySyncService service;
    private Tenant tenant;
    private GcpDiscoveryConfig config;
    private final SyncRun run = new SyncRun();
    private final UUID runId = UUID.randomUUID();

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        config = new GcpDiscoveryConfig();
        config.setId(UUID.randomUUID());
        config.setTenant(tenant);
        config.setServiceAccountEmail("scout-reader@acme-prod.iam.gserviceaccount.com");
        config.setCredentialSecret(encryption.encrypt(GcpDiscoveryConfigServiceTest.KEY));
        when(configs.findById(config.getId())).thenReturn(Optional.of(config));
        when(runs.findById(runId)).thenReturn(Optional.of(run));
        when(tokens.token(GcpDiscoveryConfigServiceTest.KEY)).thenReturn("tenant-token");
        when(tenantExecution.run(any(UUID.class), any(Supplier.class)))
                .thenAnswer(call -> ((Supplier<?>) call.getArgument(1)).get());
        doAnswer(call -> {
            ((Consumer<TransactionStatus>) call.getArgument(0)).accept(null);
            return null;
        }).when(transactions).executeWithoutResult(any());
        when(ingestion.ingestProject(any(), anyString(), any(), any(), any(), anySet(), any()))
                .thenReturn(new GcpResourceIngestionService.IngestionResult(1, 0, 1, 2, 0, 2, 0, 1));
        TenantQuotaService quota = mock(TenantQuotaService.class);
        ObjectMapper mapper = new ObjectMapper();
        GcpDiscoveryConfigService configService = new GcpDiscoveryConfigService(configs, targets, quota, encryption, mapper);
        GcpDiscoveryTargetService targetService = new GcpDiscoveryTargetService(targets, configs, configService, client, tokens, quota, mapper);
        service = new GcpDiscoverySyncService(configs, targets, configService, targetService, client, tokens, ingestion,
                runs, mapper, transactions, mock(WorkspaceService.class), mock(TenantService.class), tenantExecution,
                mock(IngestionJobService.class));
    }

    private GcpDiscoveryTarget target(String projectId) {
        GcpDiscoveryTarget target = new GcpDiscoveryTarget();
        target.setId(UUID.randomUUID());
        target.setTenant(tenant);
        target.setConfig(config);
        target.setProjectId(projectId);
        target.setResourceTypesJson("[\"COMPUTE_INSTANCE\"]");
        return target;
    }

    private static GcpInstanceRecord vm() {
        return new GcpInstanceRecord("good-project", "1", "vm", "us-central1-a", "e2", "RUNNING", null, null,
                Map.of(), Instant.now(), false);
    }

    @Test
    void oneFailingProjectDoesNotStopTheOthersAndTheRunCompletesWithErrors() {
        GcpDiscoveryTarget good = target("good-project");
        GcpDiscoveryTarget broken = target("broken-project");
        when(targets.findByConfigAndEnabledTrueOrderByProjectIdAsc(config)).thenReturn(List.of(broken, good));
        when(client.listInstances("tenant-token", "good-project")).thenReturn(new ListResult<>(List.of(vm()), Map.of(), true));
        when(client.listInstances("tenant-token", "broken-project"))
                .thenReturn(new ListResult<>(List.of(), Map.of("compute", "HTTP 403"), false));
        when(client.listInventories(eq("tenant-token"), anyString(), anyCollection()))
                .thenReturn(new InventoryResult(Map.of(), Map.of(), Map.of()));

        service.executeQueuedRun(tenant.getId(), config.getId(), runId, "manual", null);

        assertEquals("completed", run.getStatus());
        assertEquals(1, run.getRecordsFailed());
        assertTrue(run.getErrorMessage().contains("broken-project"));
        assertTrue(run.getMetadataJson().contains("completed_with_errors"));
        verify(ingestion).ingestProject(eq(tenant), eq("good-project"), any(), any(), any(),
                eq(Set.of(GcpResourceTypes.COMPUTE_INSTANCE)), any());
        verify(ingestion, never()).ingestProject(any(), eq("broken-project"), any(), any(), any(), anySet(), any());
    }

    @Test
    void anIncompleteListingIsIngestedButNotEligibleForStaleMarking() {
        GcpDiscoveryTarget partial = target("good-project");
        when(targets.findByConfigAndEnabledTrueOrderByProjectIdAsc(config)).thenReturn(List.of(partial));
        when(client.listInstances("tenant-token", "good-project"))
                .thenReturn(new ListResult<>(List.of(vm()), Map.of("zones/asia-east1-a", "unreachable"), false));
        when(client.listInventories(eq("tenant-token"), anyString(), anyCollection()))
                .thenReturn(new InventoryResult(Map.of(), Map.of(), Map.of()));

        service.executeQueuedRun(tenant.getId(), config.getId(), runId, "manual", null);

        verify(ingestion).ingestProject(eq(tenant), eq("good-project"), any(), any(), any(), eq(Set.of()), any());
        assertEquals("completed", run.getStatus());
    }

    @Test
    void aRunForAConnectorWhoseKeyWasRemovedFailsBeforeCallingGcp() {
        config.setCredentialSecret(null);

        service.executeQueuedRun(tenant.getId(), config.getId(), runId, "scheduled", null);

        assertEquals("failed", run.getStatus());
        verify(tokens, never()).token(any());
        verify(client, never()).listInstances(any(), any());
    }

    @Test
    void workQueuedForAnotherTenantIsRefused() {
        service.executeQueuedRun(UUID.randomUUID(), config.getId(), runId, "manual", null);

        assertEquals("failed", run.getStatus());
        verify(client, never()).searchResources(any(), any(), anyMap());
    }
}
