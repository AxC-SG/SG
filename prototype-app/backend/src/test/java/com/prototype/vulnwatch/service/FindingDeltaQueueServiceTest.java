package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.FindingDeltaQueueEntry;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class FindingDeltaQueueServiceTest {

    @Mock
    private FindingDeltaQueueEntryRepository repository;

    @Mock
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Mock
    private FindingRecomputeService findingRecomputeService;

    @Mock
    private DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService;

    @Mock
    private TenantService tenantService;

    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    private FindingDeltaQueueService service;

    @BeforeEach
    void setUp() {
        service = new FindingDeltaQueueService(
                repository,
                componentVulnerabilityStateRepository,
                findingRecomputeService,
                dashboardNoiseReductionProjectionService,
                tenantService,
                tenantSchemaExecutionService
        );
        lenient().when(tenantService.resolveTenantUuid(any())).thenAnswer(invocation -> {
            Tenant tenant = new Tenant();
            tenant.setId((UUID) invocation.getArgument(0));
            tenant.setSchemaName("tenant_test");
            return tenant;
        });
    }

    private static Tenant tenantWithSchema(UUID id) {
        Tenant tenant = new Tenant();
        tenant.setId(id);
        tenant.setSchemaName("tenant_" + id.toString().substring(0, 8));
        return tenant;
    }

    // ----------------------------------------------------------------
    // enqueueSoftwareDeltas
    // ----------------------------------------------------------------

    @Test
    void enqueueSoftwareDeltas_nullTenant_returnsZeroAndNoOp() {
        int n = service.enqueueSoftwareDeltas(null, List.of(UUID.randomUUID()), "tag");
        assertEquals(0, n);
        verifyNoInteractions(repository);
    }

    @Test
    void enqueueSoftwareDeltas_emptyCollection_returnsZero() {
        int n = service.enqueueSoftwareDeltas(UUID.randomUUID(), List.of(), "tag");
        assertEquals(0, n);
        verifyNoInteractions(repository);
    }

    @Test
    void enqueueSoftwareDeltas_nullCollection_returnsZero() {
        assertEquals(0, service.enqueueSoftwareDeltas(UUID.randomUUID(), null, "tag"));
    }

    @Test
    void enqueueSoftwareDeltas_buildsExpectedDedupeKey_andLowercasesTag() {
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000001");
        UUID component = UUID.fromString("00000000-0000-0000-0000-0000000000aa");
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        int queued = service.enqueueSoftwareDeltas(tenant, List.of(component), "  My-Source  ");

        assertEquals(1, queued);
        verify(repository).insertIfNotDuplicate(
                eq("SOFTWARE_DELTA"),
                eq(tenant),
                eq(component),
                eq(null),
                eq(null),
                eq("my-source"),
                eq("software:" + tenant + ":" + component + ":my-source")
        );
    }

    @Test
    void enqueueSoftwareDeltas_blankTagNormalisesToDefault() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.enqueueSoftwareDeltas(tenant, List.of(component), "   ");

        verify(repository).insertIfNotDuplicate(
                any(), any(), any(), any(), any(), eq("default"), eq("software:" + tenant + ":" + component + ":default"));
    }

    @Test
    void enqueueSoftwareDeltas_nullTagNormalisesToDefault() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.enqueueSoftwareDeltas(tenant, List.of(component), null);

        verify(repository).insertIfNotDuplicate(
                any(), any(), any(), any(), any(), eq("default"), any());
    }

    @Test
    void enqueueSoftwareDeltas_dedupesAndSortsComponentIds() {
        UUID tenant = UUID.randomUUID();
        UUID c1 = UUID.fromString("00000000-0000-0000-0000-000000000001");
        UUID c2 = UUID.fromString("00000000-0000-0000-0000-000000000002");
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        // Pass duplicate + null + reverse order; expect two unique inserts in sorted order
        int queued = service.enqueueSoftwareDeltas(tenant, Arrays.asList(c2, c1, c2, null), "tag");

        assertEquals(2, queued);
        ArgumentCaptor<UUID> componentCaptor = ArgumentCaptor.forClass(UUID.class);
        verify(repository, times(2)).insertIfNotDuplicate(
                any(), any(), componentCaptor.capture(), any(), any(), any(), any());
        assertEquals(List.of(c1, c2), componentCaptor.getAllValues());
    }

    @Test
    void enqueueSoftwareDeltas_repositoryReturnsZeroWhenDuplicate() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(0);

        assertEquals(0, service.enqueueSoftwareDeltas(tenant, List.of(component), "tag"));
    }

    // ----------------------------------------------------------------
    // enqueueCveDeltas / CveMetadata / Vex / Lifecycle / Noise
    // ----------------------------------------------------------------

    @Test
    void enqueueCveDeltas_nullCollection_returnsZero() {
        assertEquals(0, service.enqueueCveDeltas(null, "tag"));
    }

    @Test
    void enqueueCveDeltas_emptyCollection_returnsZero() {
        assertEquals(0, service.enqueueCveDeltas(List.of(), "tag"));
    }

    @Test
    void enqueueCveDeltas_buildsCveKeyAndType() {
        UUID v = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.enqueueCveDeltas(List.of(v), "Source");

        verify(repository).insertIfNotDuplicate(
                eq("CVE_DELTA"),
                eq(null),
                eq(null),
                eq(v),
                eq(null),
                eq("source"),
                eq("cve:" + v + ":source")
        );
    }

    @Test
    void enqueueCveMetadataDeltas_emitsCveMetadataType() {
        UUID v = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.enqueueCveMetadataDeltas(List.of(v), null);

        verify(repository).insertIfNotDuplicate(
                eq("CVE_METADATA_DELTA"), any(), any(), eq(v), any(), eq("default"),
                eq("cve-metadata:" + v + ":default"));
    }

    @Test
    void enqueueCveMetadataDeltas_nullCollection_returnsZero() {
        assertEquals(0, service.enqueueCveMetadataDeltas(null, "x"));
    }

    @Test
    void enqueueVexDeltas_buildsKeyWithSourceKeyAndTag() {
        UUID v = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.enqueueVexDeltas(List.of(v), "RedHat", "VEX-2024");

        verify(repository).insertIfNotDuplicate(
                eq("VEX_DELTA"),
                eq(null),
                eq(null),
                eq(v),
                eq("redhat"),
                eq("vex-2024"),
                eq("vex:" + v + ":redhat:vex-2024")
        );
    }

    @Test
    void enqueueVexDeltas_emptyCollection_returnsZero() {
        assertEquals(0, service.enqueueVexDeltas(List.of(), "k", "t"));
    }

    @Test
    void processPendingDeltasSkipsWhenRuntimeRoleIsApi() {
        service.setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy.forRole("api"));

        service.processPendingDeltas();

        verifyNoInteractions(tenantService);
        verifyNoInteractions(tenantSchemaExecutionService);
    }

    @Test
    void enqueueLifecycleDeltas_buildsLifecyclePayload() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.enqueueLifecycleDeltas(tenant, List.of(component), "EOL-SWEEP");

        verify(repository).insertIfNotDuplicate(
                eq("LIFECYCLE_DELTA"), eq(tenant), eq(component), eq(null), eq(null),
                eq("eol-sweep"), eq("lifecycle:" + tenant + ":" + component + ":eol-sweep"));
    }

    @Test
    void enqueueLifecycleDeltas_nullTenant_returnsZero() {
        assertEquals(0, service.enqueueLifecycleDeltas(null, List.of(UUID.randomUUID()), "t"));
        verifyNoInteractions(repository);
    }

    @Test
    void enqueueNoiseReductionRefresh_nullTenant_returnsZero() {
        assertEquals(0, service.enqueueNoiseReductionRefresh(null, "x"));
        verifyNoInteractions(repository);
    }

    @Test
    void enqueueNoiseReductionRefresh_buildsTenantScopedKey() {
        UUID tenant = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        int n = service.enqueueNoiseReductionRefresh(tenant, "DASH");

        assertEquals(1, n);
        verify(repository).insertIfNotDuplicate(
                eq("NOISE_REDUCTION_REFRESH"), eq(tenant), eq(null), eq(null),
                eq(null), eq("dash"), eq("noise:" + tenant));
    }

    // ----------------------------------------------------------------
    // queueDepth
    // ----------------------------------------------------------------

    @Test
    void queueDepth_delegatesToRepository() {
        when(repository.countPending()).thenReturn(42L);
        assertEquals(42L, service.queueDepth());
    }

    // ----------------------------------------------------------------
    // claimBatch / processPendingDeltas
    // ----------------------------------------------------------------

    @Test
    void claimBatch_emptyQueue_returnsEmptyAndDoesNotSave() {
        when(repository.pollPending(anyInt())).thenReturn(List.of());

        List<FindingDeltaQueueEntry> result = service.claimBatch();

        assertTrue(result.isEmpty());
        verify(repository, never()).saveAll(anyCollection());
    }

    @Test
    void claimBatch_marksProcessingAndIncrementsAttempts() {
        FindingDeltaQueueEntry e1 = newEntry(1L, FindingDeltaQueueService.SOFTWARE_DELTA);
        e1.setAttemptCount(0);
        FindingDeltaQueueEntry e2 = newEntry(2L, FindingDeltaQueueService.CVE_DELTA);
        e2.setAttemptCount(2);
        when(repository.pollPending(anyInt())).thenReturn(new ArrayList<>(List.of(e1, e2)));

        service.claimBatch();

        assertEquals("PROCESSING", e1.getStatus());
        assertEquals("PROCESSING", e2.getStatus());
        assertEquals(1, e1.getAttemptCount());
        assertEquals(3, e2.getAttemptCount());
        assertTrue(e1.getProcessingStartedAt() != null);
        verify(repository).saveAll(anyCollection());
    }

    @Test
    void processPendingDeltas_noClaimedEntries_isNoOp() {
        Tenant tenant = tenantWithSchema(UUID.randomUUID());
        when(tenantService.listActiveTenants()).thenReturn(List.of(tenant));
        when(tenantSchemaExecutionService.run(eq(tenant), any(java.util.function.Supplier.class)))
                .thenAnswer(inv -> ((java.util.function.Supplier<?>) inv.getArgument(1)).get());
        when(repository.pollPending(anyInt())).thenReturn(List.of());

        service.processPendingDeltas();

        verifyNoInteractions(findingRecomputeService);
    }

    @Test
    void processPendingDeltas_drainsEveryTenantNotJustDefault() {
        // Regression: the poller used to drain only the ambient (default) schema, leaving non-default
        // tenants' deltas PENDING forever. It must claim within each tenant's schema context.
        Tenant tenantA = tenantWithSchema(UUID.randomUUID());
        Tenant tenantB = tenantWithSchema(UUID.randomUUID());
        when(tenantService.listActiveTenants()).thenReturn(List.of(tenantA, tenantB));
        when(tenantSchemaExecutionService.run(any(Tenant.class), any(java.util.function.Supplier.class)))
                .thenAnswer(inv -> ((java.util.function.Supplier<?>) inv.getArgument(1)).get());
        when(repository.pollPending(anyInt())).thenReturn(List.of());

        service.processPendingDeltas();

        verify(tenantSchemaExecutionService).run(eq(tenantA), any(java.util.function.Supplier.class));
        verify(tenantSchemaExecutionService).run(eq(tenantB), any(java.util.function.Supplier.class));
    }

    @Test
    void processPendingDeltasDrainsMultipleBatchesPerTenantWithinConfiguredPollBudget() {
        Tenant tenant = tenantWithSchema(UUID.randomUUID());
        UUID componentA = UUID.randomUUID();
        UUID componentB = UUID.randomUUID();
        FindingDeltaQueueEntry batchOneEntry = entry(1L, FindingDeltaQueueService.SOFTWARE_DELTA, tenant.getId(), componentA, null, null);
        FindingDeltaQueueEntry batchTwoEntry = entry(2L, FindingDeltaQueueService.SOFTWARE_DELTA, tenant.getId(), componentB, null, null);
        ReflectionTestUtils.setField(service, "maxBatchesPerTenantPerPoll", 3);

        when(tenantService.listActiveTenants()).thenReturn(List.of(tenant));
        when(tenantSchemaExecutionService.run(eq(tenant), any(java.util.function.Supplier.class)))
                .thenAnswer(inv -> ((java.util.function.Supplier<?>) inv.getArgument(1)).get());
        when(repository.pollPending(anyInt())).thenReturn(
                new ArrayList<>(List.of(batchOneEntry)),
                new ArrayList<>(List.of(batchTwoEntry)),
                List.of()
        );
        when(findingRecomputeService.recomputeOnSoftwareDeltaBatch(eq(tenant.getId()), eq(List.of(componentA)))).thenReturn(1);
        when(findingRecomputeService.recomputeOnSoftwareDeltaBatch(eq(tenant.getId()), eq(List.of(componentB)))).thenReturn(1);
        when(repository.findById(1L)).thenReturn(Optional.of(batchOneEntry));
        when(repository.findById(2L)).thenReturn(Optional.of(batchTwoEntry));
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.processPendingDeltas();

        verify(repository, times(3)).pollPending(anyInt());
        verify(findingRecomputeService).recomputeOnSoftwareDeltaBatch(eq(tenant.getId()), eq(List.of(componentA)));
        verify(findingRecomputeService).recomputeOnSoftwareDeltaBatch(eq(tenant.getId()), eq(List.of(componentB)));
    }

    @Test
    void recoverInterruptedProcessingEntriesRequeuesStaleWorkAndFailsExhaustedEntries() {
        Tenant tenant = tenantWithSchema(UUID.randomUUID());
        FindingDeltaQueueEntry retryable = newEntry(1L, FindingDeltaQueueService.SOFTWARE_DELTA);
        retryable.setStatus("PROCESSING");
        retryable.setAttemptCount(1);
        retryable.setMaxAttempts(3);
        retryable.setProcessingStartedAt(Instant.now().minusSeconds(3600));

        FindingDeltaQueueEntry exhausted = newEntry(2L, FindingDeltaQueueService.CVE_DELTA);
        exhausted.setStatus("PROCESSING");
        exhausted.setAttemptCount(3);
        exhausted.setMaxAttempts(3);
        exhausted.setProcessingStartedAt(Instant.now().minusSeconds(3600));

        when(tenantService.listActiveTenants()).thenReturn(List.of(tenant));
        when(tenantSchemaExecutionService.run(eq(tenant), any(java.util.function.Supplier.class)))
                .thenAnswer(inv -> ((java.util.function.Supplier<?>) inv.getArgument(1)).get());
        when(repository.findStaleProcessingEntries(any())).thenReturn(List.of(retryable, exhausted));

        service.recoverInterruptedProcessingEntries();

        assertEquals("PENDING", retryable.getStatus());
        assertEquals("FAILED", exhausted.getStatus());
        assertTrue(retryable.getProcessingStartedAt() == null);
        assertTrue(exhausted.getProcessingStartedAt() == null);
        assertTrue(retryable.getVisibleAfter() != null);
        assertTrue(exhausted.getCompletedAt() != null);
        verify(repository).saveAll(anyCollection());
    }

    @Test
    void recoverStaleProcessingEntriesOnScheduleDoesNotThrowWhenListTenantsFails() {
        when(tenantService.listActiveTenants()).thenThrow(new IllegalStateException("db unavailable"));

        assertDoesNotThrow(() -> service.recoverStaleProcessingEntriesOnSchedule());
    }

    @Test
    void recoverInterruptedProcessingEntriesSkipsWhenRuntimeRoleIsApi() {
        service.setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy.forRole("api"));

        service.recoverInterruptedProcessingEntries();

        verifyNoInteractions(tenantService);
        verify(repository, never()).saveAll(anyCollection());
    }

    // ----------------------------------------------------------------
    // processClaimedBatch — dispatch + per-type processing
    // ----------------------------------------------------------------

    @Test
    void processClaimedBatch_softwareDelta_invokesBatchRecomputeAndEnqueuesNoise() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.SOFTWARE_DELTA, tenant, component, null, null);
        when(findingRecomputeService.recomputeOnSoftwareDeltaBatch(eq(tenant), any())).thenReturn(7);
        when(repository.findById(any())).thenReturn(Optional.of(e));
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.processClaimedBatch(List.of(e));

        verify(findingRecomputeService).recomputeOnSoftwareDeltaBatch(eq(tenant), eq(List.of(component)));
        // Noise reduction refresh enqueued after software delta
        verify(repository).insertIfNotDuplicate(
                eq("NOISE_REDUCTION_REFRESH"), eq(tenant), any(), any(), any(), eq("software-delta"), any());
        assertEquals("DONE", e.getStatus());
    }

    @Test
    void processClaimedBatch_softwareDelta_missingTenantRowsAreMarkedDoneWithoutRecompute() {
        FindingDeltaQueueEntry orphan = entry(1L, FindingDeltaQueueService.SOFTWARE_DELTA, null, null, null, null);
        when(repository.findById(1L)).thenReturn(Optional.of(orphan));

        service.processClaimedBatch(List.of(orphan));

        verify(findingRecomputeService, never()).recomputeOnSoftwareDeltaBatch(any(), any());
        assertEquals("DONE", orphan.getStatus());
    }

    @Test
    void processClaimedBatch_lifecycleDelta_callsRefreshLifecycleNotSoftwareRecompute() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.LIFECYCLE_DELTA, tenant, component, null, null);
        when(findingRecomputeService.refreshLifecycleForComponents(eq(tenant), any())).thenReturn(2);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        verify(findingRecomputeService).refreshLifecycleForComponents(eq(tenant), eq(List.of(component)));
        verify(findingRecomputeService, never()).recomputeOnSoftwareDeltaBatch(any(), any());
        // Lifecycle does NOT enqueue noise reduction
        verify(repository, never()).insertIfNotDuplicate(
                eq("NOISE_REDUCTION_REFRESH"), any(), any(), any(), any(), any(), any());
    }

    @Test
    void processClaimedBatch_softwareDelta_groupsEntriesByTenantSeparately() {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        UUID compA = UUID.randomUUID();
        UUID compB = UUID.randomUUID();
        FindingDeltaQueueEntry a = entry(1L, FindingDeltaQueueService.SOFTWARE_DELTA, tenantA, compA, null, null);
        FindingDeltaQueueEntry b = entry(2L, FindingDeltaQueueService.SOFTWARE_DELTA, tenantB, compB, null, null);
        when(findingRecomputeService.recomputeOnSoftwareDeltaBatch(any(), any())).thenReturn(0);
        when(repository.findById(any())).thenReturn(Optional.of(a), Optional.of(b));

        service.processClaimedBatch(List.of(a, b));

        verify(findingRecomputeService).recomputeOnSoftwareDeltaBatch(eq(tenantA), eq(List.of(compA)));
        verify(findingRecomputeService).recomputeOnSoftwareDeltaBatch(eq(tenantB), eq(List.of(compB)));
    }

    @Test
    void processClaimedBatch_cveDelta_invokesCveBatchAndEnqueuesNoiseForAffectedTenants() {
        UUID v = UUID.randomUUID();
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.CVE_DELTA, null, null, v, null);
        when(findingRecomputeService.recomputeOnCveDeltaBatch(any())).thenReturn(3);
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(any()))
                .thenReturn(Set.of(tenantA, tenantB));
        when(repository.findById(any())).thenReturn(Optional.of(e));
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        service.processClaimedBatch(List.of(e));

        verify(findingRecomputeService).recomputeOnCveDeltaBatch(eq(List.of(v)));
        // One noise refresh insert per affected tenant
        verify(repository, times(2)).insertIfNotDuplicate(
                eq("NOISE_REDUCTION_REFRESH"), any(), any(), any(), any(), eq("vulnerability-delta"), any());
    }

    @Test
    void processClaimedBatch_cveMetadataDelta_callsRefreshMetadata() {
        UUID v = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.CVE_METADATA_DELTA, null, null, v, null);
        when(findingRecomputeService.refreshMetadataForVulnerabilityBatch(any())).thenReturn(1);
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(any()))
                .thenReturn(Set.of());
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        verify(findingRecomputeService).refreshMetadataForVulnerabilityBatch(eq(List.of(v)));
        verify(findingRecomputeService, never()).recomputeOnCveDeltaBatch(any());
    }

    @Test
    void processClaimedBatch_cveDelta_entriesWithNullVulnerabilityIdAreMarkedDoneSeparately() {
        FindingDeltaQueueEntry orphan = entry(1L, FindingDeltaQueueService.CVE_DELTA, null, null, null, null);
        when(repository.findById(1L)).thenReturn(Optional.of(orphan));

        service.processClaimedBatch(List.of(orphan));

        verify(findingRecomputeService, never()).recomputeOnCveDeltaBatch(any());
        assertEquals("DONE", orphan.getStatus());
    }

    @Test
    void processClaimedBatch_vexDelta_groupsBySourceKeyAndCallsApplyVexBatch() {
        UUID v1 = UUID.randomUUID();
        UUID v2 = UUID.randomUUID();
        FindingDeltaQueueEntry redhat = entry(1L, FindingDeltaQueueService.VEX_DELTA, null, null, v1, "redhat");
        FindingDeltaQueueEntry msft = entry(2L, FindingDeltaQueueService.VEX_DELTA, null, null, v2, "msft");
        when(findingRecomputeService.applyVexDeltaBatch(any(), any())).thenReturn(0);
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(any()))
                .thenReturn(Set.of());
        when(repository.findById(any())).thenReturn(Optional.of(redhat), Optional.of(msft));

        service.processClaimedBatch(List.of(redhat, msft));

        verify(findingRecomputeService).applyVexDeltaBatch(eq(List.of(v1)), eq("redhat"));
        verify(findingRecomputeService).applyVexDeltaBatch(eq(List.of(v2)), eq("msft"));
    }

    @Test
    void processClaimedBatch_noiseReductionRefresh_callsProjectionRefreshPerTenant() {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        FindingDeltaQueueEntry a = entry(1L, FindingDeltaQueueService.NOISE_REDUCTION_REFRESH, tenantA, null, null, null);
        FindingDeltaQueueEntry b = entry(2L, FindingDeltaQueueService.NOISE_REDUCTION_REFRESH, tenantB, null, null, null);
        when(dashboardNoiseReductionProjectionService.refreshTenant(any())).thenReturn(0);
        when(repository.findById(any())).thenReturn(Optional.of(a), Optional.of(b));

        service.processClaimedBatch(List.of(a, b));

        verify(dashboardNoiseReductionProjectionService).refreshTenant(tenantA);
        verify(dashboardNoiseReductionProjectionService).refreshTenant(tenantB);
    }

    @Test
    void processClaimedBatch_unknownEventType_fallsBackToIndividualProcessing() {
        FindingDeltaQueueEntry e = entry(1L, "MYSTERY_EVENT", null, null, null, null);
        e.setMaxAttempts(3);
        e.setAttemptCount(1);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        // Default switch branch logs "Unknown delta event type" and yields 0; entry is marked DONE
        assertEquals("DONE", e.getStatus());
        verifyNoInteractions(findingRecomputeService);
    }

    // ----------------------------------------------------------------
    // Failure paths — markFailedOrRetry exponential backoff
    // ----------------------------------------------------------------

    @Test
    void processClaimedBatch_softwareDeltaFails_marksEntryForRetryWhenUnderMaxAttempts() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.SOFTWARE_DELTA, tenant, component, null, null);
        e.setAttemptCount(1);
        e.setMaxAttempts(3);
        when(findingRecomputeService.recomputeOnSoftwareDeltaBatch(any(), any()))
                .thenThrow(new RuntimeException("db down"));
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        assertEquals("PENDING", e.getStatus());
        assertEquals("db down", e.getErrorMessage());
        // Backoff = 60 * 2^(1-1) = 60 s
        long backoff = e.getVisibleAfter().getEpochSecond() - Instant.now().getEpochSecond();
        assertTrue(backoff >= 55 && backoff <= 65, "expected ~60s backoff, got " + backoff);
    }

    @Test
    void processClaimedBatch_softwareDeltaFails_marksFailedAtMaxAttempts() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.SOFTWARE_DELTA, tenant, component, null, null);
        e.setAttemptCount(3);
        e.setMaxAttempts(3);
        when(findingRecomputeService.recomputeOnSoftwareDeltaBatch(any(), any()))
                .thenThrow(new RuntimeException("permanent"));
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        assertEquals("FAILED", e.getStatus());
        assertEquals("permanent", e.getErrorMessage());
    }

    @Test
    void processClaimedBatch_cveDeltaFails_marksRetry() {
        UUID v = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.CVE_DELTA, null, null, v, null);
        e.setAttemptCount(2);
        e.setMaxAttempts(3);
        when(findingRecomputeService.recomputeOnCveDeltaBatch(any()))
                .thenThrow(new RuntimeException("nope"));
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        assertEquals("PENDING", e.getStatus());
        // Backoff = 60 * 2^(2-1) = 120 s
        long backoff = e.getVisibleAfter().getEpochSecond() - Instant.now().getEpochSecond();
        assertTrue(backoff >= 115 && backoff <= 125, "expected ~120s backoff, got " + backoff);
    }

    @Test
    void processClaimedBatch_vexDeltaFails_marksRetry() {
        UUID v = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.VEX_DELTA, null, null, v, "redhat");
        e.setAttemptCount(1);
        e.setMaxAttempts(3);
        when(findingRecomputeService.applyVexDeltaBatch(any(), any()))
                .thenThrow(new RuntimeException("vex error"));
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        assertEquals("PENDING", e.getStatus());
    }

    @Test
    void processClaimedBatch_noiseRefreshFails_marksRetry() {
        UUID tenant = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.NOISE_REDUCTION_REFRESH, tenant, null, null, null);
        e.setAttemptCount(1);
        e.setMaxAttempts(3);
        when(dashboardNoiseReductionProjectionService.refreshTenant(any()))
                .thenThrow(new RuntimeException("dash error"));
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        assertEquals("PENDING", e.getStatus());
    }

    // ----------------------------------------------------------------
    // processEntryIndividually — single-entry switch
    // ----------------------------------------------------------------

    @Test
    void processEntryIndividually_softwareDelta_callsRecomputeOnSoftwareDelta() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.SOFTWARE_DELTA, tenant, component, null, null);
        when(findingRecomputeService.recomputeOnSoftwareDelta(tenant, component)).thenReturn(1);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processEntryIndividually(e);

        verify(findingRecomputeService).recomputeOnSoftwareDelta(tenant, component);
        assertEquals("DONE", e.getStatus());
    }

    @Test
    void processEntryIndividually_cveDelta_callsRecomputeOnCveDelta() {
        UUID v = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.CVE_DELTA, null, null, v, null);
        when(findingRecomputeService.recomputeOnCveDelta(v)).thenReturn(2);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processEntryIndividually(e);

        verify(findingRecomputeService).recomputeOnCveDelta(v);
    }

    @Test
    void processEntryIndividually_lifecycleDelta_callsRefreshLifecycle() {
        UUID tenant = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.LIFECYCLE_DELTA, tenant, component, null, null);
        when(findingRecomputeService.refreshLifecycleForComponents(eq(tenant), any())).thenReturn(0);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processEntryIndividually(e);

        verify(findingRecomputeService).refreshLifecycleForComponents(eq(tenant), eq(List.of(component)));
    }

    @Test
    void processEntryIndividually_lifecycleDeltaWithNullComponent_passesEmptyList() {
        UUID tenant = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.LIFECYCLE_DELTA, tenant, null, null, null);
        when(findingRecomputeService.refreshLifecycleForComponents(eq(tenant), any())).thenReturn(0);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processEntryIndividually(e);

        verify(findingRecomputeService).refreshLifecycleForComponents(eq(tenant), eq(Collections.emptyList()));
    }

    @Test
    void processEntryIndividually_vexDelta_callsApplyVexDeltaForVulnerability() {
        UUID v = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.VEX_DELTA, null, null, v, "redhat");
        when(findingRecomputeService.applyVexDeltaForVulnerability(v, "redhat")).thenReturn(1);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processEntryIndividually(e);

        verify(findingRecomputeService).applyVexDeltaForVulnerability(v, "redhat");
    }

    @Test
    void processEntryIndividually_noiseRefresh_callsRefreshTenant() {
        UUID tenant = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.NOISE_REDUCTION_REFRESH, tenant, null, null, null);
        when(dashboardNoiseReductionProjectionService.refreshTenant(tenant)).thenReturn(0);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processEntryIndividually(e);

        verify(dashboardNoiseReductionProjectionService).refreshTenant(tenant);
    }

    @Test
    void processEntryIndividually_unknownEventType_yieldsZeroAndMarksDone() {
        FindingDeltaQueueEntry e = entry(1L, "MADE_UP_TYPE", null, null, null, null);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processEntryIndividually(e);

        assertEquals("DONE", e.getStatus());
        verifyNoInteractions(findingRecomputeService);
    }

    @Test
    void processEntryIndividually_thrownException_marksRetry() {
        UUID v = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.CVE_DELTA, null, null, v, null);
        e.setAttemptCount(1);
        e.setMaxAttempts(3);
        when(findingRecomputeService.recomputeOnCveDelta(v)).thenThrow(new RuntimeException("boom"));
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processEntryIndividually(e);

        assertEquals("PENDING", e.getStatus());
        assertEquals("boom", e.getErrorMessage());
    }

    // ----------------------------------------------------------------
    // markDone / markFailedOrRetry direct invocations
    // ----------------------------------------------------------------

    @Test
    void markDone_setsStatusAndCompletedAt() {
        FindingDeltaQueueEntry e = newEntry(1L, FindingDeltaQueueService.SOFTWARE_DELTA);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.markDone(1L, 5);

        assertEquals("DONE", e.getStatus());
        assertTrue(e.getCompletedAt() != null);
    }

    @Test
    void markDone_missingEntry_isNoOp() {
        when(repository.findById(99L)).thenReturn(Optional.empty());
        service.markDone(99L, 0); // must not throw
        verify(repository, never()).save(any());
    }

    @Test
    void markFailedOrRetry_belowMaxAttempts_setsPendingWithExponentialBackoff() {
        FindingDeltaQueueEntry e = newEntry(1L, FindingDeltaQueueService.CVE_DELTA);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.markFailedOrRetry(1L, 3, 5, "retry me");

        assertEquals("PENDING", e.getStatus());
        // Backoff = 60 * 2^(3-1) = 240 s
        long backoff = e.getVisibleAfter().getEpochSecond() - Instant.now().getEpochSecond();
        assertTrue(backoff >= 235 && backoff <= 245, "expected ~240s backoff, got " + backoff);
        assertEquals("retry me", e.getErrorMessage());
    }

    @Test
    void markFailedOrRetry_atMaxAttempts_setsFailed() {
        FindingDeltaQueueEntry e = newEntry(1L, FindingDeltaQueueService.CVE_DELTA);
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.markFailedOrRetry(1L, 3, 3, "final");

        assertEquals("FAILED", e.getStatus());
        assertEquals("final", e.getErrorMessage());
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    // ----------------------------------------------------------------
    // CBOM_DELTA producer + consumer
    // ----------------------------------------------------------------

    @Test
    void enqueueCbomDeltas_coalescesAcrossProducersWithTagFreeDedupeKey() {
        UUID tenant = UUID.randomUUID();
        UUID finding = UUID.randomUUID();
        when(repository.insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any())).thenReturn(1);

        int queued = service.enqueueCbomDeltas(tenant, List.of(finding, finding), "CBOM-Ingest");

        assertEquals(1, queued);
        verify(repository).insertIfNotDuplicate(eq("CBOM_DELTA"), eq(tenant), eq(finding), eq(null), eq(null),
                eq("cbom-ingest"), eq("cbom:" + tenant + ":" + finding));
    }

    @Test
    void enqueueCbomDeltas_nullTenantOrEmpty_isNoOp() {
        assertEquals(0, service.enqueueCbomDeltas(null, List.of(UUID.randomUUID()), "x"));
        assertEquals(0, service.enqueueCbomDeltas(UUID.randomUUID(), List.of(), "x"));
        verify(repository, never()).insertIfNotDuplicate(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void processClaimedBatch_cbomDelta_mirrorsOnlyReferencedFindingsPerTenant() {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        UUID f1 = UUID.randomUUID(), f2 = UUID.randomUUID(), f3 = UUID.randomUUID();
        FindingDeltaQueueEntry e1 = entry(1L, FindingDeltaQueueService.CBOM_DELTA, tenantA, f1, null, null);
        FindingDeltaQueueEntry e2 = entry(2L, FindingDeltaQueueService.CBOM_DELTA, tenantA, f2, null, null);
        FindingDeltaQueueEntry e3 = entry(3L, FindingDeltaQueueService.CBOM_DELTA, tenantB, f3, null, null);
        FindingDeltaQueueService.CbomDeltaHandler handler = org.mockito.Mockito.mock(FindingDeltaQueueService.CbomDeltaHandler.class);
        when(handler.applyCbomDeltas(any(), any())).thenReturn(1);
        service.setCbomDeltaHandler(providerOf(handler));
        when(repository.findById(any())).thenAnswer(inv -> Optional.of(
                List.of(e1, e2, e3).stream().filter(e -> e.getId().equals(inv.getArgument(0))).findFirst().orElseThrow()));

        service.processClaimedBatch(List.of(e1, e2, e3));

        verify(handler).applyCbomDeltas(tenantA, List.of(f1, f2));
        verify(handler).applyCbomDeltas(tenantB, List.of(f3));
        assertEquals("DONE", e1.getStatus());
        assertEquals("DONE", e3.getStatus());
        // No recompute or noise-refresh side effects for crypto mirror deltas.
        verify(findingRecomputeService, never()).recomputeOnSoftwareDeltaBatch(any(), any());
    }

    @Test
    void processClaimedBatch_cbomDeltaHandlerFailure_schedulesRetry() {
        UUID tenant = UUID.randomUUID();
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.CBOM_DELTA, tenant, UUID.randomUUID(), null, null);
        e.setAttemptCount(1);
        FindingDeltaQueueService.CbomDeltaHandler handler = org.mockito.Mockito.mock(FindingDeltaQueueService.CbomDeltaHandler.class);
        when(handler.applyCbomDeltas(any(), any())).thenThrow(new IllegalStateException("mirror down"));
        service.setCbomDeltaHandler(providerOf(handler));
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        assertEquals("PENDING", e.getStatus());
        assertEquals("mirror down", e.getErrorMessage());
    }

    @Test
    void processClaimedBatch_cbomDeltaWithoutHandler_isRetriedNotAcknowledged() {
        FindingDeltaQueueEntry e = entry(1L, FindingDeltaQueueService.CBOM_DELTA, UUID.randomUUID(), UUID.randomUUID(), null, null);
        e.setAttemptCount(1);
        service.setCbomDeltaHandler(providerOf(null));
        when(repository.findById(1L)).thenReturn(Optional.of(e));

        service.processClaimedBatch(List.of(e));

        assertEquals("PENDING", e.getStatus());
    }

    private static org.springframework.beans.factory.ObjectProvider<FindingDeltaQueueService.CbomDeltaHandler> providerOf(
            FindingDeltaQueueService.CbomDeltaHandler handler) {
        return new org.springframework.beans.factory.ObjectProvider<>() {
            @Override public FindingDeltaQueueService.CbomDeltaHandler getObject() { return handler; }
            @Override public FindingDeltaQueueService.CbomDeltaHandler getObject(Object... args) { return handler; }
            @Override public FindingDeltaQueueService.CbomDeltaHandler getIfAvailable() { return handler; }
            @Override public FindingDeltaQueueService.CbomDeltaHandler getIfUnique() { return handler; }
        };
    }

    private FindingDeltaQueueEntry entry(
            Long id,
            String eventType,
            UUID tenantId,
            UUID componentId,
            UUID vulnerabilityId,
            String sourceKey
    ) {
        FindingDeltaQueueEntry e = new FindingDeltaQueueEntry();
        setId(e, id);
        e.setEventType(eventType);
        e.setTenantId(tenantId);
        e.setComponentId(componentId);
        e.setVulnerabilityId(vulnerabilityId);
        e.setSourceKey(sourceKey);
        e.setMaxAttempts(3);
        e.setAttemptCount(0);
        return e;
    }

    private FindingDeltaQueueEntry newEntry(Long id, String eventType) {
        return entry(id, eventType, null, null, null, null);
    }

    private static void setId(FindingDeltaQueueEntry entry, Long id) {
        try {
            Field f = FindingDeltaQueueEntry.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(entry, id);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }

}
