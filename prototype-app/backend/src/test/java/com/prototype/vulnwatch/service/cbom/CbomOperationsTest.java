package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomAssessmentResponse;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.CbomAssessmentRunRepository;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IngestionAttemptService;
import com.prototype.vulnwatch.service.IngestionJobPayloads;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.task.TaskExecutor;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

/** Repair sweep, assessment worker and backfill operations for CBOM Milestone 1. */
class CbomOperationsTest {

    private TenantService tenants;
    private TenantSchemaExecutionService schemas;
    private TransactionTemplate transactions;
    private SimpleMeterRegistry registry;
    private CbomOperationsMetrics metrics;
    private Tenant tenant;

    @BeforeEach
    @SuppressWarnings("unchecked") // Mockito generic matchers for Supplier/TransactionCallback.
    void setUp() {
        tenants = mock(TenantService.class);
        schemas = mock(TenantSchemaExecutionService.class);
        transactions = mock(TransactionTemplate.class);
        lenient().when(schemas.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(inv -> ((Supplier<?>) inv.getArgument(1)).get());
        lenient().when(transactions.execute(any(TransactionCallback.class)))
                .thenAnswer(inv -> ((TransactionCallback<?>) inv.getArgument(0)).doInTransaction(null));
        registry = new SimpleMeterRegistry();
        metrics = new CbomOperationsMetrics(providerOf(registry));
        tenant = tenant();
    }

    // ---------------------------------------------------------------- repair sweep

    @Test
    void repairRepublishesOnlyDriftedFindingsAsCbomDeltas() {
        CbomRiskFindingRepository findings = mock(CbomRiskFindingRepository.class);
        FindingDeltaQueueService queue = mock(FindingDeltaQueueService.class);
        UUID drifted = UUID.randomUUID();
        when(findings.findMirrorRepairCandidates(500)).thenReturn(List.of(drifted));
        CbomFindingMirrorSweep sweep = new CbomFindingMirrorSweep(tenants, schemas, findings, queue, metrics);

        assertThat(sweep.repairTenant(tenant)).isEqualTo(1);

        verify(queue).enqueueCbomDeltas(tenant.getId(), List.of(drifted), "cbom-repair");
        verify(findings, never()).findByTenant_Id(any());
        assertThat(registry.counter("cbom.mirror.repair.republished").count()).isEqualTo(1.0);
    }

    @Test
    void healthyTenantRepairPublishesNothingAndFlagsTruncationWhenTheBoundIsHit() {
        CbomRiskFindingRepository findings = mock(CbomRiskFindingRepository.class);
        FindingDeltaQueueService queue = mock(FindingDeltaQueueService.class);
        CbomFindingMirrorSweep sweep = new CbomFindingMirrorSweep(tenants, schemas, findings, queue, metrics);
        sweep.setRepairLimitPerTenant(2);
        when(findings.findMirrorRepairCandidates(2)).thenReturn(List.of()).thenReturn(List.of(UUID.randomUUID(), UUID.randomUUID()));

        assertThat(sweep.repairTenant(tenant)).isZero();
        verify(queue, never()).enqueueCbomDeltas(any(), any(), any());
        assertThat(sweep.repairTenant(tenant)).isEqualTo(2);
        assertThat(registry.counter("cbom.mirror.repair.truncated").count()).isEqualTo(1.0);
    }

    // ---------------------------------------------------------------- worker

    @Test
    void transientFailureIsRetriedWithBackoffUntilAttemptsAreExhausted() {
        IngestionJobService jobs = mock(IngestionJobService.class);
        CbomAssessmentService assessments = mock(CbomAssessmentService.class);
        CbomAssessmentWorkerService worker = worker(jobs, assessments, Runnable::run);
        IngestionJobService.ClaimedJobRef ref = claimed(jobs, assessments, 1);
        when(assessments.assess(any(), any())).thenThrow(new IllegalStateException("database busy"));

        worker.execute(ref);

        verify(jobs).markQueuedForRetry(eq(tenant.getId()), eq(ref.jobId()), eq("CBOM_ASSESSMENT_RETRY"), eq("database busy"), any());
        verify(jobs, never()).markFailed(any(), any(), any(), any());
        assertThat(registry.counter("cbom.assessment.jobs", "outcome", "retried").count()).isEqualTo(1.0);

        IngestionJobService.ClaimedJobRef last = claimed(jobs, assessments, 3);
        worker.execute(last);
        verify(jobs).markFailed(tenant.getId(), last.jobId(), "CBOM_ASSESSMENT_FAILED", "database busy");
        assertThat(registry.counter("cbom.assessment.jobs", "outcome", "failed").count()).isEqualTo(1.0);
        assertThat(registry.timer("cbom.assessment.duration").count()).isEqualTo(2);
    }

    @Test
    void missingArtifactFailsImmediatelyWithoutRetry() {
        IngestionJobService jobs = mock(IngestionJobService.class);
        CbomAssessmentService assessments = mock(CbomAssessmentService.class);
        CbomAssessmentWorkerService worker = worker(jobs, assessments, Runnable::run);
        IngestionJobService.ClaimedJobRef ref = claimed(jobs, assessments, 1);
        when(assessments.assess(any(), any())).thenThrow(new IllegalArgumentException("CBOM artifact not found"));

        worker.execute(ref);

        verify(jobs, never()).markQueuedForRetry(any(), any(), any(), any(), any());
        verify(jobs).markFailed(tenant.getId(), ref.jobId(), "CBOM_ASSESSMENT_FAILED", "CBOM artifact not found");
    }

    @Test
    void successRecordsOutcomeMetric() {
        IngestionJobService jobs = mock(IngestionJobService.class);
        CbomAssessmentService assessments = mock(CbomAssessmentService.class);
        CbomAssessmentWorkerService worker = worker(jobs, assessments, Runnable::run);
        IngestionJobService.ClaimedJobRef ref = claimed(jobs, assessments, 1);
        CbomAssessmentResponse response = new CbomAssessmentResponse(UUID.randomUUID(), UUID.randomUUID(), null, "sha256:a",
                "scoutgrid-baseline", "1.0.0", "sha256:rules", "1.0", "SUCCEEDED", "VALID", 0, 0, null, null,
                Instant.now(), Instant.now(), List.of(), List.of());
        when(assessments.assess(any(), any())).thenReturn(response);
        when(jobs.toJson(any())).thenReturn("{}");

        worker.execute(ref);

        verify(jobs).markSucceeded(eq(tenant.getId()), eq(ref.jobId()), eq(null), eq("{}"));
        assertThat(registry.counter("cbom.assessment.jobs", "outcome", "succeeded").count()).isEqualTo(1.0);
    }

    @Test
    void pollRotatesTenantStartPositionAndPublishesBacklogGauges() {
        IngestionJobService jobs = mock(IngestionJobService.class);
        Tenant a = tenant(), b = tenant(), c = tenant();
        when(tenants.listActiveTenants()).thenReturn(List.of(a, b, c));
        List<UUID> order = new ArrayList<>();
        when(jobs.claimPendingJobsByType(any(), eq(IngestionJobService.JOB_TYPE_CBOM_ASSESSMENT), anyInt(), anyInt()))
                .thenAnswer(inv -> { order.add(((Tenant) inv.getArgument(0)).getId()); return List.of(); });
        Instant old = Instant.now().minusSeconds(120);
        when(jobs.backlogByType(any(), anyString())).thenReturn(new IngestionJobService.JobTypeBacklog(0, null));
        when(jobs.backlogByType(eq(b), anyString())).thenReturn(new IngestionJobService.JobTypeBacklog(4, old));
        CbomAssessmentWorkerService worker = worker(jobs, mock(CbomAssessmentService.class), Runnable::run);
        worker.setBacklogSampleIntervalMs(0);

        worker.poll();
        worker.poll();

        assertThat(order.subList(0, 3)).containsExactly(a.getId(), b.getId(), c.getId());
        assertThat(order.subList(3, 6)).containsExactly(b.getId(), c.getId(), a.getId());
        assertThat(metrics.tenantsWithBacklog()).isEqualTo(1);
        assertThat(metrics.oldestQueuedAgeSeconds()).isGreaterThanOrEqualTo(119);
    }

    @Test
    void executorRejectionReturnsTheClaimAndIsCounted() {
        IngestionJobService jobs = mock(IngestionJobService.class);
        when(tenants.listActiveTenants()).thenReturn(List.of(tenant));
        IngestionJobService.ClaimedJobRef ref = new IngestionJobService.ClaimedJobRef(tenant.getId(), UUID.randomUUID(), UUID.randomUUID());
        when(jobs.claimPendingJobsByType(any(), any(), anyInt(), anyInt())).thenReturn(List.of(ref));
        CbomAssessmentWorkerService worker = worker(jobs, mock(CbomAssessmentService.class),
                task -> { throw new java.util.concurrent.RejectedExecutionException("full"); });

        worker.poll();

        verify(jobs).retryRejectedClaim(eq(ref), eq("EXECUTOR_BUSY"), any(), any());
        assertThat(registry.counter("cbom.assessment.executor.rejections").count()).isEqualTo(1.0);
    }

    // ---------------------------------------------------------------- backfill

    @Test
    void backfillEnqueuesOnlyUnassessedIdleArtifactsAndReportsDurableProgress() {
        BomIngestionRecordRepository boms = mock(BomIngestionRecordRepository.class);
        CbomAssessmentRunRepository runs = mock(CbomAssessmentRunRepository.class);
        CbomRulePackageService packages = mock(CbomRulePackageService.class);
        IngestionJobService jobs = mock(IngestionJobService.class);
        BomIngestionRecord assessed = bom(BomType.CBOM), queued = bom(BomType.CBOM), failed = bom(BomType.CBOM),
                fresh = bom(BomType.CBOM), sbom = bom(BomType.SBOM);
        when(boms.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE)).thenReturn(List.of(assessed, queued, failed, fresh, sbom));
        when(packages.effective(tenant)).thenReturn(new CbomRulePackageService.EffectivePackage("scoutgrid-baseline", "1.0.0", "sha256:rules", "1.0", "{}"));
        when(runs.findAssessedBomIds(tenant.getId(), "sha256:rules", "1.0")).thenReturn(Set.of(assessed.getId()));
        when(jobs.assetIdentifiersByTypeAndStatus(any(), any(), eq(IngestionJobService.STATUS_QUEUED))).thenReturn(Set.of(queued.getId().toString()));
        when(jobs.assetIdentifiersByTypeAndStatus(any(), any(), eq(IngestionJobService.STATUS_RUNNING))).thenReturn(Set.of());
        when(jobs.assetIdentifiersByTypeAndStatus(any(), any(), eq(IngestionJobService.STATUS_FAILED))).thenReturn(Set.of(failed.getId().toString()));
        when(jobs.enqueueCbomAssessmentJob(eq(tenant), any(), any()))
                .thenReturn(new IngestionJobAcceptedResponse(UUID.randomUUID(), "QUEUED", "queued", false, null));
        AuditEventService audit = mock(AuditEventService.class);
        CbomAssessmentBackfillService backfill = new CbomAssessmentBackfillService(boms, runs, packages, jobs, schemas,
                transactions, tenants, audit, metrics);

        var status = backfill.status(tenant);
        assertThat(status.activeArtifacts()).isEqualTo(4);
        assertThat(status.assessed()).isEqualTo(1);
        assertThat(status.queued()).isEqualTo(1);
        assertThat(status.failed()).isEqualTo(1);
        assertThat(status.notStarted()).isEqualTo(1);
        assertThat(status.complete()).isFalse();

        var started = backfill.start(tenant, "admin", 1);

        assertThat(started.enqueued()).isEqualTo(1);
        verify(jobs, times(1)).enqueueCbomAssessmentJob(eq(tenant), any(), eq("admin"));
        verify(jobs, never()).enqueueCbomAssessmentJob(eq(tenant), eq(assessed.getId()), any());
        verify(jobs, never()).enqueueCbomAssessmentJob(eq(tenant), eq(queued.getId()), any());
        verify(jobs, never()).enqueueCbomAssessmentJob(eq(tenant), eq(sbom.getId()), any());
        verify(audit).record(eq("cbom.assessment.backfill.started"), eq("tenant"), eq(tenant.getId().toString()), any());
        assertThat(registry.counter("cbom.assessment.backfill.enqueued").count()).isEqualTo(1.0);
    }

    @Test
    void platformBackfillContinuesPastATenantFailure() {
        CbomAssessmentBackfillService backfill = mock(CbomAssessmentBackfillService.class, org.mockito.Mockito.CALLS_REAL_METHODS);
        Tenant broken = tenant();
        ReflectionTestUtils.setField(backfill, "tenants", tenants);
        when(tenants.listActiveTenants()).thenReturn(List.of(broken, tenant));
        org.mockito.Mockito.doThrow(new IllegalStateException("schema drifted")).when(backfill).start(eq(broken), any(), any());
        org.mockito.Mockito.doReturn(new CbomAssessmentBackfillService.BackfillStart(3, null)).when(backfill).start(eq(tenant), any(), any());

        var result = backfill.startAllTenants("platform", 10);

        assertThat(result.tenants()).isEqualTo(2);
        assertThat(result.tenantFailures()).isEqualTo(1);
        assertThat(result.enqueued()).isEqualTo(3);
    }

    // ---------------------------------------------------------------- helpers

    private CbomAssessmentWorkerService worker(IngestionJobService jobs, CbomAssessmentService assessments, TaskExecutor executor) {
        CbomAssessmentWorkerService worker = new CbomAssessmentWorkerService(jobs, tenants, schemas, assessments, executor, transactions);
        worker.setMetrics(metrics);
        lenient().when(tenants.resolveTenantUuid(tenant.getId())).thenReturn(tenant);
        return worker;
    }

    private IngestionJobService.ClaimedJobRef claimed(IngestionJobService jobs, CbomAssessmentService assessments, int attempt) {
        IngestionJobService.ClaimedJobRef ref = new IngestionJobService.ClaimedJobRef(tenant.getId(), UUID.randomUUID(), UUID.randomUUID());
        IngestionJob job = new IngestionJob();
        job.setAttemptCount(attempt);
        when(jobs.openAttempt(any(), eq(ref.jobId()), any())).thenReturn(mock(IngestionAttemptService.AttemptScope.class));
        when(jobs.loadJob(tenant.getId(), ref.jobId())).thenReturn(job);
        lenient().when(jobs.readPayload(job, IngestionJobPayloads.CbomAssessmentPayload.class))
                .thenReturn(new IngestionJobPayloads.CbomAssessmentPayload(UUID.randomUUID()));
        return ref;
    }

    private static Tenant tenant() {
        Tenant t = new Tenant();
        t.setId(UUID.randomUUID());
        t.setSchemaName("tenant_" + t.getId().toString().substring(0, 8));
        return t;
    }

    private BomIngestionRecord bom(BomType type) {
        BomIngestionRecord bom = new BomIngestionRecord();
        bom.setTenant(tenant);
        bom.setBomType(type);
        bom.setStatus(BomStatus.ACTIVE);
        ReflectionTestUtils.setField(bom, "id", UUID.randomUUID());
        return bom;
    }

    private static ObjectProvider<MeterRegistry> providerOf(MeterRegistry registry) {
        return new ObjectProvider<>() {
            @Override public MeterRegistry getObject() { return registry; }
            @Override public MeterRegistry getObject(Object... args) { return registry; }
            @Override public MeterRegistry getIfAvailable() { return registry; }
            @Override public MeterRegistry getIfUnique() { return registry; }
        };
    }
}
