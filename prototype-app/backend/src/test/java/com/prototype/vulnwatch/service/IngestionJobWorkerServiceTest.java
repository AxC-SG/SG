package com.prototype.vulnwatch.service;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.IngestionJob;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.TaskExecutor;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.TransactionStatus;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@ExtendWith(MockitoExtension.class)
class IngestionJobWorkerServiceTest {

    @Mock
    private IngestionJobService ingestionJobService;
    @Mock
    private IngestionJobExecutionService executionService;
    @Mock
    private IngestionJobLockService ingestionJobLockService;
    @Mock
    private TenantService tenantService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    private TaskExecutor sbomJobExecutor;
    @Mock
    private TransactionTemplate transactionTemplate;

    private IngestionJobWorkerService service;

    @BeforeEach
    void setUp() {
        service = new IngestionJobWorkerService(
                ingestionJobService,
                executionService,
                ingestionJobLockService,
                tenantService,
                tenantSchemaExecutionService,
                sbomJobExecutor,
                transactionTemplate,
                10,
                1,
                5000
        );
    }

    @Test
    void pollJobsContinuesAfterOneTenantFails() {
        Tenant broken = tenant("broken");
        Tenant healthy = tenant("healthy");
        when(tenantService.listActiveTenants()).thenReturn(List.of(broken, healthy));
        doThrow(new IllegalStateException("schema drift"))
                .when(ingestionJobService).claimPendingJobs(broken, 10, 1);

        UUID healthyTenantId = healthy.getId();
        UUID healthyJobId = UUID.randomUUID();
        when(ingestionJobService.claimPendingJobs(healthy, 10, 1))
                .thenReturn(List.of(new IngestionJobService.ClaimedJobRef(healthyTenantId, healthyJobId)));

        service.pollJobs();

        verify(ingestionJobService).claimPendingJobs(healthy, 10, 1);
        verify(sbomJobExecutor).execute(org.mockito.ArgumentMatchers.any(Runnable.class));
    }

    @Test
    void pollJobsDoesNotThrowWhenListTenantsFails() {
        // Regression: tenant listing used to be called outside the try/catch. When it threw (e.g. a
        // transient DB error after a host sleep), the exception escaped pollJobs and Spring stopped
        // rescheduling the poller, leaving every ingestion job stuck in QUEUED. pollJobs must swallow
        // it so the periodic task keeps running.
        when(tenantService.listActiveTenants()).thenThrow(new IllegalStateException("connection pool exhausted"));

        org.assertj.core.api.Assertions.assertThatCode(() -> service.pollJobs())
                .doesNotThrowAnyException();

        verify(sbomJobExecutor, never()).execute(org.mockito.ArgumentMatchers.any(Runnable.class));
    }

    @Test
    void recoverInterruptedJobsDelegatesToService() {
        when(ingestionJobService.recoverInterruptedRunningJobs()).thenReturn(2);

        service.recoverInterruptedJobs();

        verify(ingestionJobService).recoverInterruptedRunningJobs();
        verify(sbomJobExecutor, never()).execute(org.mockito.ArgumentMatchers.any(Runnable.class));
    }

    @Test
    void recoverInterruptedJobsDoesNotPreventStartupWhenTenantSchemaIsNotReady() {
        when(ingestionJobService.recoverInterruptedRunningJobs())
                .thenThrow(new IllegalStateException("Tenant schema is not at the minimum compatible version"));

        org.assertj.core.api.Assertions.assertThatCode(service::recoverInterruptedJobs)
                .doesNotThrowAnyException();

        verify(ingestionJobService).recoverInterruptedRunningJobs();
    }

    @Test
    void pollJobsSkipsWhenRuntimeRoleIsApi() {
        service.setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy.forRole("api"));

        service.pollJobs();

        verify(tenantService, never()).listActiveTenants();
        verify(sbomJobExecutor, never()).execute(org.mockito.ArgumentMatchers.any(Runnable.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {IngestionJobService.JOB_TYPE_GITHUB_REPOSITORY, IngestionJobService.JOB_TYPE_GITHUB_GHCR})
    void githubBatchRunsOutsideTheJobTransactionAndDoesNotHoldTheDocumentAssetLock(String type) throws Exception {
        Tenant tenant = tenant("github");
        IngestionJob job = executionFixture(tenant, type);
        AtomicBoolean inTransaction = transactionFixture(tenant);
        when(executionService.execute(tenant, job)).thenAnswer(invocation -> {
            org.junit.jupiter.api.Assertions.assertFalse(inTransaction.get());
            return new IngestionJobExecutionService.ExecutionOutcome(null, "{}");
        });
        service.execute(tenant.getId(), job.getId());
        verify(ingestionJobService).recordStarted(job);
        verify(ingestionJobService).markSucceeded(tenant.getId(), job.getId(), null, "{}");
        verify(ingestionJobLockService, never()).tryAcquireTransactionLock(org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void remoteEndpointRetainsItsJobTransactionAndAssetLock() throws Exception {
        Tenant tenant = tenant("remote");
        IngestionJob job = executionFixture(tenant, IngestionJobService.JOB_TYPE_REMOTE_ENDPOINT);
        AtomicBoolean inTransaction = transactionFixture(tenant);
        when(ingestionJobLockService.assetLockKey(tenant.getId(), job.getAssetIdentifier())).thenReturn(42L);
        when(ingestionJobLockService.tryAcquireTransactionLock(42L)).thenReturn(true);
        when(executionService.execute(tenant, job)).thenAnswer(invocation -> {
            org.junit.jupiter.api.Assertions.assertTrue(inTransaction.get());
            return new IngestionJobExecutionService.ExecutionOutcome(null, "{}");
        });
        service.execute(tenant.getId(), job.getId());
        verify(ingestionJobLockService).tryAcquireTransactionLock(42L);
        verify(ingestionJobService).markSucceeded(tenant.getId(), job.getId(), null, "{}");
    }

    private IngestionJob executionFixture(Tenant tenant, String type) {
        IngestionJob job = new IngestionJob();
        org.springframework.test.util.ReflectionTestUtils.setField(job, "id", UUID.randomUUID());
        job.setJobType(type);
        job.setAssetIdentifier("github:acme/app");
        when(tenantService.resolveTenantUuid(tenant.getId())).thenReturn(tenant);
        when(ingestionJobService.loadJob(tenant.getId(), job.getId())).thenReturn(job);
        return job;
    }

    private AtomicBoolean transactionFixture(Tenant tenant) {
        AtomicBoolean inTransaction = new AtomicBoolean();
        doAnswer(invocation -> {
            Supplier<?> action = invocation.getArgument(1);
            return action.get();
        }).when(tenantSchemaExecutionService).run(eq(tenant), any(Supplier.class));
        doAnswer(invocation -> {
            Consumer<TransactionStatus> action = invocation.getArgument(0);
            inTransaction.set(true);
            try {
                action.accept(org.mockito.Mockito.mock(TransactionStatus.class));
            } finally {
                inTransaction.set(false);
            }
            return null;
        }).when(transactionTemplate).executeWithoutResult(any());
        return inTransaction;
    }

    private Tenant tenant(String slug) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(slug);
        tenant.setSchemaName("tenant_" + slug);
        return tenant;
    }
}
