package com.prototype.vulnwatch.service.sbomingestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobLockService;
import java.io.IOException;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class SbomIngestionLockServiceTest {

    private IngestionJobLockService ingestionJobLockService;
    private SbomIngestionLockService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        ingestionJobLockService = mock(IngestionJobLockService.class);
        service = new SbomIngestionLockService(ingestionJobLockService, scopedRunner());
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
    }

    @Test
    void runsTheActionOnceTheAssetLockIsHeld() throws Exception {
        when(ingestionJobLockService.tryAcquireTransactionLock(anyLong())).thenReturn(true);

        assertEquals("ingested", service.withAssetLock(tenant, "pkg:npm/app", () -> "ingested"));
    }

    @Test
    void failsFastWhenAnotherIngestionHoldsTheAsset() {
        when(ingestionJobLockService.tryAcquireTransactionLock(anyLong())).thenReturn(false);

        IOException error = assertThrows(IOException.class, () ->
                service.withAssetLock(tenant, "pkg:npm/app", () -> "ingested"));
        assertTrue(error.getMessage().contains("already in progress"), error.getMessage());
    }

    @Test
    void doesNotRunTheActionWhenTheLockIsUnavailable() {
        when(ingestionJobLockService.tryAcquireTransactionLock(anyLong())).thenReturn(false);

        assertThrows(IOException.class, () -> service.withAssetLock(tenant, "pkg:npm/app", () -> {
            throw new AssertionError("the guarded action must not run without the lock");
        }));
    }

    // The asynchronous ingestion-job worker locks the same asset through
    // IngestionJobLockService. Deriving the key from that same service is what makes the two
    // paths mutually exclusive; computing it independently here would let a direct upload and
    // a queued job mutate one asset's inventory at the same time.
    @Test
    void derivesTheSameAssetKeyAsTheIngestionJobWorker() throws Exception {
        IngestionJobLockService realKeys = new IngestionJobLockService(mock(JdbcTemplate.class));
        long workerKey = realKeys.assetLockKey(tenant.getId(), "pkg:npm/app");

        when(ingestionJobLockService.assetLockKey(tenant.getId(), "pkg:npm/app")).thenReturn(workerKey);
        when(ingestionJobLockService.tryAcquireTransactionLock(workerKey)).thenReturn(true);

        service.withAssetLock(tenant, "pkg:npm/app", () -> "ingested");

        verify(ingestionJobLockService).tryAcquireTransactionLock(workerKey);
    }

    // The lock is transaction-scoped, so Postgres releases it on commit or rollback.
    // Releasing it here would expose the asset before the guarded work was committed. Asserting
    // that acquiring the key is the *only* thing this service does to the lock is what pins
    // that down: any future "tidy up in a finally block" change fails here.
    @Test
    void leavesReleaseToTheTransactionEvenWhenTheActionFails() {
        when(ingestionJobLockService.assetLockKey(tenant.getId(), "pkg:npm/app")).thenReturn(99L);
        when(ingestionJobLockService.tryAcquireTransactionLock(99L)).thenReturn(true);

        assertThrows(IllegalStateException.class, () ->
                service.withAssetLock(tenant, "pkg:npm/app", () -> {
                    throw new IllegalStateException("ingestion blew up");
                }));

        verify(ingestionJobLockService).assetLockKey(tenant.getId(), "pkg:npm/app");
        verify(ingestionJobLockService).tryAcquireTransactionLock(99L);
        verifyNoMoreInteractions(ingestionJobLockService);
    }

    @Test
    void wrapsACheckedFailureFromTheActionAsIoException() {
        when(ingestionJobLockService.tryAcquireTransactionLock(anyLong())).thenReturn(true);

        assertThrows(IOException.class, () -> service.withAssetLock(tenant, "pkg:npm/app", () -> {
            throw new java.util.concurrent.TimeoutException("slow");
        }));
    }

    private static com.prototype.vulnwatch.service.TenantWorkRunner scopedRunner() {
        return mock(com.prototype.vulnwatch.service.TenantWorkRunner.class, invocation -> {
            if (invocation.getMethod().getName().equals("runScopedChecked")) {
                return invocation.<java.util.concurrent.Callable<?>>getArgument(1).call();
            }
            return org.mockito.Answers.RETURNS_DEFAULTS.answer(invocation);
        });
    }
}
