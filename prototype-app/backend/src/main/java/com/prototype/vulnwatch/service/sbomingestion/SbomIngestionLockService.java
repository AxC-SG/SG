package com.prototype.vulnwatch.service.sbomingestion;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobLockService;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import java.io.IOException;
import java.util.concurrent.Callable;
import org.springframework.stereotype.Service;

/**
 * Serialises ingestion per asset so two documents cannot mutate one asset's inventory at
 * once.
 *
 * <p>This used to be a {@link java.util.concurrent.locks.ReentrantLock} in a map, which
 * guarded only the JVM holding it: with more than one instance running, concurrent uploads
 * for the same asset proceeded in parallel. It could also strand an asset permanently, since
 * a thread that died between {@code tryLock} and {@code unlock} left the entry locked for the
 * lifetime of the process, and every later attempt failed with "already in progress".
 *
 * <p>It is now a transaction-scoped Postgres advisory lock, which is visible across instances
 * and released by the database when the transaction ends, so it cannot be leaked. The
 * tenant work runner selects the customer before opening the document transaction here.
 *
 * <p>The key comes from {@link IngestionJobLockService} so that this path and the asynchronous
 * ingestion-job worker contend on the same key for the same asset. Previously one used a
 * JVM lock and the other a database lock, so they did not exclude each other at all. When the
 * worker calls in while already holding the key, the acquisition is re-entrant within the
 * session and succeeds.
 */
@Service
public class SbomIngestionLockService {

    private final IngestionJobLockService ingestionJobLockService;
    private final TenantWorkRunner tenantWorkRunner;

    public SbomIngestionLockService(IngestionJobLockService ingestionJobLockService, TenantWorkRunner tenantWorkRunner) {
        this.ingestionJobLockService = ingestionJobLockService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    public <T> T withAssetLock(Tenant tenant, String assetIdentifier, Callable<T> action) throws IOException {
        return tenantWorkRunner.runScopedChecked(tenant, () -> withTransactionLock(tenant, assetIdentifier, action));
    }

    private <T> T withTransactionLock(Tenant tenant, String assetIdentifier, Callable<T> action) throws IOException {
        long lockKey = ingestionJobLockService.assetLockKey(
                tenant == null ? null : tenant.getId(), assetIdentifier);
        if (!ingestionJobLockService.tryAcquireTransactionLock(lockKey)) {
            throw new IOException("An SBOM ingestion is already in progress for this asset. Please retry shortly.");
        }
        try {
            return action.call();
        } catch (IOException | RuntimeException rethrown) {
            throw rethrown;
        } catch (Exception checkedException) {
            throw new IOException(checkedException);
        }
        // Deliberately no unlock: the lock is transaction-scoped, so the database releases it
        // on commit or rollback. Releasing it here would free it before the work it guards has
        // actually been committed.
    }
}
