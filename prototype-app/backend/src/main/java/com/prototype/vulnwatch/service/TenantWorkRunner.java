package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.concurrent.Callable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class TenantWorkRunner {

    private static final Logger LOG = LoggerFactory.getLogger(TenantWorkRunner.class);

    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TransactionTemplate transactionTemplate;

    public TenantWorkRunner(
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            PlatformTransactionManager transactionManager
    ) {
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    public void forEachActiveTenant(Consumer<Tenant> work) {
        TenantContext.runAsPlatform(() -> {
            try {
                for (Tenant tenant : tenantService.listActiveTenants()) {
                    try {
                        runScoped(tenant, () -> {
                            work.accept(tenant);
                            return null;
                        });
                    } catch (Exception ex) {
                        LOG.warn("Tenant-scoped background work failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                    }
                }
            } catch (Exception ex) {
                LOG.warn("Tenant-scoped background work failed before tenant iteration: {}", ex.getMessage(), ex);
            }
        });
    }

    public void runScoped(Tenant tenant, Runnable work) {
        runScoped(tenant, () -> {
            work.run();
            return null;
        });
    }

    public <T> T runScoped(Tenant tenant, Supplier<T> work) {
        return tenantSchemaExecutionService.run(tenant, () -> transactionTemplate.execute(status -> work.get()));
    }

    public void runScoped(UUID tenantId, Runnable work) {
        runScoped(tenantId, () -> {
            work.run();
            return null;
        });
    }

    public <T> T runScoped(UUID tenantId, Supplier<T> work) {
        return tenantSchemaExecutionService.run(tenantId, () -> transactionTemplate.execute(status -> work.get()));
    }

    /** Select the tenant before the document transaction and roll back checked failures. */
    public <T> T runScopedChecked(Tenant tenant, Callable<T> work) throws IOException {
        try {
            return runScoped(tenant, () -> {
                try {
                    return work.call();
                } catch (IOException failure) {
                    throw new UncheckedIOException(failure);
                } catch (RuntimeException failure) {
                    throw failure;
                } catch (Exception failure) {
                    throw new UncheckedIOException(new IOException(failure));
                }
            });
        } catch (UncheckedIOException failure) {
            throw failure.getCause();
        }
    }
}
