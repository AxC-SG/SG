package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class TenantSchemaExecutionService {

    private final TenantService tenantService;
    private final TenantSchemaService tenantSchemaService;

    @Autowired
    public TenantSchemaExecutionService(
            TenantService tenantService,
            TenantSchemaService tenantSchemaService,
            @Value("${app.tenancy.tenant-switch-guard-mode:FAIL}") String tenantSwitchGuardMode
    ) {
        this.tenantService = tenantService;
        this.tenantSchemaService = tenantSchemaService;
        TenantSwitchGuardMode.from(tenantSwitchGuardMode);
    }

    TenantSchemaExecutionService(TenantService tenantService, TenantSchemaService tenantSchemaService) {
        this(tenantService, tenantSchemaService, "FAIL");
    }

    public void run(Tenant tenant, Runnable runnable) {
        run(tenant, () -> {
            runnable.run();
            return null;
        });
    }

    public <T> T run(Tenant tenant, Supplier<T> supplier) {
        Objects.requireNonNull(supplier, "supplier");
        if (tenant == null || tenant.getId() == null) {
            return supplier.get();
        }
        Tenant resolved = tenant;
        if (tenant.getSchemaName() == null || tenant.getSchemaName().isBlank()) {
            resolved = tenantService.resolveTenantUuid(tenant.getId());
        }
        String schemaName = tenantSchemaService.schemaNameForTenant(resolved);
        tenantSchemaService.assertSchemaReady(schemaName);
        return run(tenant.getId(), schemaName, supplier);
    }

    public <T> T run(UUID tenantId, Supplier<T> supplier) {
        Objects.requireNonNull(supplier, "supplier");
        if (tenantId == null) {
            return supplier.get();
        }
        Tenant tenant = tenantService.resolveTenantUuid(tenantId);
        String schemaName = tenantSchemaService.schemaNameForTenant(tenant);
        tenantSchemaService.assertSchemaReady(schemaName);
        return run(tenantId, schemaName, supplier);
    }

    private <T> T run(UUID tenantId, String schemaName, Supplier<T> supplier) {
        TenantContext.Snapshot previous = TenantContext.capture();
        guardTenantSwitchInsideActiveTransaction(tenantId, schemaName, previous.tenantId(), previous.schemaName());
        try {
            TenantContext.restore(new TenantContext.Snapshot(tenantId, schemaName, false, false));
            return supplier.get();
        } finally {
            TenantContext.restore(previous);
        }
    }

    private void guardTenantSwitchInsideActiveTransaction(
            UUID requestedTenantId,
            String requestedSchema,
            UUID previousTenantId,
            String previousSchema
    ) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            return;
        }
        boolean sameTenant = Objects.equals(requestedTenantId, previousTenantId);
        boolean sameSchema = Objects.equals(normalizeBlank(requestedSchema), normalizeBlank(previousSchema));
        if (sameTenant && sameSchema) {
            return;
        }
        String message = "Tenant context switch requested inside an active transaction: currentTenant=%s currentSchema=%s requestedTenant=%s requestedSchema=%s"
                .formatted(previousTenantId, previousSchema, requestedTenantId, requestedSchema);
        throw new IllegalStateException(message);
    }

    private String normalizeBlank(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    enum TenantSwitchGuardMode {
        FAIL;

        static TenantSwitchGuardMode from(String value) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("app.tenancy.tenant-switch-guard-mode must be FAIL");
            }
            try {
                return TenantSwitchGuardMode.valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("app.tenancy.tenant-switch-guard-mode must be FAIL", ex);
            }
        }
    }
}
