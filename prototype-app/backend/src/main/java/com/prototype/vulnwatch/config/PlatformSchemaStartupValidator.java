package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantSchemaStatusService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.stereotype.Component;

/** Uses the same read-only platform dependency contract as readiness before serving. */
@Component
@DependsOnDatabaseInitialization
public class PlatformSchemaStartupValidator {
    private final TenantSchemaStatusService schemas;
    private final boolean enabled;

    public PlatformSchemaStartupValidator(TenantSchemaStatusService schemas,
            @Value("${app.tenancy.enforce-schema-version:false}") boolean enabled) {
        this.schemas = schemas;
        this.enabled = enabled;
    }

    @PostConstruct
    public void validate() {
        if (enabled) schemas.assertPlatformDependencies();
    }
}
