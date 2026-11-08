package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import jakarta.annotation.PostConstruct;
import java.util.Locale;
import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/** Validates the deployment's intent before runners, schedulers, or HTTP traffic can execute. */
@Component
public class RuntimeConfigurationValidator {
    private final Environment environment;

    public RuntimeConfigurationValidator(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    public void validate() {
        String intended = environment.getProperty("app.environment", "").trim().toLowerCase(Locale.ROOT);
        if (!Set.of("local", "test", "production", "preproduction").contains(intended)) {
            throw new IllegalStateException("APP_ENVIRONMENT must explicitly be local, test, production, or preproduction.");
        }
        boolean deployedProfile = environment.matchesProfiles("prod", "preprod");
        boolean deployedHost = environment.containsProperty("ECS_CONTAINER_METADATA_URI_V4");
        boolean production = Set.of("production", "preproduction").contains(intended);
        if ((deployedProfile || deployedHost) && !production) {
            throw new IllegalStateException("A deployed runtime cannot use a local/test APP_ENVIRONMENT.");
        }
        BackgroundTaskExecutionPolicy.forRole(environment.getProperty("app.runtime.role"));
        if (!production) {
            return;
        }
        if (!"FAIL".equalsIgnoreCase(environment.getProperty("app.tenancy.tenant-switch-guard-mode", "FAIL"))) {
            throw new IllegalStateException("Production transaction tenant-switch guard must be FAIL.");
        }
        if (!environment.getProperty("app.security.require-production-secrets", Boolean.class, false)) {
            throw new IllegalStateException("Production validation cannot be disabled for a deployed runtime.");
        }
        for (String property : new String[] {
                "app.test-personas.enabled", "app.tenancy.allow-header-tenant-selection",
                "app.cmdb.sccm.mock-mode", "app.security.bootstrap.platform-owners.enabled",
                "app.ai-security.grid.demo-auto-publish-bundled-policies",
                "app.demo.synchronous-tenant-provisioning-enabled", "app.schema-migration.enabled",
                "spring.flyway.enabled"}) {
            if (environment.getProperty(property, Boolean.class, false)) {
                throw new IllegalStateException(property + " must be false in the deployed application runtime.");
            }
        }
        if (!"none".equalsIgnoreCase(environment.getProperty("server.forward-headers-strategy", "none"))) {
            throw new IllegalStateException("Use server.forward-headers-strategy=none; client identity is resolved from explicit trusted proxies.");
        }
        if (environment.getProperty("app.security.public-rate-limit.trust-proxy-headers", Boolean.class, false)
                && environment.getProperty("app.security.public-rate-limit.trusted-proxy-cidrs", "").isBlank()) {
            throw new IllegalStateException("Trusted proxy forwarding requires explicit APP_PUBLIC_RATE_LIMIT_TRUSTED_PROXY_CIDRS.");
        }
    }
}
