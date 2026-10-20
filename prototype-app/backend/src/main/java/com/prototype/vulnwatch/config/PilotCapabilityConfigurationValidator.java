package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantEntitlementService;
import jakarta.annotation.PostConstruct;
import java.util.Locale;
import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/** Makes the pilot's capability baseline explicit before requests and schedulers can run. */
@Component
public class PilotCapabilityConfigurationValidator {
    private final Environment environment;

    public PilotCapabilityConfigurationValidator(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    public void validate() {
        String intended = environment.getProperty("app.environment", "").trim().toLowerCase(Locale.ROOT);
        boolean deployed = Set.of("production", "preproduction").contains(intended)
                || environment.matchesProfiles("prod", "preprod");
        if (!deployed) {
            return;
        }
        if (!"ENFORCE".equalsIgnoreCase(environment.getProperty("app.entitlements.mode", ""))) {
            throw new IllegalStateException("The deployed pilot requires app.entitlements.mode=ENFORCE.");
        }
        if (TenantEntitlementService.parseEnforcementCohort(
                environment.getProperty("app.entitlements.enforce-tenant-allowlist", "")).isEmpty()) {
            throw new IllegalStateException("The deployed pilot requires an explicit named entitlement cohort.");
        }
        if (environment.getProperty("app.openai.enabled", Boolean.class, false)
                || environment.getProperty("OPENAI_ENABLED", Boolean.class, false)) {
            throw new IllegalStateException("Generative assistance must remain disabled for the deployed pilot.");
        }
    }
}
