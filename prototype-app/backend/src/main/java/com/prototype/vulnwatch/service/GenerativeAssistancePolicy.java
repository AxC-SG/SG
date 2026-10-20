package com.prototype.vulnwatch.service;

import java.util.List;
import java.util.Set;
import java.util.Locale;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/** Server-side pilot containment, independent of commercial entitlement results. */
@Component
public class GenerativeAssistancePolicy {
    private final Environment environment;

    public GenerativeAssistancePolicy(Environment environment) {
        this.environment = environment;
    }

    public boolean isEnabled() {
        String intended = environment.getProperty("app.environment", "").trim().toLowerCase(Locale.ROOT);
        if (Set.of("production", "preproduction").contains(intended)
                || environment.matchesProfiles("prod", "preprod")) {
            return false;
        }
        return environment.getProperty("app.openai.enabled", Boolean.class, false);
    }

    public String configuredApiKey() {
        // Do not even resolve credential aliases while assistance is disabled.
        if (!isEnabled()) {
            return null;
        }
        for (String key : List.of("app.openai.api-key", "OPENAI_API_KEY", "openai_API_KEY", "openai.api.key")) {
            String value = environment.getProperty(key);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
