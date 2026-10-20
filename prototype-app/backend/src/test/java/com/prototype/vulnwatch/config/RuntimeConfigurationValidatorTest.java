package com.prototype.vulnwatch.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class RuntimeConfigurationValidatorTest {
    private MockEnvironment production() {
        return new MockEnvironment().withProperty("app.environment", "preproduction")
                .withProperty("app.runtime.role", "all")
                .withProperty("app.security.require-production-secrets", "true");
    }
    @Test
    void requiresExplicitEnvironmentAndRoleAndPreservesLocalAndWorkerConfigurations() {
        assertThatThrownBy(() -> new RuntimeConfigurationValidator(new MockEnvironment()).validate())
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new RuntimeConfigurationValidator(production().withProperty("app.runtime.role", "typo")).validate())
                .isInstanceOf(IllegalStateException.class);
        assertThatCode(() -> new RuntimeConfigurationValidator(production().withProperty("app.runtime.role", "worker")).validate()).doesNotThrowAnyException();
        assertThatCode(() -> new RuntimeConfigurationValidator(new MockEnvironment()
                .withProperty("app.environment", "local").withProperty("app.runtime.role", "all")).validate()).doesNotThrowAnyException();
    }
    @Test
    void profileAndHostedRuntimeCannotMasqueradeAsLocalAndDisableValidation() {
        MockEnvironment activeProfile = production().withProperty("app.environment", "local");
        activeProfile.setActiveProfiles("preprod");
        assertThatThrownBy(() -> new RuntimeConfigurationValidator(activeProfile).validate()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new RuntimeConfigurationValidator(production()
                .withProperty("app.security.require-production-secrets", "false")).validate()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new RuntimeConfigurationValidator(production().withProperty("app.environment", "test")
                .withProperty("RENDER_SERVICE_ID", "fixture")).validate()).isInstanceOf(IllegalStateException.class);
    }
    @Test
    void rejectsBootstrapMockAndForwardingBypasses() {
        for (String unsafe : new String[] {"app.test-personas.enabled", "app.tenancy.allow-header-tenant-selection",
                "app.cmdb.sccm.mock-mode", "app.security.bootstrap.platform-owners.enabled",
                "app.ai-security.grid.demo-auto-publish-bundled-policies", "app.schema-migration.enabled"}) {
            assertThatThrownBy(() -> new RuntimeConfigurationValidator(production().withProperty(unsafe, "true")).validate())
                    .isInstanceOf(IllegalStateException.class);
        }
        assertThatThrownBy(() -> new RuntimeConfigurationValidator(production().withProperty("server.forward-headers-strategy", "framework")).validate())
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new RuntimeConfigurationValidator(production().withProperty("app.security.public-rate-limit.trust-proxy-headers", "true")).validate())
                .isInstanceOf(IllegalStateException.class);
        assertThatCode(() -> new RuntimeConfigurationValidator(production()
                .withProperty("app.security.public-rate-limit.trust-proxy-headers", "true")
                .withProperty("app.security.public-rate-limit.trusted-proxy-cidrs", "10.9.0.0/24")).validate()).doesNotThrowAnyException();
    }
}
