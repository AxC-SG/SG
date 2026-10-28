package com.prototype.vulnwatch.ticketing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class TicketingProviderRegistryTest {

    private final Tenant tenant = new Tenant();

    @Test
    void jiraOverridesServiceNowWhenBothAreConfigured() {
        StubProvider serviceNow = new StubProvider(TicketingSystem.SERVICENOW, true);
        StubProvider jira = new StubProvider(TicketingSystem.JIRA, true);
        TicketingProviderRegistry registry = new TicketingProviderRegistry(List.of(serviceNow, jira));

        assertSame(jira, registry.activeProvider(tenant).orElseThrow());
        assertEquals(List.of(TicketingSystem.JIRA, TicketingSystem.SERVICENOW), registry.configuredSystems(tenant));
    }

    /** Registration order must not decide the winner — only precedence. */
    @Test
    void jiraStillWinsWhenRegisteredFirst() {
        StubProvider jira = new StubProvider(TicketingSystem.JIRA, true);
        StubProvider serviceNow = new StubProvider(TicketingSystem.SERVICENOW, true);
        TicketingProviderRegistry registry = new TicketingProviderRegistry(List.of(jira, serviceNow));

        assertSame(jira, registry.activeProvider(tenant).orElseThrow());
    }

    @Test
    void fallsBackToServiceNowWhenJiraIsNotConfigured() {
        StubProvider serviceNow = new StubProvider(TicketingSystem.SERVICENOW, true);
        StubProvider jira = new StubProvider(TicketingSystem.JIRA, false);
        TicketingProviderRegistry registry = new TicketingProviderRegistry(List.of(serviceNow, jira));

        assertSame(serviceNow, registry.activeProvider(tenant).orElseThrow());
        assertEquals(List.of(TicketingSystem.SERVICENOW), registry.configuredSystems(tenant));
    }

    @Test
    void reportsNoActiveProviderWhenNothingIsConfigured() {
        TicketingProviderRegistry registry = new TicketingProviderRegistry(List.of(
                new StubProvider(TicketingSystem.SERVICENOW, false),
                new StubProvider(TicketingSystem.JIRA, false)));

        assertTrue(registry.activeProvider(tenant).isEmpty());
        assertEquals(List.of(), registry.configuredSystems(tenant));
    }

    /**
     * A Jira connector whose credential cannot be decrypted must not take ticketing down for a
     * tenant whose ServiceNow connector is healthy.
     */
    @Test
    void aProviderThatThrowsOnItsConfigCheckDoesNotHideALowerPrecedenceOne() {
        StubProvider serviceNow = new StubProvider(TicketingSystem.SERVICENOW, true);
        StubProvider brokenJira = new StubProvider(TicketingSystem.JIRA, true);
        brokenJira.throwOnConfigured = true;
        TicketingProviderRegistry registry = new TicketingProviderRegistry(List.of(serviceNow, brokenJira));

        assertSame(serviceNow, registry.activeProvider(tenant).orElseThrow());
    }

    /** Existing tickets are routed by the recorded system, never by current precedence. */
    @Test
    void providerForResolvesTheExactSystem() {
        StubProvider serviceNow = new StubProvider(TicketingSystem.SERVICENOW, false);
        StubProvider jira = new StubProvider(TicketingSystem.JIRA, true);
        TicketingProviderRegistry registry = new TicketingProviderRegistry(List.of(serviceNow, jira));

        assertSame(serviceNow, registry.providerFor(TicketingSystem.SERVICENOW).orElseThrow());
        assertSame(jira, registry.providerFor(TicketingSystem.JIRA).orElseThrow());
        assertTrue(registry.providerFor(null).isEmpty());
    }

    @Test
    void rejectsTwoProvidersClaimingTheSameSystem() {
        assertThrows(IllegalStateException.class, () -> new TicketingProviderRegistry(List.of(
                new StubProvider(TicketingSystem.JIRA, true),
                new StubProvider(TicketingSystem.JIRA, true))));
    }

    private static final class StubProvider implements TicketingProvider {
        private final TicketingSystem system;
        private final boolean configured;
        private boolean throwOnConfigured;

        StubProvider(TicketingSystem system, boolean configured) {
            this.system = system;
            this.configured = configured;
        }

        @Override
        public TicketingSystem system() {
            return system;
        }

        @Override
        public boolean isConfigured(Tenant tenant) {
            if (throwOnConfigured) {
                throw new IllegalStateException("credential could not be decrypted");
            }
            return configured;
        }

        @Override
        public TicketRef createForFinding(Tenant tenant, Finding finding, TicketRequest request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public TicketRef createForCve(Tenant tenant, CveTicketRequest request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<TicketStatus> fetchStatus(Tenant tenant, String externalKey) {
            return Optional.empty();
        }

        @Override
        public boolean pushFindingStatus(Tenant tenant, String externalKey, TicketPush push) {
            throw new UnsupportedOperationException();
        }
    }
}
