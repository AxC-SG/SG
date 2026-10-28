package com.prototype.vulnwatch.ticketing;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Resolves which {@link TicketingProvider} to use.
 *
 * <p>Two different questions, deliberately separate:
 * <ul>
 *   <li>{@link #activeProvider(Tenant)} — where should a <em>new</em> ticket go? The
 *       configured provider with the highest {@link TicketingSystem#precedence()}, so Jira
 *       overrides ServiceNow.</li>
 *   <li>{@link #providerFor(TicketingSystem)} — who owns an <em>existing</em> ticket? Driven by
 *       the system recorded on the finding, never by current precedence. Without this split,
 *       enabling Jira would send status polls for historical ServiceNow incidents to Jira.</li>
 * </ul>
 */
@Component
public class TicketingProviderRegistry {

    private static final Logger log = LoggerFactory.getLogger(TicketingProviderRegistry.class);

    private final Map<TicketingSystem, TicketingProvider> providersBySystem;
    private final List<TicketingProvider> byDescendingPrecedence;

    public TicketingProviderRegistry(List<TicketingProvider> providers) {
        Map<TicketingSystem, TicketingProvider> resolved = new EnumMap<>(TicketingSystem.class);
        for (TicketingProvider provider : providers) {
            TicketingProvider previous = resolved.put(provider.system(), provider);
            if (previous != null) {
                throw new IllegalStateException(
                        "Two TicketingProvider beans claim " + provider.system()
                                + ": " + previous.getClass().getName() + " and " + provider.getClass().getName());
            }
        }
        this.providersBySystem = Map.copyOf(resolved);
        this.byDescendingPrecedence = resolved.values().stream()
                .sorted(Comparator.comparingInt((TicketingProvider p) -> p.system().precedence()).reversed())
                .toList();
    }

    /** Every registered provider, highest precedence first. */
    public List<TicketingProvider> providers() {
        return byDescendingPrecedence;
    }

    /** The provider that owns an existing ticket, if this build still supports that system. */
    public Optional<TicketingProvider> providerFor(TicketingSystem system) {
        return Optional.ofNullable(system == null ? null : providersBySystem.get(system));
    }

    /**
     * The provider that new tickets should be raised in, or empty when the tenant has
     * configured none.
     */
    public Optional<TicketingProvider> activeProvider(Tenant tenant) {
        for (TicketingProvider provider : byDescendingPrecedence) {
            if (isConfiguredSafely(provider, tenant)) {
                return Optional.of(provider);
            }
        }
        return Optional.empty();
    }

    /** Every system this tenant has configured, highest precedence first. */
    public List<TicketingSystem> configuredSystems(Tenant tenant) {
        return byDescendingPrecedence.stream()
                .filter(provider -> isConfiguredSafely(provider, tenant))
                .map(TicketingProvider::system)
                .toList();
    }

    /**
     * A misconfigured connector must not hide a working one. A provider whose configuration
     * lookup throws is treated as unconfigured so precedence falls through to the next system.
     */
    private boolean isConfiguredSafely(TicketingProvider provider, Tenant tenant) {
        try {
            return provider.isConfigured(tenant);
        } catch (RuntimeException ex) {
            log.warn("Ticketing provider {} failed its configuration check — treating it as unconfigured: {}",
                    provider.system().key(), ex.getMessage());
            return false;
        }
    }
}
