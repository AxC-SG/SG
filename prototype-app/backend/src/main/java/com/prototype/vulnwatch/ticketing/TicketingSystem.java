package com.prototype.vulnwatch.ticketing;

import java.util.Locale;
import java.util.Optional;

/**
 * The external systems Scout can raise remediation tickets in.
 *
 * <p>{@link #precedence()} decides which system wins when a tenant has more than one
 * configured: the highest value is used for <em>new</em> tickets. Jira therefore overrides
 * ServiceNow. Tickets that already exist keep the system that created them — see
 * {@code findings.incident_provider} — so status sync continues to poll the right place.
 *
 * <p>Adding a system (Freshworks, say) means adding a constant here plus a
 * {@link TicketingProvider} bean; no caller changes.
 */
public enum TicketingSystem {

    SERVICENOW("servicenow", "ServiceNow", 10),
    JIRA("jira", "Jira", 20);

    private final String key;
    private final String displayName;
    private final int precedence;

    TicketingSystem(String key, String displayName, int precedence) {
        this.key = key;
        this.displayName = displayName;
        this.precedence = precedence;
    }

    /** Stable lowercase identifier used in persisted columns, API payloads and provider keys. */
    public String key() {
        return key;
    }

    public String displayName() {
        return displayName;
    }

    /** Higher wins when several systems are configured for the same tenant. */
    public int precedence() {
        return precedence;
    }

    /**
     * Resolves a persisted or request-supplied identifier back to a system.
     *
     * <p>Accepts both the {@link #key()} and the enum name so historical rows written before
     * a naming change still resolve. Returns empty rather than throwing, because a value read
     * from the database may name a system this build no longer knows about.
     */
    public static Optional<TicketingSystem> fromKey(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        for (TicketingSystem system : values()) {
            if (system.key.equals(normalized) || system.name().toLowerCase(Locale.ROOT).equals(normalized)) {
                return Optional.of(system);
            }
        }
        return Optional.empty();
    }
}
