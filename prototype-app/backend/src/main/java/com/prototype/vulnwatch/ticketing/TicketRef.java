package com.prototype.vulnwatch.ticketing;

/**
 * A ticket that exists in an external system.
 *
 * @param system      the system that holds the ticket
 * @param externalKey the human-facing identifier used to poll status later
 *                    (a ServiceNow incident number, a Jira issue key)
 * @param externalId  the system's internal identifier, when it differs from the key
 * @param url         a deep link a human can open
 * @param status      the ticket's state at creation time, in the provider's own vocabulary
 * @param message     an operator-facing confirmation
 */
public record TicketRef(
        TicketingSystem system,
        String externalKey,
        String externalId,
        String url,
        String status,
        String message
) {
}
