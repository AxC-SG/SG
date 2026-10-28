package com.prototype.vulnwatch.ticketing;

/**
 * Provider-neutral description of the ticket a caller wants raised.
 *
 * <p>Every field is optional: each provider falls back to values derived from the finding
 * when a field is absent, so a caller can post an empty body and still get a sensible ticket.
 * Provider-specific concerns (ServiceNow assignment groups, Jira project keys) live in the
 * connector configuration, not here.
 */
public record TicketRequest(
        String title,
        String severity,
        String priority,
        /** ISO-8601 date (yyyy-MM-dd). */
        String dueDate,
        /** Provider-native user identifier — a ServiceNow user or a Jira account id. */
        String assignee,
        String assignmentGroup,
        String notes,
        /** Patch / fix version information and remediation guidance. */
        String solutionInfo
) {

    public static TicketRequest empty() {
        return new TicketRequest(null, null, null, null, null, null, null, null);
    }
}
