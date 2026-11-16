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
        String solutionInfo,
        /**
         * The server-routed assignment group (Phase 0B §4.9), set only by {@code TicketingService} on the canonical
         * routing path. When present, providers use exactly this group and never a finding's {@code owner_group} or a
         * built-in default.
         */
        String routedAssignmentGroup
) {
    public TicketRequest(String title, String severity, String priority, String dueDate, String assignee, String assignmentGroup,
                         String notes, String solutionInfo) {
        this(title, severity, priority, dueDate, assignee, assignmentGroup, notes, solutionInfo, null);
    }


    public static TicketRequest empty() {
        return new TicketRequest(null, null, null, null, null, null, null, null, null);
    }
}
