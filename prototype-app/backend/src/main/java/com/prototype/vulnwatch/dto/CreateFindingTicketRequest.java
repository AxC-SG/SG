package com.prototype.vulnwatch.dto;

/**
 * Provider-neutral ticket request accepted by the finding ticket endpoint.
 * Every field is optional; omitted values are derived from the finding.
 */
public record CreateFindingTicketRequest(
        String title,
        String severity,
        String priority,
        String dueDate,
        String assignee,
        String assignmentGroup,
        String notes,
        String solutionInfo
) {
}
