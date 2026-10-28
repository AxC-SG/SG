package com.prototype.vulnwatch.dto;

/**
 * A ticket raised for a finding.
 *
 * @param provider     lowercase key of the system that holds the ticket ("servicenow", "jira")
 * @param providerName display name for that system
 * @param ticketKey    the identifier a human quotes — an incident number or a Jira issue key
 */
public record FindingTicketResponse(
        String provider,
        String providerName,
        String ticketKey,
        String ticketId,
        String url,
        String status,
        String message
) {
}
