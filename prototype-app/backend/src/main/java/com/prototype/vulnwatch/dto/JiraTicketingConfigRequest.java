package com.prototype.vulnwatch.dto;

/**
 * Jira connector settings submitted from the connector page.
 *
 * <p>{@code credentialSecret} is write-only: a blank value leaves the stored token untouched,
 * so the UI never has to round-trip the secret.
 */
public record JiraTicketingConfigRequest(
        String baseUrl,
        String authType,
        String username,
        String credentialSecret,
        String projectKey,
        String issueTypeId,
        String issueTypeName,
        String defaultLabels,
        Boolean includePriority,
        Boolean enabled
) {
}
