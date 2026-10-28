package com.prototype.vulnwatch.dto;

import java.util.List;

/**
 * Which ticketing system new tickets will go to, and why.
 *
 * @param activeProvider     lowercase key of the winning system, or null when none is configured
 * @param configuredProviders every configured system, highest precedence first
 * @param overridden         systems that are configured but outranked — the UI surfaces this so
 *                           an operator understands why their ServiceNow connector stopped
 *                           receiving new tickets after Jira was enabled
 */
public record TicketingProviderStatusResponse(
        String activeProvider,
        String activeProviderName,
        List<String> configuredProviders,
        List<String> overridden
) {
}
