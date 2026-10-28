package com.prototype.vulnwatch.dto;

/**
 * Tenant-level GCP connector settings.
 *
 * @param credentialJson the customer's service account key JSON; write-only, and omitted to keep
 *                       the stored key
 */
public record GcpDiscoveryConfigRequest(
        String credentialJson,
        Boolean enabled,
        Boolean autoSyncEnabled,
        Integer intervalMinutes
) {}
