package com.prototype.vulnwatch.dto;

/**
 * Patch tool connection settings. {@code secret} (BigFix password, Tanium API token, Intune
 * client secret) is write-only: omit it to keep the stored value.
 */
public record PatchConnectorConfigRequest(
        String baseUrl,
        String directoryId,
        String clientId,
        String username,
        String secret,
        Boolean enabled,
        Boolean autoSyncEnabled,
        Integer intervalMinutes
) {}
