package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

/**
 * Result of probing a GCP target. {@code status} is SUCCESS, SUCCESS_WITH_WARNINGS (only optional
 * permissions missing) or FAILED, and every permission is reported individually so an operator
 * can see exactly which grant is missing.
 */
public record GcpConnectionTestResponse(
        String status,
        String message,
        String serviceAccountEmail,
        List<PermissionCheck> permissions,
        Instant testedAt
) {
    public record PermissionCheck(String permission, boolean granted, boolean required) {}
}
