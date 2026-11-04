package com.prototype.vulnwatch.service;

public enum SuppressionMutationSource {
    DIRECT_TENANT_ADMIN,
    APPROVED_REQUEST,
    AUTOMATED_RULE,
    SYSTEM_COPY,
    LEGACY_V11_CUTOVER
}
