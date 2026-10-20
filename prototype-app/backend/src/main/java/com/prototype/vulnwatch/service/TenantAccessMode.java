package com.prototype.vulnwatch.service;

public enum TenantAccessMode {
    SERVICE_ACCOUNT,
    DIRECT_PLAYGROUND_MEMBERSHIP,
    TENANT_MEMBERSHIP,
    SUPPORT_READ_ONLY,
    SUPPORT_WRITE_ENABLED;

    public boolean isSupport() {
        return this == SUPPORT_READ_ONLY || this == SUPPORT_WRITE_ENABLED;
    }

    public boolean permitsWrite() {
        return this != SUPPORT_READ_ONLY;
    }
}
