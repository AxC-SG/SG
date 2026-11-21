package com.prototype.vulnwatch.service;

/** This binary requires the tenant schema through tenant-scoped inventory rollups. */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=80;
    public static final int SUPPORTED_MAXIMUM=80;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
