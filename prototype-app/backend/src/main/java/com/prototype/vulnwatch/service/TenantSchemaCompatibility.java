package com.prototype.vulnwatch.service;

/** This binary requires the tenant schema through the incremental inventory correlation cutover. */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=77;
    public static final int SUPPORTED_MAXIMUM=77;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
