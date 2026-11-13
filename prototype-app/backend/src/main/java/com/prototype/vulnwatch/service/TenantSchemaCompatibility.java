package com.prototype.vulnwatch.service;

/** This binary requires the complete tenant schema through the ownership projection columns in V23. */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=23;
    public static final int SUPPORTED_MAXIMUM=23;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
