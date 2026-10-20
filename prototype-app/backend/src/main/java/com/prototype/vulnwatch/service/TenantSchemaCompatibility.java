package com.prototype.vulnwatch.service;

/** This binary needs V4 ownership columns and the V5 bounded retention progress table. */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=5;
    public static final int SUPPORTED_MAXIMUM=5;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
