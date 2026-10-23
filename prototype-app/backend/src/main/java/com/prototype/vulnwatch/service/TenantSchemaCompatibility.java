package com.prototype.vulnwatch.service;

/** This binary needs V6 intelligence eligibility and revision columns. */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=6;
    public static final int SUPPORTED_MAXIMUM=6;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
