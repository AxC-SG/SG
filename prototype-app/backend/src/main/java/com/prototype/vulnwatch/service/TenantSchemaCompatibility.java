package com.prototype.vulnwatch.service;

/** This binary needs V9 Fix Intelligence and patch management tables (on top of V8 GCP discovery, V7 ticketing and V6 intelligence eligibility). */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=9;
    public static final int SUPPORTED_MAXIMUM=9;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
