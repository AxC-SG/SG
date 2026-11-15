package com.prototype.vulnwatch.service;

/** This binary requires the complete tenant schema through the ownership Release 2 schema in V24. */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=24;
    public static final int SUPPORTED_MAXIMUM=24;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
