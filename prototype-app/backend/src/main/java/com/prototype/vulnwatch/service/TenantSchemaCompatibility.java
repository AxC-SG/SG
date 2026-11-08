package com.prototype.vulnwatch.service;

/** This binary requires the complete tenant schema through durable BOM uploads. */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=20;
    public static final int SUPPORTED_MAXIMUM=20;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
