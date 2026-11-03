package com.prototype.vulnwatch.service;

/** This binary requires the complete tenant schema through the CBOM CI gates in V19. */
public final class TenantSchemaCompatibility {
    public static final int REQUIRED_MINIMUM=19;
    public static final int SUPPORTED_MAXIMUM=19;
    private TenantSchemaCompatibility() { }
    public static boolean supports(int version,int configuredMinimum,int configuredMaximum) {
        return version>=Math.max(REQUIRED_MINIMUM,configuredMinimum) && version<=Math.min(SUPPORTED_MAXIMUM,configuredMaximum);
    }
}
