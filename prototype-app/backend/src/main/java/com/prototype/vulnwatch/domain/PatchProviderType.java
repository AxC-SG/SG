package com.prototype.vulnwatch.domain;

import java.util.Locale;

/** Patch management tools Fix Intelligence imports from. */
public enum PatchProviderType {
    SCCM("SCCM/MECM"),
    INTUNE("Microsoft Intune"),
    BIGFIX("BigFix"),
    TANIUM("Tanium");

    private final String displayName;

    PatchProviderType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }

    /** Sync run type, e.g. PATCH_SCCM; one active run per tenant per provider. */
    public String syncType() {
        return "PATCH_" + name();
    }

    public static PatchProviderType parse(String value) {
        try {
            return PatchProviderType.valueOf(value == null ? "" : value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            throw new IllegalArgumentException("Unknown patch provider: " + value);
        }
    }
}
