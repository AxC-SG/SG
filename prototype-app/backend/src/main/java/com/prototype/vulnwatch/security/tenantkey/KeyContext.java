package com.prototype.vulnwatch.security.tenantkey;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Encryption context bound to a wrapped tenant key. */
public record KeyContext(UUID tenantId, int keyVersion) {

    public static final String PURPOSE = "tenant-data-key";

    public KeyContext {
        Objects.requireNonNull(tenantId, "tenantId");
        if (keyVersion < 1) throw new IllegalArgumentException("keyVersion must be positive");
    }

    /** Context map in the shape KMS encryption contexts expect. */
    public Map<String, String> asMap() {
        return Map.of("tenantId", tenantId.toString(), "purpose", PURPOSE, "keyVersion", Integer.toString(keyVersion));
    }

    byte[] aad() {
        return (tenantId + "|" + PURPOSE + "|" + keyVersion).getBytes(StandardCharsets.UTF_8);
    }
}
