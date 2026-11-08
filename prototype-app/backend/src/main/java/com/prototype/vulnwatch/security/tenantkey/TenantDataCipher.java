package com.prototype.vulnwatch.security.tenantkey;

import java.util.UUID;

/**
 * Tenant-scoped field encryption for PII and connector secrets.
 *
 * <p>Ciphertext format: {@code enc:t1:<tenantKeyVersion>:<base64(iv || ciphertext+tag)>} with AAD
 * {@code tenantId|purpose|tenantKeyVersion}, so a value copied to another tenant, purpose or column
 * fails authentication. ({@code enc:v1:}/{@code enc:v2:} stay owned by the platform-key
 * {@code CredentialEncryptionService}.)
 */
public interface TenantDataCipher {

    String PREFIX = "enc:t1:";

    String encrypt(UUID tenantId, String purpose, String plaintext);

    String decrypt(UUID tenantId, String purpose, String ciphertext);

    /**
     * Deterministic HMAC-SHA256 of an already-normalized value for exact-match lookup. The index key
     * is derived from the tenant's first key version so indexes stay valid across DEK rotation.
     */
    byte[] blindIndex(UUID tenantId, String purpose, String normalizedValue);

    /** Key version a ciphertext was written under, or -1 when it is not tenant ciphertext. */
    int keyVersionOf(String value);

    /** Live readiness check; PII writers and identity-source enablement must call this first. */
    TenantKeyRegistry.Readiness readiness(UUID tenantId);

    static boolean isTenantCiphertext(String value) {
        return value != null && value.startsWith(PREFIX);
    }
}
