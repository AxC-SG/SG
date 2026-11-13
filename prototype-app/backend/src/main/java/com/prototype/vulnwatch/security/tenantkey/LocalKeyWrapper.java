package com.prototype.vulnwatch.security.tenantkey;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Local/test-only key wrapper: AES-256-GCM under a configured master key with the key context as
 * AAD. It refuses to start outside {@code APP_ENVIRONMENT=local|test}, so a deployed runtime can
 * only wrap tenant keys with a real KMS.
 */
public final class LocalKeyWrapper implements KeyWrapper {

    static final String KIND = "LOCAL";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKeySpec masterKey;
    private final String keyRef;
    private final SecureRandom random = new SecureRandom();

    public LocalKeyWrapper(String environment, String base64MasterKey) {
        String env = environment == null ? "" : environment.trim().toLowerCase(Locale.ROOT);
        if (!Set.of("local", "test").contains(env)) {
            throw new IllegalStateException("The local tenant key wrapper is only allowed when APP_ENVIRONMENT is local or test.");
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64MasterKey == null ? "" : base64MasterKey.trim());
        } catch (IllegalArgumentException ex) {
            decoded = new byte[0];
        }
        if (decoded.length != 32) {
            throw new IllegalStateException("The local tenant key wrapper needs a base64-encoded 256-bit master key.");
        }
        masterKey = new SecretKeySpec(decoded, "AES");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(decoded);
            keyRef = "local:" + HexFormat.of().formatHex(digest, 0, 8);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    @Override
    public String kind() {
        return KIND;
    }

    @Override
    public String activeKeyRef() {
        return keyRef;
    }

    @Override
    public byte[] wrap(byte[] plaintextKey, KeyContext context) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(context.aad());
            byte[] ct = cipher.doFinal(plaintextKey);
            return ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
        } catch (GeneralSecurityException ex) {
            throw new TenantKeyUnavailableException(TenantKeyUnavailableException.Reason.WRAPPER_UNAVAILABLE, "Tenant key wrap failed", ex);
        }
    }

    @Override
    public byte[] unwrap(byte[] wrappedKey, String ref, KeyContext context) {
        if (!keyRef.equals(ref)) {
            throw new TenantKeyUnavailableException(TenantKeyUnavailableException.Reason.WRAPPER_UNAVAILABLE,
                    "Tenant key was wrapped by a different local master key");
        }
        try {
            if (wrappedKey.length <= IV_BYTES) throw new GeneralSecurityException("short");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, wrappedKey, 0, IV_BYTES));
            cipher.updateAAD(context.aad());
            return cipher.doFinal(wrappedKey, IV_BYTES, wrappedKey.length - IV_BYTES);
        } catch (GeneralSecurityException ex) {
            throw new TenantKeyUnavailableException(TenantKeyUnavailableException.Reason.WRAPPER_UNAVAILABLE, "Tenant key unwrap failed", ex);
        }
    }
}
