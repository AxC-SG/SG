package com.prototype.vulnwatch.security.tenantkey;

import com.prototype.vulnwatch.security.tenantkey.TenantKeyUnavailableException.Reason;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-256-GCM implementation of {@link TenantDataCipher} over {@link TenantKeyRegistry} keys. */
public class AesGcmTenantDataCipher implements TenantDataCipher {

    private static final Pattern PURPOSE = Pattern.compile("[a-z0-9._-]{1,64}");
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int INDEX_KEY_VERSION = 1;

    private final TenantKeyRegistry registry;
    private final SecureRandom random = new SecureRandom();

    public AesGcmTenantDataCipher(TenantKeyRegistry registry) {
        this.registry = registry;
    }

    @Override
    public String encrypt(UUID tenantId, String purpose, String plaintext) {
        Objects.requireNonNull(tenantId, "tenantId");
        checkPurpose(purpose);
        if (plaintext == null) return null;
        TenantKeyRegistry.ActiveKey active = registry.activeKey(tenantId);
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(active.key(), "AES"), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad(tenantId, purpose, active.version()));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] envelope = ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
            return PREFIX + active.version() + ":" + Base64.getEncoder().encodeToString(envelope);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Tenant field encryption failed", ex);
        } finally {
            Arrays.fill(active.key(), (byte) 0);
        }
    }

    @Override
    public String decrypt(UUID tenantId, String purpose, String ciphertext) {
        Objects.requireNonNull(tenantId, "tenantId");
        checkPurpose(purpose);
        if (ciphertext == null) return null;
        int version = keyVersionOf(ciphertext);
        if (version < 1) throw invalid(null);
        byte[] envelope;
        try {
            envelope = Base64.getDecoder().decode(ciphertext.substring(ciphertext.indexOf(':', PREFIX.length()) + 1));
        } catch (IllegalArgumentException ex) {
            throw invalid(ex);
        }
        if (envelope.length < IV_BYTES + TAG_BITS / 8) throw invalid(null);
        byte[] key = registry.key(tenantId, version);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, envelope, 0, IV_BYTES));
            cipher.updateAAD(aad(tenantId, purpose, version));
            return new String(cipher.doFinal(envelope, IV_BYTES, envelope.length - IV_BYTES), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException ex) {
            throw invalid(ex);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    @Override
    public byte[] blindIndex(UUID tenantId, String purpose, String normalizedValue) {
        Objects.requireNonNull(tenantId, "tenantId");
        checkPurpose(purpose);
        Objects.requireNonNull(normalizedValue, "normalizedValue");
        byte[] root = registry.key(tenantId, INDEX_KEY_VERSION);
        byte[] indexKey = null;
        try {
            indexKey = hmac(root, ("blind-index|" + tenantId + "|" + purpose).getBytes(StandardCharsets.UTF_8));
            return hmac(indexKey, normalizedValue.getBytes(StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(root, (byte) 0);
            if (indexKey != null) Arrays.fill(indexKey, (byte) 0);
        }
    }

    @Override
    public int keyVersionOf(String value) {
        if (!TenantDataCipher.isTenantCiphertext(value)) return -1;
        int end = value.indexOf(':', PREFIX.length());
        if (end <= PREFIX.length() || end - PREFIX.length() > 9) return -1;
        try {
            int version = Integer.parseInt(value.substring(PREFIX.length(), end));
            return version > 0 ? version : -1;
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    @Override
    public TenantKeyRegistry.Readiness readiness(UUID tenantId) {
        return registry.readiness(tenantId);
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", ex);
        }
    }

    private static byte[] aad(UUID tenantId, String purpose, int version) {
        return (tenantId + "|" + purpose + "|" + version).getBytes(StandardCharsets.UTF_8);
    }

    private static void checkPurpose(String purpose) {
        if (purpose == null || !PURPOSE.matcher(purpose).matches()) {
            throw new IllegalArgumentException("Invalid encryption purpose");
        }
    }

    private static TenantKeyUnavailableException invalid(Throwable cause) {
        return new TenantKeyUnavailableException(Reason.INVALID_CIPHERTEXT, "Tenant ciphertext cannot be decrypted", cause);
    }
}
