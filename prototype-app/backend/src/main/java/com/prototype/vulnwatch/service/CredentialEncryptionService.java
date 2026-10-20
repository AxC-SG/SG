package com.prototype.vulnwatch.service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CredentialEncryptionService {

    private static final String LEGACY_PREFIX = "enc:v1:";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final String DECRYPTION_FAILURE = "Encrypted credential cannot be decrypted. "
            + "Restore the original APP_CREDENTIAL_ENCRYPTION_KEY or replace the credential profile.";

    private final String activeKeyId;
    private final Map<String, SecretKeySpec> keys;
    private final SecretKeySpec legacyKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public CredentialEncryptionService(String base64Key) {
        this(base64Key, "primary", "");
    }

    @Autowired
    public CredentialEncryptionService(
            @Value("${app.security.credential-encryption-key}") String base64Key,
            @Value("${app.security.credential-encryption-key-id:primary}") String keyId,
            @Value("${app.security.credential-encryption-previous-keys:}") String previousKeys) {
        activeKeyId = validateKeyId(keyId);
        Map<String, SecretKeySpec> configured = new HashMap<>();
        configured.put(activeKeyId, key(base64Key));
        if (previousKeys != null && !previousKeys.isBlank()) {
            for (String entry : previousKeys.split(",")) {
                int separator = entry.indexOf('=');
                if (separator < 1) throw new IllegalStateException("Invalid credential decryption key configuration");
                String previousId = validateKeyId(entry.substring(0, separator).trim());
                if (configured.putIfAbsent(previousId, key(entry.substring(separator + 1).trim())) != null) {
                    throw new IllegalStateException("Duplicate credential encryption key version");
                }
            }
        }
        keys = Map.copyOf(configured);
        legacyKey = keys.getOrDefault("legacy", keys.get(activeKeyId));
    }

    public String encrypt(String plaintext) {
        if (!hasText(plaintext)) {
            return plaintext;
        }
        try {
            byte[] iv = new byte[IV_BYTES];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            String prefix = "enc:v2:" + activeKeyId + ":";
            cipher.init(Cipher.ENCRYPT_MODE, keys.get(activeKeyId), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(prefix.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            ByteBuffer envelope = ByteBuffer.allocate(iv.length + ciphertext.length);
            envelope.put(iv);
            envelope.put(ciphertext);
            return prefix + Base64.getEncoder().encodeToString(envelope.array());
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Failed to encrypt credential", ex);
        }
    }

    public String decrypt(String storedValue) {
        if (!hasText(storedValue)) {
            return storedValue;
        }
        try {
            boolean legacy = storedValue.startsWith(LEGACY_PREFIX);
            String prefix;
            SecretKeySpec selected;
            if (legacy) {
                prefix = LEGACY_PREFIX;
                selected = legacyKey;
            } else if (storedValue.startsWith("enc:v2:")) {
                int separator = storedValue.indexOf(':', 7);
                if (separator < 0) throw new CredentialDecryptionException(DECRYPTION_FAILURE);
                prefix = storedValue.substring(0, separator + 1);
                selected = keys.get(storedValue.substring(7, separator));
                if (selected == null) throw new CredentialDecryptionException(DECRYPTION_FAILURE);
            } else {
                throw new CredentialDecryptionException("Legacy plaintext credential requires the bounded provider credential migration before use.");
            }
            byte[] envelope = Base64.getDecoder().decode(storedValue.substring(prefix.length()));
            if (envelope.length < IV_BYTES + TAG_BITS / 8) {
                throw new CredentialDecryptionException(DECRYPTION_FAILURE);
            }
            ByteBuffer buffer = ByteBuffer.wrap(envelope);
            byte[] iv = new byte[IV_BYTES];
            buffer.get(iv);
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, selected, new GCMParameterSpec(TAG_BITS, iv));
            if (!legacy) cipher.updateAAD(prefix.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new CredentialDecryptionException(DECRYPTION_FAILURE, ex);
        }
    }

    public boolean isEncrypted(String value) {
        return value != null && (value.startsWith(LEGACY_PREFIX) || value.startsWith("enc:v2:"));
    }

    public boolean usesActiveKey(String value) {
        return value != null && value.startsWith("enc:v2:" + activeKeyId + ":");
    }

    private static String validateKeyId(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalStateException("Invalid credential encryption key version");
        }
        return value;
    }

    private static SecretKeySpec key(String encoded) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (decoded.length != 32) throw new IllegalArgumentException();
            return new SecretKeySpec(decoded, "AES");
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Credential encryption keys must be base64-encoded 256-bit keys");
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    /** Signals that an encrypted value cannot be opened with the configured key. */
    public static final class CredentialDecryptionException extends IllegalStateException {
        public CredentialDecryptionException(String message) {
            super(message);
        }

        public CredentialDecryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
