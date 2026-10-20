package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CredentialEncryptionServiceTest {

    private static final String TEST_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static final String OTHER_TEST_KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    @Test
    void encryptsAndDecryptsCredential() {
        CredentialEncryptionService service = new CredentialEncryptionService(TEST_KEY);

        String encrypted = service.encrypt("super-secret-token");

        assertTrue(service.isEncrypted(encrypted));
        assertNotEquals("super-secret-token", encrypted);
        assertEquals("super-secret-token", service.decrypt(encrypted));
    }

    @Test
    void encryptionIsNonDeterministic() {
        CredentialEncryptionService service = new CredentialEncryptionService(TEST_KEY);

        assertNotEquals(service.encrypt("same-secret"), service.encrypt("same-secret"));
    }

    @Test
    void decryptRejectsLegacyPlaintextUntilExplicitMigration() {
        CredentialEncryptionService service = new CredentialEncryptionService(TEST_KEY);

        assertFalse(service.isEncrypted("legacy-secret"));
        assertThrows(CredentialEncryptionService.CredentialDecryptionException.class, () -> service.decrypt("legacy-secret"));
    }

    @Test
    void rejectsNon256BitKey() {
        assertThrows(IllegalStateException.class, () -> new CredentialEncryptionService("AAAA"));
    }

    @Test
    void explainsHowToRecoverWhenCiphertextUsesAnotherKey() {
        String ciphertext = new CredentialEncryptionService(TEST_KEY).encrypt("super-secret-token");

        CredentialEncryptionService.CredentialDecryptionException exception = assertThrows(
                CredentialEncryptionService.CredentialDecryptionException.class,
                () -> new CredentialEncryptionService(OTHER_TEST_KEY).decrypt(ciphertext));

        assertEquals(
                "Encrypted credential cannot be decrypted. "
                        + "Restore the original APP_CREDENTIAL_ENCRYPTION_KEY or replace the credential profile.",
                exception.getMessage());
    }
    @Test
    void rotatesKeysAndRestoresOldBackupsWithoutPlaintextFallback() {
        CredentialEncryptionService old = new CredentialEncryptionService(TEST_KEY, "first", "");
        String original = old.encrypt("tenant-secret");
        CredentialEncryptionService rotated = new CredentialEncryptionService(OTHER_TEST_KEY, "second", "first=" + TEST_KEY);
        assertEquals("tenant-secret", rotated.decrypt(original));
        assertTrue(rotated.encrypt("new-secret").startsWith("enc:v2:second:"));
        assertThrows(CredentialEncryptionService.CredentialDecryptionException.class,
                () -> new CredentialEncryptionService(OTHER_TEST_KEY, "second", "").decrypt(original));
    }

    @Test
    void envelopeHeaderIsAuthenticatedAndEnvelopeShapedInputIsEncrypted() {
        CredentialEncryptionService service = new CredentialEncryptionService(TEST_KEY, "first", "second=" + TEST_KEY);
        String original = service.encrypt("secret");
        assertThrows(CredentialEncryptionService.CredentialDecryptionException.class,
                () -> service.decrypt(original.replace("v2:first:", "v2:second:")));
        assertEquals(original, service.decrypt(service.encrypt(original)));
    }

    @Test
    void restoresUnversionedLegacyCiphertextWithRetainedLegacyKey() throws Exception {
        byte[] iv = new byte[12];
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(java.util.Base64.getDecoder().decode(TEST_KEY), "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal("legacy-tenant-secret".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String stored = "enc:v1:" + java.util.Base64.getEncoder().encodeToString(
                java.nio.ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array());
        CredentialEncryptionService service = new CredentialEncryptionService(OTHER_TEST_KEY, "rotated", "legacy=" + TEST_KEY);
        assertEquals("legacy-tenant-secret", service.decrypt(stored));
    }

}
