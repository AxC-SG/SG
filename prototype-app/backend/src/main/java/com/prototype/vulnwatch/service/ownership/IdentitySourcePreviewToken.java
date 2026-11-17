package com.prototype.vulnwatch.service.ownership;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import java.util.function.Function;

/**
 * The identity-source preview token (Phase 0B contract §1.6): bound to the source, its version, the scope hash and
 * the actor, and valid for {@link #TTL}. It is stateless, because a preview writes nothing: the token is a payload
 * plus an HMAC under the tenant key, so it cannot be forged or moved to another tenant, source or admin.
 */
final class IdentitySourcePreviewToken {

    static final Duration TTL = Duration.ofMinutes(30);
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private IdentitySourcePreviewToken() { }

    /** SHA-256 of the canonical scope JSON, hex-encoded. */
    static String scopeHash(String canonicalScopeJson) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonicalScopeJson.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    static String issue(Function<String, byte[]> mac, UUID sourceId, long version, String scopeHash, String actor, Instant expiresAt) {
        String payload = payload(sourceId, version, expiresAt.getEpochSecond(), scopeHash, actor);
        return ENCODER.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + ENCODER.encodeToString(mac.apply(payload));
    }

    /** True only for an untampered, unexpired token issued for exactly this source version, scope and actor. */
    static boolean valid(Function<String, byte[]> mac, String token, UUID sourceId, long version, String scopeHash, String actor,
                         Instant now) {
        if (token == null || token.length() > 2_048) return false;
        int dot = token.indexOf('.');
        if (dot <= 0 || dot != token.lastIndexOf('.')) return false;
        String payload;
        byte[] signature;
        try {
            payload = new String(DECODER.decode(token.substring(0, dot)), StandardCharsets.UTF_8);
            signature = DECODER.decode(token.substring(dot + 1));
        } catch (IllegalArgumentException malformed) {
            return false;
        }
        if (!MessageDigest.isEqual(mac.apply(payload), signature)) return false;
        String[] parts = payload.split("\\|", 5);
        if (parts.length != 5) return false;
        long expires;
        try {
            expires = Long.parseLong(parts[2]);
        } catch (NumberFormatException malformed) {
            return false;
        }
        return parts[0].equals(sourceId.toString()) && parts[1].equals(Long.toString(version)) && now.getEpochSecond() < expires
                && parts[3].equals(scopeHash) && parts[4].equals(actor);
    }

    private static String payload(UUID sourceId, long version, long expiresEpochSecond, String scopeHash, String actor) {
        return sourceId + "|" + version + "|" + expiresEpochSecond + "|" + scopeHash + "|" + actor;
    }
}
