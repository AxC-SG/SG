package com.prototype.vulnwatch.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Invitation digests are lookup keys; raw bearer values exist only during delivery. */
public final class InvitationTokens {
    private InvitationTokens() { }

    public static String hash(String token) {
        if (token == null || token.isBlank() || token.length() > 256) {
            throw new IllegalArgumentException("Invite token is invalid");
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }
}
