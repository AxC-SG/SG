package com.prototype.vulnwatch.client;

import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Production {@link GcpTokenSource}: signs a JWT with the customer's service account key and
 * exchanges it at Google's token endpoint (validated by {@link GcpServiceAccountKey} before the
 * key was stored). Credentials are cached by a digest of the key, so a rotated key gets new
 * credentials and the cache never holds the key text as a lookup value.
 */
@Component
public class GoogleGcpTokenSource implements GcpTokenSource {

    private static final List<String> SCOPES = List.of("https://www.googleapis.com/auth/cloud-platform");
    private static final int MAX_CACHED = 500;

    private final Map<String, GoogleCredentials> cache = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, GoogleCredentials> eldest) {
            return size() > MAX_CACHED;
        }
    };

    @Override
    public String token(String serviceAccountKeyJson) {
        GoogleCredentials credentials = credentials(serviceAccountKeyJson);
        try {
            credentials.refreshIfExpired();
            AccessToken token = credentials.getAccessToken();
            if (token == null || token.getTokenValue() == null) {
                throw new IllegalStateException("GCP returned no access token");
            }
            return token.getTokenValue();
        } catch (IOException failure) {
            throw new IllegalStateException("GCP rejected the service account key: " + failure.getMessage(), failure);
        }
    }

    private GoogleCredentials credentials(String keyJson) {
        String digest = digest(keyJson);
        synchronized (cache) {
            GoogleCredentials cached = cache.get(digest);
            if (cached != null) {
                return cached;
            }
            try {
                GoogleCredentials created = ServiceAccountCredentials
                        .fromStream(new ByteArrayInputStream(keyJson.getBytes(StandardCharsets.UTF_8)))
                        .createScoped(SCOPES);
                cache.put(digest, created);
                return created;
            } catch (IOException | RuntimeException unreadable) {
                throw new IllegalStateException("The stored GCP service account key could not be read", unreadable);
            }
        }
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
