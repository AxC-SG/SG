package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * A customer-supplied GCP service account key, validated before it is stored or used.
 *
 * <p>A key file is more than a credential: Google's auth library follows the {@code token_uri}
 * inside it, and other credential types ({@code external_account}) name arbitrary URLs and local
 * files. So only a plain {@code service_account} key is accepted, and only with Google's own
 * token endpoint — otherwise a tenant could make the backend send signed requests to an address
 * of its choosing.
 */
public record GcpServiceAccountKey(String clientEmail, String projectId) {

    static final int MAX_KEY_BYTES = 16 * 1024;
    static final String GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token";

    private static final Pattern PROJECT_ID = Pattern.compile("^[a-z][a-z0-9-]{4,28}[a-z0-9]$");
    private static final Pattern SERVICE_ACCOUNT_EMAIL =
            Pattern.compile("^[a-z0-9][a-z0-9._-]{0,99}@[a-z0-9.-]+\\.gserviceaccount\\.com$");

    /**
     * @throws IllegalArgumentException with an operator-facing reason that never echoes the key
     */
    public static GcpServiceAccountKey parse(String json, ObjectMapper objectMapper) {
        if (json == null || json.isBlank()) {
            throw new IllegalArgumentException("A GCP service account key (JSON) is required");
        }
        if (json.length() > MAX_KEY_BYTES) {
            throw new IllegalArgumentException("The GCP service account key is too large");
        }
        JsonNode key;
        try {
            key = objectMapper.readTree(json);
        } catch (Exception malformed) {
            throw new IllegalArgumentException("The GCP service account key is not valid JSON");
        }
        if (key == null || !key.isObject() || !"service_account".equals(key.path("type").asText())) {
            throw new IllegalArgumentException(
                    "Only a service account key (\"type\": \"service_account\") is supported");
        }
        String email = key.path("client_email").asText("").trim().toLowerCase(Locale.ROOT);
        if (!SERVICE_ACCOUNT_EMAIL.matcher(email).matches()) {
            throw new IllegalArgumentException("The key has no valid service account client_email");
        }
        String privateKey = key.path("private_key").asText("");
        if (!privateKey.contains("-----BEGIN PRIVATE KEY-----") || key.path("private_key_id").asText("").isBlank()) {
            throw new IllegalArgumentException("The key has no private key; download a new JSON key for the service account");
        }
        String tokenUri = key.path("token_uri").asText("");
        if (!tokenUri.isEmpty() && !GOOGLE_TOKEN_URI.equals(tokenUri)) {
            throw new IllegalArgumentException("The key's token_uri must be " + GOOGLE_TOKEN_URI);
        }
        String universe = key.path("universe_domain").asText("");
        if (!universe.isEmpty() && !"googleapis.com".equals(universe)) {
            throw new IllegalArgumentException("Only the googleapis.com universe is supported");
        }
        String project = key.path("project_id").asText("").trim();
        return new GcpServiceAccountKey(email, PROJECT_ID.matcher(project).matches() ? project : null);
    }

    /** Normalizes and validates a customer project id. */
    public static String projectId(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (!PROJECT_ID.matcher(normalized).matches()) {
            throw new IllegalArgumentException(
                    "GCP project ID must be 6-30 characters: lowercase letters, digits and hyphens, starting with a letter");
        }
        return normalized;
    }
}
