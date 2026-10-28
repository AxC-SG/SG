package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GcpServiceAccountKeyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static String key(String overrides) {
        return "{\"type\":\"service_account\",\"project_id\":\"acme-prod\",\"private_key_id\":\"abc123\","
                + "\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIfake\\n-----END PRIVATE KEY-----\\n\","
                + "\"client_email\":\"scout-reader@acme-prod.iam.gserviceaccount.com\","
                + "\"token_uri\":\"https://oauth2.googleapis.com/token\"" + overrides + "}";
    }

    @Test
    void acceptsAStandardServiceAccountKeyAndReadsItsIdentity() {
        GcpServiceAccountKey parsed = GcpServiceAccountKey.parse(key(""), MAPPER);

        assertEquals("scout-reader@acme-prod.iam.gserviceaccount.com", parsed.clientEmail());
        assertEquals("acme-prod", parsed.projectId());
    }

    @Test
    void aKeyWithoutAProjectIsStillAcceptedButNamesNoProject() {
        assertNull(GcpServiceAccountKey.parse(key("").replace("\"project_id\":\"acme-prod\",", ""), MAPPER).projectId());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            ",\"token_uri\":\"http://169.254.169.254/token\"",
            ",\"universe_domain\":\"evil.example\""
    })
    void refusesKeysThatWouldSendTheSignedRequestSomewhereElse(String override) {
        String json = key("").replace(",\"token_uri\":\"https://oauth2.googleapis.com/token\"", "") .replace("}", override + "}");
        assertThrows(IllegalArgumentException.class, () -> GcpServiceAccountKey.parse(json, MAPPER));
    }

    @Test
    void refusesOtherCredentialTypesThatCanNameArbitraryUrlsOrFiles() {
        String external = "{\"type\":\"external_account\",\"credential_source\":{\"file\":\"/etc/passwd\"}}";
        var error = assertThrows(IllegalArgumentException.class, () -> GcpServiceAccountKey.parse(external, MAPPER));
        assertFalse(error.getMessage().contains("/etc/passwd"), "errors never echo key content");
    }

    @Test
    void refusesMalformedOrIncompleteKeys() {
        assertThrows(IllegalArgumentException.class, () -> GcpServiceAccountKey.parse("", MAPPER));
        assertThrows(IllegalArgumentException.class, () -> GcpServiceAccountKey.parse("not json", MAPPER));
        assertThrows(IllegalArgumentException.class, () -> GcpServiceAccountKey.parse(key("").replace("BEGIN PRIVATE KEY", "nothing"), MAPPER));
        assertThrows(IllegalArgumentException.class, () -> GcpServiceAccountKey.parse(key("").replace("iam.gserviceaccount.com", "example.com"), MAPPER));
        assertThrows(IllegalArgumentException.class, () -> GcpServiceAccountKey.parse("{" + "\"a\":\"" + "x".repeat(20000) + "\"}", MAPPER));
    }

    @Test
    void projectIdsAreNormalized() {
        assertEquals("my-project-123", GcpServiceAccountKey.projectId("  My-Project-123 "));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "short", "1starts-with-digit", "ends-with-hyphen-", "has_underscore",
            "projects/other", "this-project-id-is-far-too-long-for-gcp", "a/../b"})
    void invalidProjectIdsAreRejected(String value) {
        assertThrows(IllegalArgumentException.class, () -> GcpServiceAccountKey.projectId(value));
    }
}
