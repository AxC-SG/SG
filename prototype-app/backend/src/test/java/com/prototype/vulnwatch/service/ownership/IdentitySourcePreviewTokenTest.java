package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.function.Function;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class IdentitySourcePreviewTokenTest {

    private static final UUID SOURCE = UUID.randomUUID();
    private static final String SCOPE = IdentitySourcePreviewToken.scopeHash("{\"instanceUrl\":\"https://acme.service-now.com\"}");
    private static final Instant NOW = Instant.parse("2026-11-16T09:00:00Z");
    private static final Instant EXPIRES = NOW.plus(IdentitySourcePreviewToken.TTL);
    private final Function<String, byte[]> mac = hmac("tenant-a");
    private final String token = IdentitySourcePreviewToken.issue(mac, SOURCE, 3, SCOPE, "admin-1", EXPIRES);

    @Test
    void aTokenIsValidOnlyForItsSourceVersionScopeAndActorUntilItExpires() {
        assertThat(valid(token, SOURCE, 3, SCOPE, "admin-1", NOW)).isTrue();
        assertThat(valid(token, SOURCE, 3, SCOPE, "admin-1", EXPIRES.minusSeconds(1))).isTrue();
        assertThat(valid(token, SOURCE, 3, SCOPE, "admin-1", EXPIRES)).isFalse();
        assertThat(valid(token, UUID.randomUUID(), 3, SCOPE, "admin-1", NOW)).isFalse();
        assertThat(valid(token, SOURCE, 4, SCOPE, "admin-1", NOW)).isFalse();
        assertThat(valid(token, SOURCE, 3, IdentitySourcePreviewToken.scopeHash("{}"), "admin-1", NOW)).isFalse();
        assertThat(valid(token, SOURCE, 3, SCOPE, "admin-2", NOW)).isFalse();
    }

    @Test
    void aTokenFromAnotherTenantKeyOrAlteredInAnyWayIsRejected() {
        assertThat(IdentitySourcePreviewToken.valid(hmac("tenant-b"), token, SOURCE, 3, SCOPE, "admin-1", NOW)).isFalse();

        String[] parts = token.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String longer = payload.replace("|" + EXPIRES.getEpochSecond() + "|", "|" + EXPIRES.plusSeconds(86_400).getEpochSecond() + "|");
        String forged = Base64.getUrlEncoder().withoutPadding().encodeToString(longer.getBytes(StandardCharsets.UTF_8)) + "." + parts[1];
        assertThat(valid(forged, SOURCE, 3, SCOPE, "admin-1", NOW)).isFalse();
        assertThat(valid(parts[0] + ".AAAA", SOURCE, 3, SCOPE, "admin-1", NOW)).isFalse();
        for (String garbage : new String[] {null, "", ".", "abc", "a.b.c", "!!!.???", "x".repeat(3_000)}) {
            assertThat(valid(garbage, SOURCE, 3, SCOPE, "admin-1", NOW)).as(String.valueOf(garbage)).isFalse();
        }
    }

    @Test
    void anActorContainingTheSeparatorStillBindsExactly() {
        String odd = IdentitySourcePreviewToken.issue(mac, SOURCE, 3, SCOPE, "a|b", EXPIRES);
        assertThat(valid(odd, SOURCE, 3, SCOPE, "a|b", NOW)).isTrue();
        assertThat(valid(odd, SOURCE, 3, SCOPE, "a", NOW)).isFalse();
    }

    private boolean valid(String candidate, UUID source, long version, String scope, String actor, Instant now) {
        return IdentitySourcePreviewToken.valid(mac, candidate, source, version, scope, actor, now);
    }

    private static Function<String, byte[]> hmac(String key) {
        return payload -> {
            try {
                Mac m = Mac.getInstance("HmacSHA256");
                m.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
                return m.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        };
    }
}
