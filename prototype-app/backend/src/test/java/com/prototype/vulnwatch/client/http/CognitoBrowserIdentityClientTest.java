package com.prototype.vulnwatch.client.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

class CognitoBrowserIdentityClientTest {
    private static final String ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_testpool";
    private static final String LOGIN = "https://testpool.auth.us-east-1.amazoncognito.com";
    private static final String API = "https://api.example.test";
    private static final String SUBJECT = "e647837d-8f24-47d4-b8c8-9b8c7d938b0b";

    @Test
    void redirectsWithCodeGrantAndS256AndExchangesUsingBoundVerifier() throws Exception {
        var identity = exchange("browserclient", "expected-nonce", "id", true);
        assertEquals(SUBJECT, identity.subject());
        assertEquals("fixture@example.test", identity.verifiedEmail());
    }

    @Test
    void unverifiedEmailIsUnavailableForInvitationLinking() throws Exception {
        var identity = exchange("browserclient", "expected-nonce", "id", false);
        assertEquals(SUBJECT, identity.subject());
        assertNull(identity.verifiedEmail());
    }

    @ParameterizedTest
    @CsvSource({
            "browserclient,wrong-nonce,id",
            "otherclient,expected-nonce,id",
            "browserclient,expected-nonce,access"
    })
    void rejectsIncorrectNonceAudienceAndTokenUse(String audience, String nonce, String tokenUse) {
        assertEquals(HttpStatus.UNAUTHORIZED, assertThrows(ResponseStatusException.class,
                () -> exchange(audience, nonce, tokenUse, true)).getStatusCode());
    }

    @Test
    void requiresExternalModeAndCognitoLoginHostInSameRegion() {
        assertThrows(IllegalStateException.class,
                () -> new CognitoBrowserIdentityClient(new RestTemplate(), "LOCAL", ISSUER, LOGIN, API, "browserclient"));
        assertThrows(IllegalStateException.class,
                () -> new CognitoBrowserIdentityClient(new RestTemplate(), "EXTERNAL", ISSUER,
                        "https://testpool.auth.us-west-2.amazoncognito.com", API, "browserclient"));
    }

    private CognitoBrowserIdentityClient.Identity exchange(String audience, String nonce, String tokenUse, boolean verifiedEmail) throws Exception {
        var http = new RestTemplate();
        var provider = new CognitoBrowserIdentityClient(http, "EXTERNAL", ISSUER, LOGIN, API, "browserclient");
        var authorization = UriComponentsBuilder.fromUri(provider.authorizationUri("state", "expected-nonce", "challenge"))
                .build().getQueryParams();
        assertEquals("code", authorization.getFirst("response_type"));
        assertEquals("openid%20email", authorization.getFirst("scope"));
        assertEquals("login", authorization.getFirst("prompt"));
        assertEquals("S256", authorization.getFirst("code_challenge_method"));
        assertEquals("challenge", authorization.getFirst("code_challenge"));
        assertEquals("state", authorization.getFirst("state"));
        assertEquals("expected-nonce", authorization.getFirst("nonce"));

        var key = new RSAKeyGenerator(2048).keyID("fixture-key").generate();
        var token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().issuer(ISSUER).subject(SUBJECT).audience(audience)
                        .issueTime(Date.from(Instant.now())).expirationTime(Date.from(Instant.now().plusSeconds(600)))
                        .claim("nonce", nonce).claim("token_use", tokenUse)
                        .claim("email", "fixture@example.test").claim("email_verified", verifiedEmail).build());
        token.sign(new RSASSASigner(key));

        var form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", "browserclient");
        form.add("redirect_uri", API + "/api/auth/callback");
        form.add("code", "fixture-code");
        form.add("code_verifier", "bound-verifier");
        var server = MockRestServiceServer.bindTo(http).build();
        server.expect(requestTo(LOGIN + "/oauth2/token")).andExpect(method(HttpMethod.POST))
                .andExpect(content().formData(form))
                .andRespond(withSuccess("{\"id_token\":\"" + token.serialize() + "\",\"token_type\":\"Bearer\"}",
                        MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER + "/.well-known/jwks.json"))
                .andRespond(withSuccess(new JWKSet(key.toPublicJWK()).toString(), MediaType.APPLICATION_JSON));
        try {
            return provider.exchange("fixture-code", "bound-verifier", "expected-nonce");
        } finally {
            server.verify();
        }
    }
}
