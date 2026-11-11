package com.prototype.vulnwatch.client.http;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@ConditionalOnProperty(name = "app.security.managed-auth.enabled", havingValue = "true")
public class CognitoBrowserIdentityClient {
    private static final Pattern ISSUER = Pattern.compile(
            "https://cognito-idp\\.([a-z0-9-]+)\\.amazonaws\\.com/\\1_[A-Za-z0-9]+");
    private static final Pattern HTTPS_ORIGIN = Pattern.compile("https://[a-z0-9.-]+");

    private final RestTemplate http;
    private final JwtDecoder idTokenDecoder;
    private final String issuer;
    private final String loginOrigin;
    private final String apiOrigin;
    private final String clientId;

    CognitoBrowserIdentityClient(
            RestTemplate http,
            @Value("${app.security.jwt.mode:LOCAL}") String mode,
            @Value("${app.security.jwt.issuer-uri:}") String issuer,
            @Value("${app.security.managed-auth.login-origin:}") String loginOrigin,
            @Value("${app.security.jwt.audience:}") String apiOrigin,
            @Value("${app.security.managed-auth.client-id:}") String clientId
    ) {
        var pool = ISSUER.matcher(issuer);
        if (!"EXTERNAL".equalsIgnoreCase(mode) || !pool.matches()
                || !loginOrigin.matches("https://[a-z0-9-]+\\.auth\\." + pool.group(1) + "\\.amazoncognito\\.com")
                || !HTTPS_ORIGIN.matcher(apiOrigin).matches() || !clientId.matches("[a-z0-9]{1,128}")) {
            throw new IllegalStateException("Managed sign-in requires EXTERNAL mode and the configured Cognito pool, domain, client and API origin.");
        }
        this.http = http;
        this.issuer = issuer;
        this.loginOrigin = loginOrigin;
        this.apiOrigin = apiOrigin;
        this.clientId = clientId;
        var decoder = NimbusJwtDecoder.withJwkSetUri(issuer + "/.well-known/jwks.json").restOperations(http).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        this.idTokenDecoder = decoder;
    }

    public String issuer() {
        return issuer;
    }

    public URI authorizationUri(String state, String nonce, String challenge) {
        return UriComponentsBuilder.fromUriString(loginOrigin + "/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("prompt", "login")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", callbackUri())
                .queryParam("scope", "openid email")
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge_method", "S256")
                .queryParam("code_challenge", challenge)
                .build().encode().toUri();
    }

    public Identity exchange(String code, String verifier, String nonce) {
        var body = new LinkedMultiValueMap<String, String>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", clientId);
        body.add("redirect_uri", callbackUri());
        body.add("code", code);
        body.add("code_verifier", verifier);
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        TokenResponse tokens;
        try {
            var response = http.postForEntity(URI.create(loginOrigin + "/oauth2/token"),
                    new HttpEntity<>(body, headers), TokenResponse.class);
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw providerUnavailable();
            }
            tokens = response.getBody();
        } catch (HttpClientErrorException rejected) {
            throw denied();
        } catch (RestClientException unavailable) {
            throw providerUnavailable();
        }
        if (tokens == null || tokens.idToken() == null || tokens.idToken().length() > 16384) {
            throw denied();
        }
        Jwt id;
        try {
            id = idTokenDecoder.decode(tokens.idToken());
        } catch (JwtException invalid) {
            throw denied();
        }
        if (!"id".equals(id.getClaimAsString("token_use")) || !List.of(clientId).equals(id.getAudience())
                || !nonce.equals(id.getClaimAsString("nonce")) || id.getSubject() == null
                || id.getSubject().isBlank() || id.getSubject().length() > 255
                || id.getExpiresAt() == null || !id.getExpiresAt().isAfter(Instant.now())) {
            throw denied();
        }
        String verifiedEmail = Boolean.TRUE.equals(id.getClaims().get("email_verified"))
                && id.getClaims().get("email") instanceof String email && !email.isBlank() && email.length() <= 255
                ? email : null;
        return new Identity(id.getSubject(), id.getExpiresAt(), verifiedEmail);
    }

    private String callbackUri() {
        return apiOrigin + "/api/auth/callback";
    }

    private static ResponseStatusException denied() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Managed sign-in was rejected");
    }

    private static ResponseStatusException providerUnavailable() {
        return new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Managed sign-in provider is unavailable");
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record TokenResponse(@JsonProperty("id_token") String idToken) { }
    public record Identity(String subject, Instant expiresAt, String verifiedEmail) { }
}
