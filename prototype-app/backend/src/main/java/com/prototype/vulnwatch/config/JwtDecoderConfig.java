package com.prototype.vulnwatch.config;

import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;

@Configuration
public class JwtDecoderConfig {

    @Bean
    @ConditionalOnExpression("'${app.security.jwt.issuer-uri:}' != '' || '${app.security.jwt.jwk-set-uri:}' != '' || '${app.security.jwt.hmac-secret:}' != ''")
    public JwtDecoder jwtDecoder(
            @Value("${app.security.jwt.issuer-uri:}") String issuerUri,
            @Value("${app.security.jwt.jwk-set-uri:}") String jwkSetUri,
            @Value("${app.security.jwt.hmac-secret:}") String hmacSecret,
            @Value("${app.security.jwt.audience:scoutgrid-api}") String audience,
            @Value("${app.security.jwt.mode:LOCAL}") String mode,
            @Value("${app.security.jwt.local-issuer:urn:scoutgrid:local}") String localIssuer
    ) {
        if (!hasText(audience)) {
            throw new IllegalStateException("JWT audience must be configured.");
        }
        if ("LOCAL".equalsIgnoreCase(mode)) {
            if (hasText(issuerUri) || hasText(jwkSetUri) || !hasText(localIssuer)
                    || hmacSecret == null || hmacSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < 32) {
                throw new IllegalStateException("LOCAL JWT mode requires a 32-byte HMAC secret and local issuer, without external issuer/JWK settings.");
            }
            SecretKeySpec key = new SecretKeySpec(hmacSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256");
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
            configureAudienceValidator(decoder, localIssuer.trim(), audience);
            return decoder;
        }
        if (!"EXTERNAL".equalsIgnoreCase(mode) || !hasText(issuerUri) || hasText(hmacSecret)) {
            throw new IllegalStateException("EXTERNAL JWT mode requires an issuer URI and no local HMAC secret.");
        }
        if (!hasText(jwkSetUri)) {
            NimbusJwtDecoder decoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri.trim());
            configureAudienceValidator(decoder, issuerUri.trim(), audience);
            return decoder;
        }
        if (hasText(jwkSetUri)) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri.trim()).build();
            configureAudienceValidator(decoder, issuerUri.trim(), audience);
            return decoder;
        }
        throw new IllegalStateException("JWT authentication is enabled but no decoder setting was provided.");
    }

    private void configureAudienceValidator(NimbusJwtDecoder decoder, String issuerUri, String audience) {
        OAuth2TokenValidator<org.springframework.security.oauth2.jwt.Jwt> validator =
                hasText(issuerUri) ? JwtValidators.createDefaultWithIssuer(issuerUri) : JwtValidators.createDefault();
        if (hasText(audience)) {
            validator = new DelegatingOAuth2TokenValidator<>(validator, jwt -> {
                if (jwt.getAudience()!=null && jwt.getAudience().contains(audience.trim())) {
                    return OAuth2TokenValidatorResult.success();
                }
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "JWT audience is invalid", null)
                );
            });
        }
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validator, jwt ->
                "access".equals(jwt.getClaimAsString("token_use"))
                        ? OAuth2TokenValidatorResult.success()
                        : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "JWT must be an access token", null))));
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
