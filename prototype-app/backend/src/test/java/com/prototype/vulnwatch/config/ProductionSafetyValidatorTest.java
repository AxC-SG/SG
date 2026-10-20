package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

class ProductionSafetyValidatorTest {

    @Test
    void validateRejectsRuntimeEvenWithADedicatedIdentityKey() {
        ProductionSafetyValidator validator = validator(
                "", false, "https://issuer.example.com", "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", false, true,
                "https://app.example.com", disabledBootstrap());
        ReflectionTestUtils.setField(validator, "aiRuntimeEnabled", true);
        ReflectionTestUtils.setField(validator, "aiIdentityHmacKey", testHmacKey());

        var error = assertThrows(IllegalStateException.class, validator::validate);
        assertTrue(error.getMessage().contains("RUNTIME_OUT_OF_SCOPE"));
    }

    @Test
    void sharedDemoLifecycleTablesAreExemptOnlyInDefaultSchema() {
        assertTrue(ProductionSafetyValidator.isSharedLifecycleTable("tenant_default", "demo_requests"));
        assertTrue(ProductionSafetyValidator.isSharedLifecycleTable("tenant_default", "demo_invites"));
        assertFalse(ProductionSafetyValidator.isSharedLifecycleTable("tenant_default", "assets"));
        assertFalse(ProductionSafetyValidator.isSharedLifecycleTable("tenant_customer", "demo_invites"));
    }

    @Test
    void validateAllowsProductionSafeConfiguration() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                disabledBootstrap());

        assertDoesNotThrow(validator::validate);
    }

    private static String testHmacKey() {
        return String.join("-", "test", "only", "identity", "hmac", "material", "0001");
    }

    @Test
    void validateRejectsWildcardCorsOrigins() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "*",
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsApiKeyModeForProduction() {
        ProductionSafetyValidator validator = validator(
                "",
                true,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsMissingJwtIssuerOrJwk() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateAllowsExplicitStrongHmacForPreproduction() {
        ProductionSafetyValidator validator = hmacValidator(
                "0123456789abcdef0123456789abcdef",
                true);

        assertDoesNotThrow(validator::validate);
    }

    @Test
    void validateRejectsWeakHmacForPreproduction() {
        ProductionSafetyValidator validator = hmacValidator("too-short", true);

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validatesEncodedAesKeyAndActualHmacBytes() {
        ProductionSafetyValidator invalidAes = validator("", false, "https://issuer.example.com", "",
                "a".repeat(32), false, true, "https://app.example.com", disabledBootstrap());
        assertThrows(IllegalStateException.class, invalidAes::validate);
        assertDoesNotThrow(hmacValidator("é".repeat(16), true)::validate);
        assertThrows(IllegalStateException.class, hmacValidator(" ".repeat(32), true)::validate);
    }

    @Test
    void validateRejectsMissingTenantContextRequirement() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                false,
                "https://app.example.com",
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsEnabledTestPersonasForProduction() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                true,
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsEnabledPlatformOwnerBootstrapWithoutUsers() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                enabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsLegacyPlatformOwnerCredentialProperties() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "legacy.owner@example.com",
                "$2a$10$legacyhashlegacyhashlegacyhashlegacyhashlegacyhash12",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                false,
                safeRoleJdbcTemplate(),
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsProductionBootstrapUsersWithoutEmail() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(true);
        PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed = new PlatformOwnerBootstrapProperties.PlatformOwnerSeed();
        seed.setExternalSubject("owner-subject");
        properties.setUsers(java.util.List.of(seed));

        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                properties);

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsProductionBootstrapUsersWithLocalhostEmail() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(true);
        PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed = new PlatformOwnerBootstrapProperties.PlatformOwnerSeed();
        seed.setEmail("owner@localhost");
        properties.setUsers(java.util.List.of(seed));

        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                properties);

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsSuperuserRuntimeRole() {
        JdbcTemplate jdbcTemplate = safeRoleJdbcTemplate();
        when(jdbcTemplate.queryForObject(anyString(), eq(Boolean.class)))
                .thenReturn(true, false, false);
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                true,
                jdbcTemplate,
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsBypassRlsRuntimeRole() {
        JdbcTemplate jdbcTemplate = safeRoleJdbcTemplate();
        when(jdbcTemplate.queryForObject(anyString(), eq(Boolean.class)))
                .thenReturn(false, true, false);
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                true,
                jdbcTemplate,
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        return validator(
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                false,
                platformOwnerBootstrapProperties);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        ProductionSafetyValidator validator = new ProductionSafetyValidator(
                true,
                "",
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                "",
                false,
                "",
                "",
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                false,
                safeRoleJdbcTemplate(),
                platformOwnerBootstrapProperties);
        ReflectionTestUtils.setField(validator, "aiIdentityHmacKey", testHmacKey());
        return validator;
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String legacyPlatformOwnerEmail,
            String legacyPlatformOwnerPasswordHash,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled,
            JdbcTemplate jdbcTemplate,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        return validator(
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                legacyPlatformOwnerEmail,
                legacyPlatformOwnerPasswordHash,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                false,
                jdbcTemplate,
                platformOwnerBootstrapProperties);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled,
            boolean validateRlsRuntimeRole,
            JdbcTemplate jdbcTemplate,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        return validator(
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                "",
                "",
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                validateRlsRuntimeRole,
                jdbcTemplate,
                platformOwnerBootstrapProperties);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String legacyPlatformOwnerEmail,
            String legacyPlatformOwnerPasswordHash,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled,
            boolean validateRlsRuntimeRole,
            JdbcTemplate jdbcTemplate,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        ProductionSafetyValidator validator = new ProductionSafetyValidator(
                true,
                "",
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                "",
                false,
                legacyPlatformOwnerEmail,
                legacyPlatformOwnerPasswordHash,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                validateRlsRuntimeRole,
                jdbcTemplate,
                platformOwnerBootstrapProperties);
        ReflectionTestUtils.setField(validator, "aiIdentityHmacKey", testHmacKey());
        return validator;
    }

    private PlatformOwnerBootstrapProperties disabledBootstrap() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(false);
        return properties;
    }

    private ProductionSafetyValidator hmacValidator(String hmacSecret, boolean allowHmacInProduction) {
        ProductionSafetyValidator validator = new ProductionSafetyValidator(
                true,
                "",
                "",
                false,
                "",
                "",
                hmacSecret,
                allowHmacInProduction,
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                false,
                safeRoleJdbcTemplate(),
                disabledBootstrap());
        ReflectionTestUtils.setField(validator, "aiIdentityHmacKey", testHmacKey());
        return validator;
    }

    private PlatformOwnerBootstrapProperties enabledBootstrap() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(true);
        return properties;
    }

    private JdbcTemplate safeRoleJdbcTemplate() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(jdbcTemplate.queryForObject(anyString(), eq(Boolean.class)))
                .thenReturn(false, false, false);
        when(jdbcTemplate.queryForObject(anyString(), eq(String.class))).thenReturn("off");
        return jdbcTemplate;
    }
}
