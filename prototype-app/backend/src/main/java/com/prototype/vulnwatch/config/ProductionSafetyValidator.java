package com.prototype.vulnwatch.config;

import org.springframework.beans.factory.annotation.Value;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Qualifier;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Map;
import java.util.Locale;

@Component
public class ProductionSafetyValidator {

    private final boolean requireProductionSecrets;
    private final String apiKey;
    private final String creatorKey;
    private final boolean allowApiKeyAuth;
    private final String jwtIssuerUri;
    private final String jwtJwkSetUri;
    private final String jwtHmacSecret;
    private final boolean allowHmacInProduction;
    private final String legacyPlatformOwnerEmail;
    private final String legacyPlatformOwnerPasswordHash;
    private final String credentialEncryptionKey;
    private final boolean allowHeaderTenantSelection;
    private final boolean requireTenantContext;
    private final String corsAllowedOrigins;
    private final boolean testPersonasEnabled;
    private final JdbcTemplate platformJdbcTemplate;
    private final boolean validateRlsRuntimeRole;
    private final PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties;

    @Value("${app.security.production-forbidden-identity-subjects:}")
    private String forbiddenIdentitySubjects = "";
    @Value("${app.ai-security.identity-hmac-key:}")
    private String aiIdentityHmacKey = "";
    @Value("${app.ai-security.runtime.enabled:false}")
    private boolean aiRuntimeEnabled;

    public ProductionSafetyValidator(
            @Value("${app.security.require-production-secrets:false}") boolean requireProductionSecrets,
            @Value("${app.security.api-key:}") String apiKey,
            @Value("${app.security.creator-key:}") String creatorKey,
            @Value("${app.security.allow-api-key-auth:true}") boolean allowApiKeyAuth,
            @Value("${app.security.jwt.issuer-uri:}") String jwtIssuerUri,
            @Value("${app.security.jwt.jwk-set-uri:}") String jwtJwkSetUri,
            @Value("${app.security.jwt.hmac-secret:}") String jwtHmacSecret,
            @Value("${app.security.jwt.allow-hmac-in-production:false}") boolean allowHmacInProduction,
            @Value("${app.security.platform-owner-email:}") String legacyPlatformOwnerEmail,
            @Value("${app.security.platform-owner-password-hash:}") String legacyPlatformOwnerPasswordHash,
            @Value("${app.security.credential-encryption-key:}") String credentialEncryptionKey,
            @Value("${app.tenancy.allow-header-tenant-selection:false}") boolean allowHeaderTenantSelection,
            @Value("${app.tenancy.require-tenant-context:true}") boolean requireTenantContext,
            @Value("${app.cors.allowed-origins:}") String corsAllowedOrigins,
            @Value("${app.test-personas.enabled:false}") boolean testPersonasEnabled,
            @Value("${app.security.validate-rls-runtime-role:false}") boolean validateRlsRuntimeRole,
            @Qualifier("platformJdbcTemplate") JdbcTemplate platformJdbcTemplate,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        this.requireProductionSecrets = requireProductionSecrets;
        this.apiKey = apiKey;
        this.creatorKey = creatorKey;
        this.allowApiKeyAuth = allowApiKeyAuth;
        this.jwtIssuerUri = jwtIssuerUri;
        this.jwtJwkSetUri = jwtJwkSetUri;
        this.jwtHmacSecret = jwtHmacSecret;
        this.allowHmacInProduction = allowHmacInProduction;
        this.legacyPlatformOwnerEmail = legacyPlatformOwnerEmail;
        this.legacyPlatformOwnerPasswordHash = legacyPlatformOwnerPasswordHash;
        this.credentialEncryptionKey = credentialEncryptionKey;
        this.allowHeaderTenantSelection = allowHeaderTenantSelection;
        this.requireTenantContext = requireTenantContext;
        this.corsAllowedOrigins = corsAllowedOrigins;
        this.testPersonasEnabled = testPersonasEnabled;
        this.platformJdbcTemplate = platformJdbcTemplate;
        this.validateRlsRuntimeRole = validateRlsRuntimeRole;
        this.platformOwnerBootstrapProperties = platformOwnerBootstrapProperties;
    }

    @PostConstruct
    public void validate() {
        if (aiRuntimeEnabled) {
            throw new IllegalStateException("RUNTIME_OUT_OF_SCOPE: APP_AI_SECURITY_RUNTIME_ENABLED must be false in this release.");
        }
        validateLegacyPlatformOwnerCredentialsAreUnused();
        validatePlatformOwnerBootstrapConfiguration();
        if (!requireProductionSecrets) {
            if (validateRlsRuntimeRole) {
                validateRuntimeRoleCannotBypassRls();
            }
            return;
        }
        if (allowApiKeyAuth) {
            throw new IllegalStateException("APP_ALLOW_API_KEY_AUTH must be false for production startup.");
        }
        if (hasText(creatorKey)) {
            throw new IllegalStateException("APP_CREATOR_KEY must be unset for production startup.");
        }
        if (!hasText(jwtIssuerUri) && !hasText(jwtJwkSetUri)) {
            if (!allowHmacInProduction) {
                throw new IllegalStateException(
                        "APP_JWT_ISSUER_URI or APP_JWT_JWK_SET_URI must be set for production startup; "
                                + "preproduction HMAC requires APP_ALLOW_HMAC_IN_PRODUCTION=true."
                );
            }
            if (!hasStrongValue(jwtHmacSecret) || isPlaceholder(jwtHmacSecret)) {
                throw new IllegalStateException(
                        "APP_JWT_HMAC_SECRET must be a non-placeholder value of at least 32 UTF-8 bytes when HMAC is enabled."
                );
            }
        }
        if (allowHeaderTenantSelection) {
            throw new IllegalStateException("APP_ALLOW_HEADER_TENANT_SELECTION must be false for production startup.");
        }
        if (!requireTenantContext) {
            throw new IllegalStateException("APP_REQUIRE_TENANT_CONTEXT must be true for production startup.");
        }
        if (!hasAes256Key(credentialEncryptionKey) || isPlaceholder(credentialEncryptionKey)
                || "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".equals(credentialEncryptionKey)) {
            throw new IllegalStateException("APP_CREDENTIAL_ENCRYPTION_KEY must be set to a non-default 256-bit base64 key for production startup.");
        }
        if (!hasStrongValue(aiIdentityHmacKey) || isPlaceholder(aiIdentityHmacKey)) {
            throw new IllegalStateException(
                    "APP_AI_SECURITY_IDENTITY_HMAC_KEY must be a non-placeholder value of at least 32 UTF-8 bytes in production.");
        }
        if (corsAllowedOrigins == null || corsAllowedOrigins.isBlank() || corsAllowedOrigins.contains("*")) {
            throw new IllegalStateException("APP_CORS_ALLOWED_ORIGINS must be set to explicit production origins.");
        }
        if (testPersonasEnabled) {
            throw new IllegalStateException("APP_TEST_PERSONAS_ENABLED must be false for production startup.");
        }
        validateForbiddenProductionIdentities();
        validateRuntimeRoleCannotBypassRls();
    }

    private boolean hasAes256Key(String key) {
        try {
            return key != null && Base64.getDecoder().decode(key).length == 32;
        } catch (IllegalArgumentException invalidEncoding) {
            return false;
        }
    }

    private void validateForbiddenProductionIdentities() {
        List<String> configured = java.util.Arrays.stream(
                        forbiddenIdentitySubjects == null ? new String[0] : forbiddenIdentitySubjects.split(","))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .map(value -> value.toLowerCase(Locale.ROOT))
                .toList();
        List<Map<String, Object>> unsafeCandidates = platformJdbcTemplate.queryForList("""
                select distinct u.external_subject, u.email
                from platform.app_users u
                left join platform.app_user_global_roles r on r.app_user_id = u.id
                left join platform.tenant_memberships m on m.user_id = u.id and upper(m.status) = 'ACTIVE'
                where
                    upper(u.status) = 'ACTIVE'
                    or u.password_hash is not null
                    or u.password_setup_token_hash is not null
                    or r.id is not null
                    or m.id is not null
                """);
        boolean unsafe = unsafeCandidates.stream().anyMatch(row -> {
            String subject = String.valueOf(row.getOrDefault("external_subject", "")).toLowerCase(Locale.ROOT);
            String email = String.valueOf(row.getOrDefault("email", "")).toLowerCase(Locale.ROOT);
            return subject.startsWith("persona-") || email.endsWith("@localhost")
                    || configured.contains(subject) || configured.contains(email);
        });
        if (unsafe) {
            throw new IllegalStateException(
                    "Production contains active local/test identities. Run cleanup-production-identities.sh before startup.");
        }
    }

    private void validatePlatformOwnerBootstrapConfiguration() {
        if (platformOwnerBootstrapProperties == null || !platformOwnerBootstrapProperties.isEnabled()) {
            return;
        }
        if (platformOwnerBootstrapProperties.getUsers() == null || platformOwnerBootstrapProperties.getUsers().isEmpty()) {
            throw new IllegalStateException("APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED is true but no platform owner bootstrap users are configured.");
        }
        for (PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed : platformOwnerBootstrapProperties.getUsers()) {
            boolean hasSubject = hasText(seed.getExternalSubject());
            boolean hasEmail = hasText(seed.getEmail());
            if (!hasSubject && !hasEmail) {
                throw new IllegalStateException("Each platform owner bootstrap user must include externalSubject or email.");
            }
            if (requireProductionSecrets) {
                if (!hasEmail) {
                    throw new IllegalStateException("Production platform owner bootstrap users must include email for password setup and login.");
                }
                String email = seed.getEmail().trim().toLowerCase();
                if (email.endsWith("@localhost")) {
                    throw new IllegalStateException("Production platform owner bootstrap users cannot use localhost email addresses.");
                }
            }
        }
    }

    private void validateLegacyPlatformOwnerCredentialsAreUnused() {
        if (hasText(legacyPlatformOwnerEmail) || hasText(legacyPlatformOwnerPasswordHash)) {
            throw new IllegalStateException(
                    "Legacy platform-owner credential properties are no longer supported. "
                            + "Remove APP_PLATFORM_OWNER_EMAIL / APP_PLATFORM_OWNER_PASSWORD_HASH and use "
                            + "platform-owner bootstrap users plus password setup instead.");
        }
    }

    private void validateRuntimeRoleCannotBypassRls() {
        if (platformJdbcTemplate == null) {
            throw new IllegalStateException("platformJdbcTemplate is required for production DB role safety validation.");
        }
        Boolean superuser = platformJdbcTemplate.queryForObject("""
                select rolsuper
                from pg_roles
                where rolname = current_user
                """, Boolean.class);
        if (Boolean.TRUE.equals(superuser)) {
            throw new IllegalStateException("Production DB runtime role must not be a PostgreSQL superuser; superusers bypass RLS.");
        }
        Boolean bypassRls = platformJdbcTemplate.queryForObject("""
                select rolbypassrls
                from pg_roles
                where rolname = current_user
                """, Boolean.class);
        if (Boolean.TRUE.equals(bypassRls)) {
            throw new IllegalStateException("Production DB runtime role must not have BYPASSRLS.");
        }
        String isSuperuser = platformJdbcTemplate.queryForObject("select current_setting('is_superuser')", String.class);
        if ("on".equalsIgnoreCase(isSuperuser) || "true".equalsIgnoreCase(isSuperuser)) {
            throw new IllegalStateException("Production DB runtime role reports is_superuser=true; RLS would be bypassed.");
        }
        Boolean ownsTenantTables = platformJdbcTemplate.queryForObject("""
                select exists (
                    select 1
                    from pg_class c
                    join pg_namespace n on n.oid = c.relnamespace
                    join pg_roles r on r.oid = c.relowner
                    where (n.nspname = 'platform' or n.nspname = 'tenant_default' or n.nspname ~ '^tenant_')
                      and c.relkind in ('r', 'p')
                      and r.rolname = current_user
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(ownsTenantTables)) {
            throw new IllegalStateException("Production DB runtime role must not own tenant/platform tables protected by RLS.");
        }
        Boolean canCreateInProtectedSchemas = platformJdbcTemplate.queryForObject("""
                select exists (
                    select 1
                    from pg_namespace n
                    where (n.nspname = 'platform' or n.nspname = 'tenant_default' or n.nspname ~ '^tenant_')
                      and has_schema_privilege(current_user, n.oid, 'CREATE')
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(canCreateInProtectedSchemas)) {
            throw new IllegalStateException("Production DB runtime role must not have CREATE on platform or tenant schemas.");
        }
        Boolean canAssumeUnsafeRole = platformJdbcTemplate.queryForObject("""
                with recursive memberships(roleid) as (
                    select m.roleid
                    from pg_auth_members m
                    join pg_roles me on me.oid = m.member
                    where me.rolname = current_user
                    union
                    select m.roleid
                    from pg_auth_members m
                    join memberships inherited on inherited.roleid = m.member
                )
                select exists (
                    select 1 from memberships m
                    join pg_roles r on r.oid = m.roleid
                    where r.rolsuper or r.rolbypassrls
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(canAssumeUnsafeRole)) {
            throw new IllegalStateException("Production DB runtime role must not inherit or assume a superuser/BYPASSRLS role.");
        }
        Boolean incompleteRls = platformJdbcTemplate.queryForObject("""
                select exists (
                    select 1
                    from platform.tenants t
                    join pg_namespace n on n.nspname = t.schema_name
                    join pg_class c on c.relnamespace = n.oid and c.relkind in ('r', 'p')
                    where t.status='ACTIVE' and exists(select 1 from platform.tenant_schema_versions v where v.tenant_id=t.id and v.status='CURRENT' and v.current_version between 5 and 5)
                      and c.relname not in ('tenant_schema_history', 'flyway_schema_history', 'demo_requests')
                      and (
                          not c.relrowsecurity
                          or not c.relforcerowsecurity
                          or not exists (
                              select 1 from pg_policy p
                              where p.polrelid = c.oid and p.polname = 'tenant_isolation'
                          )
                      )
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(incompleteRls)) {
            throw new IllegalStateException("Production startup rejected: tenant RLS coverage is incomplete.");
        }
        validateRegisteredTenantRows();
    }

    private void validateRegisteredTenantRows() {
        List<Map<String, Object>> schemas = platformJdbcTemplate.queryForList("""
                select t.id,t.schema_name from platform.tenants t join platform.tenant_schema_versions v on v.tenant_id=t.id where t.status='ACTIVE' and v.status='CURRENT' and v.current_version between 5 and 5
                """);
        for (Map<String, Object> tenant : schemas) {
            String schema = String.valueOf(tenant.get("schema_name"));
            String tenantId = String.valueOf(tenant.get("id"));
            List<String> tables = platformJdbcTemplate.queryForList("""
                    select table_name
                    from information_schema.columns
                    where table_schema = ? and column_name = 'tenant_id'
                      and table_name not in ('tenant_schema_history', 'flyway_schema_history')
                    order by table_name
                    """, String.class, schema);
            for (String table : tables) {
                if (isSharedLifecycleTable(schema, table)) {
                    continue;
                }
                Long conflicts = platformJdbcTemplate.queryForObject(
                        "select count(*) from " + quoteIdentifier(schema) + "." + quoteIdentifier(table)
                                + " where tenant_id is not null and tenant_id <> ?::uuid",
                        Long.class,
                        tenantId);
                if (conflicts != null && conflicts > 0) {
                    throw new IllegalStateException(
                            "Production startup rejected: conflicting tenant rows in " + schema + "." + table);
                }
            }
        }
    }

    static boolean isSharedLifecycleTable(String schema, String table) {
        // Until the live playground is split from tenant_default, demo onboarding records
        // are intentionally centralized there and may reference any provisioned tenant.
        // Keep the exemption narrow: copies of these tables in customer schemas remain
        // subject to the normal single-tenant row ownership validation.
        return "tenant_default".equals(schema)
                && ("demo_requests".equals(table) || "demo_invites".equals(table));
    }

    private String quoteIdentifier(String identifier) {
        return "\"" + identifier.replace("\"", "\"\"") + "\"";
    }

    private boolean hasStrongValue(String value) {
        return value != null && !value.isBlank() && value.getBytes(StandardCharsets.UTF_8).length >= 32;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private boolean isPlaceholder(String value) {
        return value != null && value.toLowerCase().contains("replace-with");
    }
}
