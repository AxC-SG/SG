package com.prototype.vulnwatch.aisecurity.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.prototype.vulnwatch.client.AzureDiscoveryClient;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.CredentialEncryptionService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiSecurityAzureCredentialService {

    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactionTemplate;
    private final CredentialEncryptionService encryption;
    private final AzureDiscoveryClient azureClient;
    private final AuditEventService audit;
    private final AiSecurityAzureMetrics metrics;

    public AiSecurityAzureCredentialService(
            NamedParameterJdbcTemplate jdbc,
            TenantSchemaExecutionService tenantExecution,
            TransactionTemplate transactionTemplate,
            CredentialEncryptionService encryption,
            AzureDiscoveryClient azureClient,
            AuditEventService audit,
            AiSecurityAzureMetrics metrics
    ) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactionTemplate = transactionTemplate;
        this.encryption = encryption;
        this.azureClient = azureClient;
        this.audit = audit;
        this.metrics = metrics;
    }

    public List<CredentialProfileResponse> list(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id, name, auth_type, azure_tenant_id, client_id, status,
                       active_secret_expires_at, last_verified_at, last_verification_status,
                       created_at, updated_at
                  from ai_security_azure_credential_profiles
                 order by name, id
                """, (rs, rowNum) -> new CredentialProfileResponse(
                rs.getObject("id", UUID.class),
                rs.getString("name"),
                rs.getString("auth_type"),
                rs.getString("azure_tenant_id"),
                rs.getString("client_id"),
                rs.getString("status"),
                instant(rs.getTimestamp("active_secret_expires_at")),
                instant(rs.getTimestamp("last_verified_at")),
                rs.getString("last_verification_status"),
                instant(rs.getTimestamp("created_at")),
                instant(rs.getTimestamp("updated_at")))));
    }

    public CredentialProfileResponse create(Tenant tenant, CredentialProfileRequest request, String actor) {
        validateCreate(request);
        UUID id = UUID.randomUUID();
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.update("""
                    insert into ai_security_azure_credential_profiles (
                        id, tenant_id, name, auth_type, azure_tenant_id, client_id,
                        active_secret_ciphertext, active_secret_expires_at, created_by, updated_by
                    ) values (
                        :id, :tenantId, :name, :authType, :azureTenantId, :clientId,
                        :secret, :expiresAt, :actor, :actor
                    )
                    """, new MapSqlParameterSource()
                    .addValue("id", id)
                    .addValue("tenantId", tenant.getId())
                    .addValue("name", request.name().trim())
                    .addValue("authType", "CLIENT_SECRET")
                    .addValue("azureTenantId", request.azureTenantId().trim())
                    .addValue("clientId", blankToNull(request.clientId()))
                    .addValue("secret", encryption.encrypt(blankToNull(request.clientSecret())))
                    .addValue("expiresAt", timestamp(request.expiresAt()))
                    .addValue("actor", actor));
            audit.record("ai_security.azure_credential.created", "azure_credential_profile", id.toString(), null);
            metrics.recordCredentialEvent("created");
            return requireResponse(id);
        }));
    }

    public CredentialTestResponse test(
            Tenant tenant, UUID profileId, String subscriptionId, String actor) {
        CredentialSecret profile = secret(tenant, profileId);
        CredentialTestResponse response = testSecret(profile, subscriptionId);
        tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.update("""
                    update ai_security_azure_credential_profiles
                       set last_verified_at = now(), last_verification_status = :result,
                           updated_by = :actor, updated_at = now()
                     where id = :id
                    """, Map.of(
                    "result", response.success() ? "SUCCESS" : "FAILED",
                    "actor", actor,
                    "id", profileId));
            audit.record("ai_security.azure_credential.tested", "azure_credential_profile",
                    profileId.toString(), "{\"success\":" + response.success() + "}");
            return null;
        }));
        metrics.recordCredentialEvent(response.success() ? "test_succeeded" : "test_failed");
        return response;
    }

    public CredentialProfileResponse rotate(
            Tenant tenant, UUID profileId, RotateCredentialRequest request, String actor) {
        if (request == null || !hasText(request.clientSecret()) || request.expiresAt() == null
                || !request.expiresAt().isAfter(Instant.now().plus(1, ChronoUnit.DAYS))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A replacement secret and future expiry are required");
        }
        CredentialSecret existing = clientSecret(tenant, profileId);
        String encrypted = encryption.encrypt(request.clientSecret().trim());
        tenantExecution.run(tenant, () -> jdbc.update("""
                update ai_security_azure_credential_profiles
                   set pending_secret_ciphertext = :secret,
                       pending_secret_expires_at = :expiresAt,
                       updated_by = :actor, updated_at = now()
                 where id = :id and status = 'ACTIVE'
                """, new MapSqlParameterSource()
                .addValue("secret", encrypted)
                .addValue("expiresAt", timestamp(request.expiresAt()))
                .addValue("actor", actor)
                .addValue("id", profileId)));

        CredentialSecret pending = existing.withSecret(request.clientSecret().trim(), request.expiresAt());
        CredentialTestResponse test = testSecret(pending, request.subscriptionId());
        if (!test.success()) {
            tenantExecution.run(tenant, () -> jdbc.update("""
                    update ai_security_azure_credential_profiles
                       set pending_secret_ciphertext = null, pending_secret_expires_at = null,
                           last_verified_at = now(), last_verification_status = 'FAILED',
                           updated_by = :actor, updated_at = now()
                     where id = :id
                    """, Map.of("actor", actor, "id", profileId)));
            audit.record("ai_security.azure_credential.rotation_failed", "azure_credential_profile",
                    profileId.toString(), null, "FAILED");
            metrics.recordCredentialEvent("rotation_failed");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, test.message());
        }

        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.update("""
                    update ai_security_azure_credential_profiles
                       set active_secret_ciphertext = pending_secret_ciphertext,
                           active_secret_expires_at = pending_secret_expires_at,
                           pending_secret_ciphertext = null, pending_secret_expires_at = null,
                           expiry_warning_days = null,
                           last_verified_at = now(), last_verification_status = 'SUCCESS',
                           updated_by = :actor, updated_at = now()
                     where id = :id and status = 'ACTIVE'
                    """, Map.of("actor", actor, "id", profileId));
            audit.record("ai_security.azure_credential.rotated", "azure_credential_profile",
                    profileId.toString(), null);
            metrics.recordCredentialEvent("rotated");
            return requireResponse(profileId);
        }));
    }

    public void revoke(Tenant tenant, UUID profileId, String actor) {
        tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            int changed = jdbc.update("""
                    update ai_security_azure_credential_profiles
                       set status = 'REVOKED', active_secret_ciphertext = null,
                           pending_secret_ciphertext = null, pending_secret_expires_at = null,
                           revoked_at = now(), revoked_by = :actor,
                           updated_by = :actor, updated_at = now()
                     where id = :id and status = 'ACTIVE'
                    """, Map.of("actor", actor, "id", profileId));
            if (changed == 0) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Azure credential profile not found");
            }
            audit.record("ai_security.azure_credential.revoked", "azure_credential_profile",
                    profileId.toString(), null);
            metrics.recordCredentialEvent("revoked");
            return null;
        }));
    }

    public void processExpiryWarnings(Tenant tenant) {
        tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            List<ExpiryCandidate> candidates = jdbc.query("""
                    select id, active_secret_expires_at, expiry_warning_days
                      from ai_security_azure_credential_profiles
                     where status = 'ACTIVE'
                       and auth_type = 'CLIENT_SECRET'
                       and active_secret_expires_at <= now() + interval '30 days'
                     order by active_secret_expires_at
                    """, (rs, rowNum) -> new ExpiryCandidate(
                    rs.getObject("id", UUID.class),
                    rs.getTimestamp("active_secret_expires_at").toInstant(),
                    (Integer) rs.getObject("expiry_warning_days")));
            Instant now = Instant.now();
            for (ExpiryCandidate candidate : candidates) {
                if (!candidate.expiresAt().isAfter(now)) {
                    int changed = jdbc.update("""
                            update ai_security_azure_credential_profiles
                               set status = 'EXPIRED', expiry_warning_days = 0, updated_at = now()
                             where id = :id and status = 'ACTIVE'
                               and active_secret_expires_at = :expiresAt
                            """, Map.of("id", candidate.id(), "expiresAt", Timestamp.from(candidate.expiresAt())));
                    if (changed == 1) {
                        audit.record("ai_security.azure_credential.expired", "azure_credential_profile",
                                candidate.id().toString(), null);
                        metrics.recordCredentialEvent("expired");
                    }
                    continue;
                }
                long remaining = ChronoUnit.DAYS.between(now, candidate.expiresAt()) + 1;
                int threshold = remaining <= 7 ? 7 : remaining <= 14 ? 14 : 30;
                if (candidate.lastWarningDays() == null || threshold < candidate.lastWarningDays()) {
                    int changed = jdbc.update("""
                            update ai_security_azure_credential_profiles
                               set expiry_warning_days = :threshold, updated_at = now()
                             where id = :id and status = 'ACTIVE'
                               and active_secret_expires_at = :expiresAt
                               and (expiry_warning_days is null or expiry_warning_days > :threshold)
                            """, Map.of("threshold", threshold, "id", candidate.id(),
                            "expiresAt", Timestamp.from(candidate.expiresAt())));
                    if (changed == 1) {
                        audit.record("ai_security.azure_credential.expiry_warning", "azure_credential_profile",
                                candidate.id().toString(), "{\"days\":" + threshold + "}");
                        metrics.recordCredentialEvent("expiry_warning");
                    }
                }
            }
            return null;
        }));
    }

    public CredentialSecret secret(Tenant tenant, UUID profileId) {
        return tenantExecution.run(tenant, () -> {
            List<CredentialSecret> rows = jdbc.query("""
                    select id, auth_type, azure_tenant_id, client_id, active_secret_ciphertext,
                           active_secret_expires_at, status
                      from ai_security_azure_credential_profiles
                     where id = :id
                    """, Map.of("id", profileId), (rs, rowNum) -> new CredentialSecret(
                    rs.getObject("id", UUID.class),
                    rs.getString("auth_type"),
                    rs.getString("azure_tenant_id"),
                    rs.getString("client_id"),
                    encryption.decrypt(rs.getString("active_secret_ciphertext")),
                    instant(rs.getTimestamp("active_secret_expires_at")),
                    rs.getString("status")));
            if (rows.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Azure credential profile not found");
            }
            CredentialSecret result = rows.get(0);
            if (!"ACTIVE".equals(result.status())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Azure credential profile is not active");
            }
            if (result.expiresAt() != null && !result.expiresAt().isAfter(Instant.now())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Azure credential profile has expired");
            }
            return result;
        });
    }

    private CredentialSecret clientSecret(Tenant tenant, UUID profileId) {
        return tenantExecution.run(tenant, () -> {
            List<CredentialSecret> rows = jdbc.query("""
                    select id, auth_type, azure_tenant_id, client_id, active_secret_ciphertext,
                           active_secret_expires_at, status
                      from ai_security_azure_credential_profiles
                     where id = :id and auth_type = 'CLIENT_SECRET'
                    """, Map.of("id", profileId), (rs, rowNum) -> new CredentialSecret(
                    rs.getObject("id", UUID.class),
                    rs.getString("auth_type"),
                    rs.getString("azure_tenant_id"),
                    rs.getString("client_id"),
                    encryption.decrypt(rs.getString("active_secret_ciphertext")),
                    instant(rs.getTimestamp("active_secret_expires_at")),
                    rs.getString("status")));
            if (rows.isEmpty()) {
                throw new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Active client-secret credential profile not found");
            }
            CredentialSecret result = rows.get(0);
            if (!"ACTIVE".equals(result.status())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Azure credential profile is not active");
            }
            if (result.expiresAt() == null || !result.expiresAt().isAfter(Instant.now())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Azure credential profile has expired");
            }
            return result;
        });
    }

    public TokenCredential tokenCredential(CredentialSecret profile) {
        return switch (profile.authType()) {
            case "CLIENT_SECRET" -> new ClientSecretCredentialBuilder()
                    .tenantId(profile.azureTenantId())
                    .clientId(profile.clientId())
                    .clientSecret(profile.clientSecret())
                    .build();
            case "MANAGED_IDENTITY" -> {
                DefaultAzureCredentialBuilder builder = new DefaultAzureCredentialBuilder();
                if (hasText(profile.clientId())) {
                    builder.managedIdentityClientId(profile.clientId());
                }
                yield builder.build();
            }
            case "WORKLOAD_FEDERATION" -> throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Workload federation is not approved for this hosting path");
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported Azure authentication type");
        };
    }

    private CredentialTestResponse testSecret(CredentialSecret profile, String subscriptionId) {
        if (!hasText(subscriptionId)) {
            return new CredentialTestResponse(false, "INVALID_CONFIGURATION",
                    "An Azure subscription is required", false, null, null);
        }
        try {
            var result = azureClient.testConnectivity(tokenCredential(profile), subscriptionId.trim());
            if (!result.success()) {
                return new CredentialTestResponse(false, "AZURE_AUTHENTICATION_FAILED",
                        "Azure credentials could not access the selected subscription", false, null, null);
            }
            if (hasText(result.tenantId())
                    && !profile.azureTenantId().equalsIgnoreCase(result.tenantId())) {
                return new CredentialTestResponse(false, "AZURE_TENANT_MISMATCH",
                        "The subscription belongs to a different Azure tenant", false,
                        result.subscriptionName(), result.tenantId());
            }
            return new CredentialTestResponse(true, null, "Azure credential test succeeded", false,
                    result.subscriptionName(), result.tenantId());
        } catch (Exception exception) {
            return new CredentialTestResponse(false, "PROVIDER_UNAVAILABLE",
                    "Azure credential test could not be completed", true, null, null);
        }
    }

    private CredentialProfileResponse requireResponse(UUID id) {
        return listCurrent().stream().filter(profile -> profile.id().equals(id)).findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Azure credential profile not found"));
    }

    private List<CredentialProfileResponse> listCurrent() {
        return jdbc.query("""
                select id, name, auth_type, azure_tenant_id, client_id, status,
                       active_secret_expires_at, last_verified_at, last_verification_status,
                       created_at, updated_at
                  from ai_security_azure_credential_profiles order by name, id
                """, (rs, rowNum) -> new CredentialProfileResponse(
                rs.getObject("id", UUID.class), rs.getString("name"), rs.getString("auth_type"),
                rs.getString("azure_tenant_id"), rs.getString("client_id"), rs.getString("status"),
                instant(rs.getTimestamp("active_secret_expires_at")),
                instant(rs.getTimestamp("last_verified_at")),
                rs.getString("last_verification_status"),
                instant(rs.getTimestamp("created_at")), instant(rs.getTimestamp("updated_at"))));
    }

    private void validateCreate(CredentialProfileRequest request) {
        if (request == null || !hasText(request.name()) || !hasText(request.azureTenantId())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name and Azure tenant are required");
        }
        if (!hasText(request.clientId()) || !hasText(request.clientSecret()) || request.expiresAt() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Client ID, client secret, and expiry are required");
        }
        if (!request.expiresAt().isAfter(Instant.now().plus(1, ChronoUnit.DAYS))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credential expiry must be in the future");
        }
    }

    private Instant instant(java.sql.Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private String blankToNull(String value) {
        return hasText(value) ? value.trim() : null;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public record CredentialProfileRequest(
            String name,
            String azureTenantId,
            String clientId,
            String clientSecret,
            Instant expiresAt
    ) {
    }

    public record RotateCredentialRequest(String clientSecret, Instant expiresAt, String subscriptionId) {
    }

    public record CredentialProfileResponse(
            UUID id,
            String name,
            String authType,
            String azureTenantId,
            String clientId,
            String status,
            Instant expiresAt,
            Instant lastVerifiedAt,
            String lastVerificationStatus,
            Instant createdAt,
            Instant updatedAt
    ) {
    }

    public record CredentialTestResponse(
            boolean success,
            String code,
            String message,
            boolean retryable,
            String subscriptionName,
            String azureTenantId
    ) {
    }

    public record CredentialSecret(
            UUID id,
            String authType,
            String azureTenantId,
            String clientId,
            String clientSecret,
            Instant expiresAt,
            String status
    ) {
        CredentialSecret withSecret(String replacement, Instant replacementExpiry) {
            return new CredentialSecret(
                    id, authType, azureTenantId, clientId, replacement, replacementExpiry, status);
        }
    }

    private record ExpiryCandidate(UUID id, Instant expiresAt, Integer lastWarningDays) {
    }
}
