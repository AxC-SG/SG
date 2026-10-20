package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.client.AwsCustomerBinding;
import com.prototype.vulnwatch.aisecurity.aws.AwsPermissionPreflightService;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.CredentialEncryptionService;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

@Service
public class AiSecurityAwsConnectorService {

    private static final Logger LOG = LoggerFactory.getLogger(AiSecurityAwsConnectorService.class);

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final CredentialEncryptionService encryptionService;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactionTemplate;
    private final IngestionJobService ingestionJobService;

    public AiSecurityAwsConnectorService(
            NamedParameterJdbcTemplate jdbc,
            ObjectMapper objectMapper,
            CredentialEncryptionService encryptionService,
            TenantSchemaExecutionService tenantExecution,
            TransactionTemplate transactionTemplate,
            IngestionJobService ingestionJobService
    ) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.encryptionService = encryptionService;
        this.tenantExecution = tenantExecution;
        this.transactionTemplate = transactionTemplate;
        this.ingestionJobService = ingestionJobService;
    }

    public ConnectorConfigResponse get(Tenant tenant) {
        return tenantExecution.run(tenant, () -> rows().stream().findFirst().orElse(null));
    }

    public ConnectorConfigResponse save(Tenant tenant, ConnectorConfigRequest request) {
        validate(request);
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            ConnectorConfigResponse existing = rows().stream().findFirst().orElse(null);
            UUID id = existing == null ? UUID.randomUUID() : existing.id();
            String externalId;
            try {
                externalId = AwsCustomerBinding.externalId(tenant.getId(), existing == null ? null : existing.externalId(),
                        existing == null || existing.externalId() == null ? 0 : AwsCustomerBinding.VERSION, request.externalId());
            } catch (IllegalArgumentException invalid) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, invalid.getMessage());
            }
            jdbc.update("""
                    insert into ai_security_connector_configs as existing (
                        id, tenant_id, provider, account_id, role_arn, external_id_ciphertext,
                        regions_json, enabled, credential_binding_version
                    ) values (
                        :id, :tenantId, 'AWS', :accountId, :roleArn, :externalId,
                        cast(:regions as jsonb), :enabled, 1
                    ) on conflict (id) do update
                        set account_id = excluded.account_id,
                            role_arn = excluded.role_arn,
                            external_id_ciphertext = coalesce(
                                excluded.external_id_ciphertext,
                                existing.external_id_ciphertext
                            ),
                            regions_json = excluded.regions_json,
                            enabled = excluded.enabled,
                            credential_binding_version = excluded.credential_binding_version,
                            updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("id", id)
                    .addValue("tenantId", tenant.getId())
                    .addValue("accountId", request.accountId().trim())
                    .addValue("roleArn", blankToNull(request.roleArn()))
                    .addValue("externalId", encryptionService.encrypt(externalId))
                    .addValue("regions", json(request.regions()))
                    .addValue("enabled", request.enabled()));
            return rows().stream().filter(row -> row.accountId().equals(request.accountId().trim())).findFirst()
                    .orElseThrow();
        }));
    }

    public ConnectionTestResponse test(Tenant tenant) {
        ConnectorSecret config = secret(tenant);
        try (CredentialsHandle handle = credentials(config);
             StsClient sts = StsClient.builder()
                     .region(Region.US_EAST_1)
                     .credentialsProvider(handle.provider())
                     .build()) {
            var callerIdentity = sts.getCallerIdentity();
            String actualAccount = callerIdentity.account();
            if (!config.accountId().equals(actualAccount)) {
                return new ConnectionTestResponse(false, "INVALID_CONFIGURATION",
                        "The assumed identity belongs to a different AWS account", false, List.of(), null, null);
            }
            return new ConnectionTestResponse(true, null, "AWS connection successful", false, List.of(),
                    new AwsPermissionPreflightService.Identity(actualAccount,
                            callerIdentity.arn(), callerIdentity.userId()), null);
        } catch (software.amazon.awssdk.services.sts.model.StsException ex) {
            String code = ex.awsErrorDetails() == null ? "ASSUME_ROLE_FAILED" : ex.awsErrorDetails().errorCode();
            return new ConnectionTestResponse(false, normalizeStsCode(code),
                    "Unable to assume the configured AWS role", false, List.of("sts:AssumeRole"), null, null);
        } catch (Exception ex) {
            LOG.warn("AWS connection test could not be completed for tenant {}: {}: {}",
                    tenant.getId(), ex.getClass().getName(), ex.getMessage());
            return new ConnectionTestResponse(false, "PROVIDER_UNAVAILABLE",
                    "AWS connection test could not be completed", true, List.of(), null, null);
        }
    }

    public IngestionJobAcceptedResponse trigger(Tenant tenant, String requestedBy) {
        ConnectorSecret config = secret(tenant);
        validateBinding(config);
        if (!config.enabled()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "AI Security connector is disabled");
        }
        return ingestionJobService.enqueueAiSecurityJob(tenant, config.id(), requestedBy);
    }

    public ConnectorSecret secret(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id, tenant_id, account_id, role_arn, external_id_ciphertext, regions_json::text, enabled, credential_binding_version
                  from ai_security_connector_configs
                 where provider = 'AWS' and tenant_id = :tenantId
                 order by updated_at desc limit 1
                """, Map.of("tenantId", tenant.getId()), rs -> {
            if (!rs.next()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security AWS connector is not configured");
            }
            ConnectorSecret config = new ConnectorSecret(
                    rs.getObject("id", UUID.class),
                    rs.getString("account_id"),
                    rs.getString("role_arn"),
                    encryptionService.decrypt(rs.getString("external_id_ciphertext")),
                    readRegions(rs.getString("regions_json")),
                    rs.getBoolean("enabled"), rs.getObject("tenant_id", UUID.class), rs.getInt("credential_binding_version"));
            if (!tenant.getId().equals(config.tenantId())) throw new IllegalStateException("AWS connector tenant does not match");
            return config;
        }));
    }

    public CredentialsHandle credentials(ConnectorSecret config) {
        validateBinding(config);
        // Local pilot runs use a named profile. Resolve it explicitly when present so an SDK
        // upgrade cannot silently fall through to an unrelated environment/IMDS provider.
        String profile = System.getenv("AWS_PROFILE");
        AwsCredentialsProvider base = profile == null || profile.isBlank()
                ? DefaultCredentialsProvider.create()
                : ProfileCredentialsProvider.create(profile.trim());
        StsClient sts = stsClient(base);
        AssumeRoleRequest.Builder request = AssumeRoleRequest.builder()
                .roleArn(config.roleArn())
                .roleSessionName("scout-ai-security-" + config.accountId());
        request.externalId(config.externalId());
        StsAssumeRoleCredentialsProvider assumed = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(sts)
                .refreshRequest(request.build())
                .build();
        CredentialsHandle handle = new CredentialsHandle(assumed, sts);
        try (StsClient identity = stsClient(assumed)) {
            var caller = identity.getCallerIdentity();
            AwsCustomerBinding.verifyIdentity(config.accountId(), config.roleArn(), caller.account(), caller.arn());
            return handle;
        } catch (RuntimeException failure) {
            handle.close();
            throw failure;
        }
    }

    StsClient stsClient(AwsCredentialsProvider provider) {
        return StsClient.builder().region(Region.US_EAST_1).credentialsProvider(provider).build();
    }

    private void validateBinding(ConnectorSecret config) {
        AwsCustomerBinding.validate(config.tenantId(), config.accountId(), config.roleArn(), config.externalId(), config.bindingVersion());
        if (config.tenantId() == null) throw new IllegalArgumentException("AWS connector tenant binding is missing");
    }

    private List<ConnectorConfigResponse> rows() {
        return jdbc.query("""
                select id, account_id, role_arn, regions_json::text, enabled, created_at, updated_at,
                       external_id_ciphertext, credential_binding_version
                  from ai_security_connector_configs
                 where provider = 'AWS' order by updated_at desc
                """, (rs, rowNum) -> new ConnectorConfigResponse(
                rs.getObject("id", UUID.class),
                rs.getString("account_id"),
                rs.getString("role_arn"),
                rs.getString("role_arn") == null ? "WORKLOAD_IDENTITY" : "CROSS_ACCOUNT_ROLE",
                rs.getInt("credential_binding_version") == AwsCustomerBinding.VERSION
                        ? encryptionService.decrypt(rs.getString("external_id_ciphertext")) : null,
                readRegions(rs.getString("regions_json")),
                rs.getBoolean("enabled"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant()));
    }

    private void validate(ConnectorConfigRequest request) {
        if (request == null || request.accountId() == null || !request.accountId().matches("\\d{12}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A 12-digit AWS account ID is required");
        }
        if (request.regions() == null || request.regions().isEmpty() || request.regions().size() > 20) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one AWS region is required");
        }
        try {
            if (!request.accountId().equals(AwsCustomerBinding.accountForRole(request.roleArn()))) {
                throw new IllegalArgumentException("The cross-account role ARN must belong to the configured AWS account");
            }
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, invalid.getMessage());
        }
        if (request.roleArn() != null && !request.roleArn().isBlank()
                && !request.roleArn().matches("arn:aws[a-z-]*:iam::\\d{12}:role/.+")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A valid cross-account role ARN is required");
        }
        if (request.roleArn() != null && !request.roleArn().isBlank()
                && !request.roleArn().contains("::" + request.accountId() + ":role/")) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "The cross-account role ARN must belong to the configured AWS account"
            );
        }
        if (request.regions().stream().anyMatch(region ->
                region == null || !region.matches("[a-z]{2}(?:-gov)?-[a-z]+-\\d"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "One or more AWS regions are invalid");
        }
    }

    private List<String> readRegions(String json) {
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception ex) {
            return List.of();
        }
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to serialize AWS connector regions", ex);
        }
    }

    private String normalizeStsCode(String code) {
        if ("AccessDenied".equalsIgnoreCase(code)) {
            return "ACCESS_DENIED";
        }
        if ("InvalidClientTokenId".equalsIgnoreCase(code)) {
            return "EXTERNAL_ID_MISMATCH";
        }
        return "ASSUME_ROLE_FAILED";
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    public record ConnectorConfigRequest(
            String accountId,
            String roleArn,
            String externalId,
            List<String> regions,
            boolean enabled
    ) {
    }

    public record ConnectorConfigResponse(
            UUID id,
            String accountId,
            String roleArn,
            String authMode,
            String externalId,
            List<String> regions,
            boolean enabled,
            java.time.Instant createdAt,
            java.time.Instant updatedAt
    ) {
    }

    public record ConnectionTestResponse(
            boolean success,
            String code,
            String message,
            boolean retryable,
            List<String> missingPermissions,
            AwsPermissionPreflightService.Identity identity,
            AwsPermissionPreflightService.PreflightReport preflight
    ) {
        public ConnectionTestResponse withPreflight(AwsPermissionPreflightService.PreflightReport report) {
            return new ConnectionTestResponse(success, code, message, retryable, missingPermissions,
                    report == null ? identity : report.identity(), report);
        }
    }

    public record ConnectorSecret(
            UUID id,
            String accountId,
            String roleArn,
            String externalId,
            List<String> regions,
            boolean enabled,
            UUID tenantId,
            int bindingVersion
    ) {
        public ConnectorSecret(UUID id, String accountId, String roleArn, String externalId, List<String> regions, boolean enabled) {
            this(id, accountId, roleArn, externalId, regions, enabled, null, 0);
        }
    }

    public static final class CredentialsHandle implements AutoCloseable {
        private final AwsCredentialsProvider provider;
        private final StsClient stsClient;

        CredentialsHandle(AwsCredentialsProvider provider, StsClient stsClient) {
            this.provider = provider;
            this.stsClient = stsClient;
        }

        public AwsCredentialsProvider provider() {
            return provider;
        }

        @Override
        public void close() {
            if (provider instanceof AutoCloseable closeable) {
                try {
                    closeable.close();
                } catch (Exception ignored) {
                    // Nothing actionable remains after the scan.
                }
            }
            if (stsClient != null) {
                stsClient.close();
            }
        }
    }
}
