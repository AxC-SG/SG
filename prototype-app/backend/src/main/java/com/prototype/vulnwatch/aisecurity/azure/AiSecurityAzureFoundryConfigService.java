package com.prototype.vulnwatch.aisecurity.azure;

import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService.ConnectorRequest;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService.ConnectorResponse;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService.ConnectionTestResponse;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.CredentialProfileRequest;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.CredentialProfileResponse;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.RotateCredentialRequest;
import com.prototype.vulnwatch.domain.AzureAuthType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AzureDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.AzureDiscoveryConfigResponse;
import com.prototype.vulnwatch.dto.AzureDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.AzureDiscoveryTargetResponse;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.AzureDiscoveryConfigService;
import com.prototype.vulnwatch.service.AzureDiscoveryTargetService;
import com.prototype.vulnwatch.service.CredentialEncryptionService.CredentialDecryptionException;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Single-form, tenant-scoped Azure AI Security setup. Orchestrates the lower-level Azure Cloud
 * Discovery config/target and AI Security credential-profile/connector primitives behind one
 * "save configuration" action so a tenant never has to configure two separate connectors to turn
 * on Azure AI Security discovery.
 */
@Service
public class AiSecurityAzureFoundryConfigService {

    private static final String PROFILE_NAME = "AI Security Azure";
    private static final String DEFAULT_REGION = "eastus2";

    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final AzureDiscoveryConfigService discoveryConfigService;
    private final AzureDiscoveryTargetService discoveryTargetService;
    private final AiSecurityAzureCredentialService credentialService;
    private final AiSecurityAzureConnectorService connectorService;

    public AiSecurityAzureFoundryConfigService(
            NamedParameterJdbcTemplate jdbc,
            TenantSchemaExecutionService tenantExecution,
            AzureDiscoveryConfigService discoveryConfigService,
            AzureDiscoveryTargetService discoveryTargetService,
            AiSecurityAzureCredentialService credentialService,
            AiSecurityAzureConnectorService connectorService
    ) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.discoveryConfigService = discoveryConfigService;
        this.discoveryTargetService = discoveryTargetService;
        this.credentialService = credentialService;
        this.connectorService = connectorService;
    }

    public FoundryConfigResponse get(Tenant tenant) {
        AzureDiscoveryConfigResponse config = discoveryConfigService.get(tenant);
        ConnectorResponse connector = firstConnector(tenant);
        CredentialProfileResponse profile = firstActiveProfile(tenant);
        return toResponse(tenant, config, connector, profile);
    }

    public FoundryConfigResponse save(Tenant tenant, FoundryConfigRequest request, String actor) {
        List<String> subscriptionIds = splitCsv(request == null ? null : request.subscriptionIds());
        List<String> regions = splitCsv(request == null ? null : request.region());
        if (request == null || !hasText(request.azureTenantId()) || !hasText(request.clientId())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tenant ID and Client ID are required");
        }
        if (subscriptionIds.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one subscription ID is required");
        }
        final List<String> resolvedRegions = regions.isEmpty() ? List.of(DEFAULT_REGION) : regions;
        String primarySubscriptionId = subscriptionIds.get(0);
        boolean secretProvided = hasText(request.clientSecret());

        // Save the config with an empty subscription list first. AzureDiscoveryTargetService's
        // legacy bootstrap (ensureLegacyTarget) auto-provisions a target from this same JSON list
        // the moment anything reads the config, and self-conflicts if we also explicitly create a
        // target for a subscription that's already listed here. Populate the list (step 2, below)
        // only once the target genuinely exists, so that legacy bootstrap has nothing left to do.
        discoveryConfigService.saveForAiSecurity(tenant, new AzureDiscoveryConfigRequest(
                AzureAuthType.CLIENT_SECRET,
                request.azureTenantId(),
                request.clientId(),
                secretProvided ? request.clientSecret().trim() : null,
                toJsonArray(List.of()),
                toJsonArray(resolvedRegions),
                true, false, 1440));

        AzureDiscoveryTargetResponse target = resolveTarget(tenant, primarySubscriptionId, resolvedRegions);

        discoveryConfigService.saveForAiSecurity(tenant, new AzureDiscoveryConfigRequest(
                AzureAuthType.CLIENT_SECRET,
                request.azureTenantId(),
                request.clientId(),
                null,
                toJsonArray(subscriptionIds),
                toJsonArray(resolvedRegions),
                true, false, 1440));

        UUID profileId = resolveCredentialProfile(tenant, request, primarySubscriptionId, secretProvided, actor);

        ConnectorResponse connector = connectorService.save(
                tenant, new ConnectorRequest(profileId, target.id(), null, true));
        persistFoundryEndpointUrl(tenant, connector.id(), request.foundryEndpointUrl());

        return get(tenant);
    }

    public ConnectionTestResponse test(Tenant tenant, String actor) {
        return connectorService.test(tenant, requireConnectorId(tenant), actor);
    }

    public IngestionJobAcceptedResponse run(Tenant tenant, String actor) {
        return connectorService.trigger(tenant, requireConnectorId(tenant), actor);
    }

    /**
     * AzureDiscoveryTargetService.list() runs read-only and, as a side effect, lazily
     * auto-provisions a target from the config's subscription list the first time it's called
     * for a tenant (ensureLegacyTarget). Under a read-only transaction that provisioning insert
     * is not guaranteed to be visible to the very same list() call's own read, so a target we
     * just caused to exist can still look "missing" here. Re-list once before falling back to an
     * explicit create, and if an explicit create still loses a race against that side effect,
     * recover by re-reading rather than surfacing the resulting unique-constraint conflict.
     */
    private AzureDiscoveryTargetResponse resolveTarget(Tenant tenant, String subscriptionId, List<String> regions) {
        AzureDiscoveryTargetResponse target = findTarget(discoveryTargetService.listForAiSecurity(tenant), subscriptionId);
        if (target != null) {
            return target;
        }
        target = findTarget(discoveryTargetService.listForAiSecurity(tenant), subscriptionId);
        if (target != null) {
            return target;
        }
        try {
            return discoveryTargetService.createForAiSecurity(tenant, new AzureDiscoveryTargetRequest(
                    subscriptionId, null, true, toJsonArray(regions)));
        } catch (DataIntegrityViolationException raced) {
            AzureDiscoveryTargetResponse recovered = findTarget(discoveryTargetService.listForAiSecurity(tenant), subscriptionId);
            if (recovered == null) {
                throw raced;
            }
            return recovered;
        }
    }

    private AzureDiscoveryTargetResponse findTarget(List<AzureDiscoveryTargetResponse> targets, String subscriptionId) {
        return targets.stream()
                .filter(candidate -> subscriptionId.equals(candidate.subscriptionId()))
                .findFirst()
                .orElse(null);
    }

    private UUID resolveCredentialProfile(
            Tenant tenant, FoundryConfigRequest request, String primarySubscriptionId, boolean secretProvided, String actor) {
        CredentialProfileResponse existing = firstActiveProfile(tenant);
        UUID profileId;
        if (existing == null) {
            if (!secretProvided) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A client secret is required for first-time setup");
            }
            deleteProfilesByName(tenant, PROFILE_NAME, null);
            CredentialProfileResponse created = credentialService.create(tenant, new CredentialProfileRequest(
                    PROFILE_NAME, request.azureTenantId(), request.clientId(), request.clientSecret().trim(),
                    Instant.now().plus(365, ChronoUnit.DAYS)), actor);
            profileId = created.id();
        } else {
            profileId = existing.id();
            if (secretProvided) {
                try {
                    credentialService.rotate(tenant, profileId, new RotateCredentialRequest(
                            request.clientSecret().trim(), Instant.now().plus(365, ChronoUnit.DAYS), primarySubscriptionId), actor);
                } catch (CredentialDecryptionException ignored) {
                    // The prior key is unavailable. A new supplied secret is the recovery path:
                    // remove the unreadable profile and its binding, then create a replacement.
                    deleteProfilesByName(tenant, PROFILE_NAME, null);
                    CredentialProfileResponse created = credentialService.create(tenant, new CredentialProfileRequest(
                            PROFILE_NAME, request.azureTenantId(), request.clientId(), request.clientSecret().trim(),
                            Instant.now().plus(365, ChronoUnit.DAYS)), actor);
                    profileId = created.id();
                }
            }
        }
        // Defensive cleanup: remove any stale duplicate/revoked profiles left over from earlier
        // manual testing so the (tenant, name) unique slot never conflicts on a future save.
        deleteProfilesByName(tenant, PROFILE_NAME, profileId);
        return profileId;
    }

    private ConnectorResponse firstConnector(Tenant tenant) {
        return connectorService.list(tenant).stream().findFirst().orElse(null);
    }

    private CredentialProfileResponse firstActiveProfile(Tenant tenant) {
        return credentialService.list(tenant).stream()
                .filter(profile -> "ACTIVE".equals(profile.status()))
                .findFirst()
                .orElse(null);
    }

    private UUID requireConnectorId(Tenant tenant) {
        ConnectorResponse connector = firstConnector(tenant);
        if (connector == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Save the Azure Foundry configuration first");
        }
        return connector.id();
    }

    private void deleteProfilesByName(Tenant tenant, String name, UUID keepId) {
        String keepClause = keepId == null ? "" : "and id <> :keepId";
        tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("tenantId", tenant.getId())
                    .addValue("name", name);
            if (keepId != null) {
                params.addValue("keepId", keepId);
            }
            jdbc.update("""
                    delete from ai_security_connector_configs
                     where provider = 'AZURE'
                       and credential_profile_id in (
                           select id from ai_security_azure_credential_profiles
                            where tenant_id = :tenantId and name = :name %s
                       )
                    """.formatted(keepClause), params);
            return jdbc.update("""
                    delete from ai_security_azure_credential_profiles
                     where tenant_id = :tenantId and name = :name %s
                    """.formatted(keepClause), params);
        });
    }

    private void persistFoundryEndpointUrl(Tenant tenant, UUID connectorId, String foundryEndpointUrl) {
        tenantExecution.run(tenant, () -> jdbc.update("""
                update ai_security_connector_configs
                   set foundry_endpoint_url = :url
                 where id = :id
                """, new MapSqlParameterSource()
                .addValue("url", trimToNull(foundryEndpointUrl))
                .addValue("id", connectorId)));
    }

    private String readFoundryEndpointUrl(Tenant tenant, UUID connectorId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select foundry_endpoint_url from ai_security_connector_configs where id = :id
                """, Map.of("id", connectorId),
                rs -> rs.next() ? rs.getString("foundry_endpoint_url") : null));
    }

    private FoundryConfigResponse toResponse(
            Tenant tenant, AzureDiscoveryConfigResponse config, ConnectorResponse connector, CredentialProfileResponse profile) {
        String foundryEndpointUrl = connector == null ? null : readFoundryEndpointUrl(tenant, connector.id());
        return new FoundryConfigResponse(
                connector != null,
                config.azureTenantId(),
                config.clientId(),
                config.hasCredential(),
                connector != null ? connector.subscriptionId() : null,
                parseJsonArray(config.subscriptionIdsJson()),
                parseJsonArray(config.regionsJson()),
                foundryEndpointUrl,
                connector != null ? connector.id() : null,
                profile != null ? profile.expiresAt() : null);
    }

    private List<String> splitCsv(String value) {
        if (!hasText(value)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (String part : value.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    private String toJsonArray(List<String> values) {
        StringBuilder builder = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) builder.append(',');
            builder.append('"').append(values.get(i).replace("\"", "\\\"")).append('"');
        }
        return builder.append(']').toString();
    }

    private List<String> parseJsonArray(String json) {
        if (!hasText(json)) {
            return List.of();
        }
        String trimmed = json.trim();
        if (trimmed.length() < 2) {
            return List.of();
        }
        String inner = trimmed.substring(1, trimmed.length() - 1).trim();
        if (inner.isEmpty()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        for (String part : inner.split(",")) {
            String cleaned = part.trim().replaceAll("^\"|\"$", "");
            if (!cleaned.isEmpty()) {
                values.add(cleaned);
            }
        }
        return values;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String trimToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    public record FoundryConfigRequest(
            String foundryEndpointUrl,
            String azureTenantId,
            String clientId,
            String clientSecret,
            String subscriptionIds,
            String region
    ) {
    }

    public record FoundryConfigResponse(
            boolean configured,
            String azureTenantId,
            String clientId,
            boolean hasCredential,
            String primarySubscriptionId,
            List<String> subscriptionIds,
            List<String> regions,
            String foundryEndpointUrl,
            UUID connectorId,
            Instant credentialExpiresAt
    ) {
    }
}
