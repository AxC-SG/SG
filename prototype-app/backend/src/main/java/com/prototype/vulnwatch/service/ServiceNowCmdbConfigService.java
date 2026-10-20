package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigRequest;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigResponse;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConnectionTestResponse;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
public class ServiceNowCmdbConfigService {

    public static final String DEFAULT_INSTALL_FIELDS = String.join(",",
            "sys_id",
            "display_name",
            "publisher",
            "version",
            "install_date",
            "last_scanned",
            "last_used",
            "active_install",
            "unlicensed_install",
            "installed_on",
            "discovery_model",
            // CI-level ownership fields via dot-walking
            "installed_on.owned_by",
            "installed_on.managed_by",
            "installed_on.assigned_to",
            "installed_on.department",
            "installed_on.support_group"
    );

    public static final String DEFAULT_DISCOVERY_FIELDS = String.join(",",
            "sys_id",
            "primary_key",
            "normalized_product",
            "normalized_publisher",
            "normalized_version",
            "product_hash",
            "version_hash",
            "full_version",
            "platform",
            "language",
            "normalization_status",
            "approved",
            "low_confidence"
    );

    private final ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService credentialEncryptionService;
    private final OutboundHostPolicy outboundHostPolicy;

    @Autowired
    public ServiceNowCmdbConfigService(
            ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService,
            OutboundHostPolicy outboundHostPolicy
    ) {
        this.serviceNowCmdbConfigRepository = serviceNowCmdbConfigRepository;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.tenantQuotaService = tenantQuotaService;
        this.credentialEncryptionService = credentialEncryptionService;
        this.outboundHostPolicy = outboundHostPolicy;
    }

    public ServiceNowCmdbConfigService(
            ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService
    ) {
        this(serviceNowCmdbConfigRepository, outboundHttpClient, outboundPolicyFactory, objectMapper,
                tenantQuotaService, credentialEncryptionService, new OutboundHostPolicy("servicenow=acme.service-now.example"));
    }

    @Transactional(readOnly = true)
    public ServiceNowCmdbConfigResponse get(Tenant tenant) {
        return toResponse(findConfig(tenant).orElse(null));
    }

    @Transactional
    public ServiceNowCmdbConfigResponse save(Tenant tenant, ServiceNowCmdbConfigRequest request) {
        ServiceNowCmdbConfig config = findConfig(tenant).orElseGet(() -> {
            tenantQuotaService.assertCanCreateConnector(tenant, "servicenow");
            ServiceNowCmdbConfig created = new ServiceNowCmdbConfig();
            created.setTenant(tenant);
            created.setSourceSystem("servicenow");
            return created;
        });
        apply(config, request);
        config.touch();
        return toResponse(serviceNowCmdbConfigRepository.save(config));
    }

    @Transactional
    public ServiceNowCmdbConnectionTestResponse test(Tenant tenant) {
        ServiceNowRuntimeConfig runtimeConfig = resolveRuntimeConfig(tenant).orElseThrow(
                () -> new ResponseStatusException(BAD_REQUEST, "ServiceNow CMDB connector is not configured yet")
        );
        validate(runtimeConfig);

        Instant testedAt = Instant.now();
        ProbeResult ciProbe = probeTable(runtimeConfig, runtimeConfig.ciTable(), null, "sys_id");
        ProbeResult installProbe = probeTable(runtimeConfig, runtimeConfig.installTable(), runtimeConfig.installQuery(), "sys_id");
        ProbeResult discoveryProbe = probeTable(
                runtimeConfig,
                runtimeConfig.discoveryModelTable(),
                runtimeConfig.discoveryQuery(),
                "sys_id"
        );
        boolean success = ciProbe.success() && installProbe.success() && discoveryProbe.success();
        String message = success
                ? "ServiceNow CMDB connection succeeded. Required tables are reachable."
                : joinMessages(ciProbe, installProbe, discoveryProbe);

        findConfig(tenant).ifPresent(config -> {
            config.setLastTestStatus(success ? "SUCCESS" : "FAILED");
            config.setLastTestMessage(message);
            config.setLastTestedAt(testedAt);
            config.touch();
            serviceNowCmdbConfigRepository.save(config);
        });

        return new ServiceNowCmdbConnectionTestResponse(
                success ? "SUCCESS" : "FAILED",
                message,
                ciProbe.success(),
                installProbe.success(),
                discoveryProbe.success(),
                testedAt
        );
    }

    @Transactional(readOnly = true)
    public Optional<ServiceNowRuntimeConfig> resolveRuntimeConfig(Tenant tenant) {
        Optional<ServiceNowCmdbConfig> saved = findConfig(tenant);
        if (saved.isPresent()) {
            ServiceNowCmdbConfig config = saved.get();
            return Optional.of(new ServiceNowRuntimeConfig(
                    trimToNull(config.getBaseUrl()),
                    config.getAuthType() == null ? ServiceNowAuthType.BASIC : config.getAuthType(),
                    trimToNull(config.getUsername()),
                    trimToNull(credentialEncryptionService.decrypt(config.getCredentialSecret())),
                    defaultIfBlank(config.getInstallTable(), "cmdb_sam_sw_install"),
                    defaultIfBlank(config.getDiscoveryModelTable(), "cmdb_sam_sw_discovery_model"),
                    defaultIfBlank(config.getCiTable(), "cmdb_ci"),
                    trimToNull(config.getInstallQuery()),
                    trimToNull(config.getDiscoveryQuery()),
                    defaultIfBlank(config.getInstallFields(), DEFAULT_INSTALL_FIELDS),
                    defaultIfBlank(config.getDiscoveryFields(), DEFAULT_DISCOVERY_FIELDS),
                    config.getPageSize() == null ? 1000 : Math.max(1, Math.min(10_000, config.getPageSize())),
                    config.isEnabled(),
                    config.isAutoSyncEnabled(),
                    config.getIntervalMinutes() == null ? 1440 : Math.max(5, config.getIntervalMinutes())
            ));
        }
        return Optional.empty();
    }

    Optional<ServiceNowCmdbConfig> findConfig(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return Optional.empty();
        }
        return serviceNowCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow");
    }

    private void apply(ServiceNowCmdbConfig config, ServiceNowCmdbConfigRequest request) {
        ServiceNowAuthType authType = parseAuthType(request.authType());
        config.setBaseUrl(trimToNull(request.baseUrl()));
        config.setAuthType(authType);
        config.setUsername(trimToNull(request.username()));
        if (hasText(request.credentialSecret())) {
            config.setCredentialSecret(credentialEncryptionService.encrypt(request.credentialSecret().trim()));
        }
        config.setInstallTable(defaultIfBlank(request.installTable(), "cmdb_sam_sw_install"));
        config.setDiscoveryModelTable(defaultIfBlank(request.discoveryModelTable(), "cmdb_sam_sw_discovery_model"));
        config.setCiTable(defaultIfBlank(request.ciTable(), "cmdb_ci"));
        config.setInstallQuery(trimToNull(request.installQuery()));
        config.setDiscoveryQuery(trimToNull(request.discoveryQuery()));
        config.setInstallFields(defaultIfBlank(request.installFields(), DEFAULT_INSTALL_FIELDS));
        config.setDiscoveryFields(defaultIfBlank(request.discoveryFields(), DEFAULT_DISCOVERY_FIELDS));
        config.setPageSize(request.pageSize() == null ? 1000 : Math.max(1, Math.min(10_000, request.pageSize())));
        config.setEnabled(request.enabled() == null || request.enabled());
        config.setAutoSyncEnabled(request.autoSyncEnabled() != null && request.autoSyncEnabled());
        config.setIntervalMinutes(request.intervalMinutes() == null ? 1440 : Math.max(5, request.intervalMinutes()));

        ServiceNowRuntimeConfig runtimeConfig = new ServiceNowRuntimeConfig(
                config.getBaseUrl(),
                config.getAuthType(),
                config.getUsername(),
                config.getCredentialSecret(),
                config.getInstallTable(),
                config.getDiscoveryModelTable(),
                config.getCiTable(),
                config.getInstallQuery(),
                config.getDiscoveryQuery(),
                config.getInstallFields(),
                config.getDiscoveryFields(),
                config.getPageSize(),
                config.isEnabled(),
                config.isAutoSyncEnabled(),
                config.getIntervalMinutes()
        );
        validate(runtimeConfig);
    }

    private ProbeResult probeTable(ServiceNowRuntimeConfig config, String tableName, String query, String fields) {
        try {
            int probePageSize = Math.max(1, Math.min(25, config.pageSize()));
            String uri = UriComponentsBuilder.fromHttpUrl(config.baseUrl())
                    .path("/api/now/table/{tableName}")
                    .queryParam("sysparm_fields", fields)
                    .queryParam("sysparm_limit", probePageSize)
                    .queryParam("sysparm_offset", 0)
                    .queryParam("sysparm_display_value", ServiceNowCmdbSyncService.displayValueModeForTable(config, tableName))
                    .queryParam("sysparm_exclude_reference_link", "true")
                    .queryParamIfPresent("sysparm_query", Optional.ofNullable(trimToNull(query)))
                    .buildAndExpand(tableName)
                    .toUriString();
            HttpHeaders headers = buildHeaders(config);
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    uri,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class,
                    "ServiceNow CMDB probe",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    )
            );
            if (!response.getStatusCode().is2xxSuccessful()) {
                return new ProbeResult(false, tableName + " returned HTTP " + response.getStatusCode().value());
            }
            JsonNode root = ServiceNowApiResponseParser.parseJson(
                    objectMapper,
                    response,
                    "ServiceNow table " + tableName
            );
            if (!root.has("result")) {
                return new ProbeResult(false, tableName + " did not return a ServiceNow result payload");
            }
            return new ProbeResult(true, tableName + " reachable");
        } catch (Exception e) {
            return new ProbeResult(false, tableName + " failed: " + e.getMessage());
        }
    }

    private HttpHeaders buildHeaders(ServiceNowRuntimeConfig config) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        if (config.authType() == ServiceNowAuthType.BEARER) {
            headers.setBearerAuth(config.credentialSecret());
        } else {
            headers.setBasicAuth(
                    config.username(),
                    config.credentialSecret() == null ? "" : config.credentialSecret(),
                    StandardCharsets.UTF_8
            );
        }
        return headers;
    }

    private void validate(ServiceNowRuntimeConfig config) {
        if (!hasText(config.baseUrl())) {
            throw new ResponseStatusException(BAD_REQUEST, "ServiceNow base URL is required");
        }
        try {
            outboundHostPolicy.validate("servicenow", java.net.URI.create(config.baseUrl().trim()));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(BAD_REQUEST, "ServiceNow base URL is not an approved public HTTPS endpoint", ex);
        }
        if (config.authType() == ServiceNowAuthType.BASIC && !hasText(config.username())) {
            throw new ResponseStatusException(BAD_REQUEST, "ServiceNow username is required for basic auth");
        }
        if (!hasText(config.credentialSecret())) {
            throw new ResponseStatusException(BAD_REQUEST, "ServiceNow password or token is required");
        }
        if (!hasText(config.installTable())) {
            throw new ResponseStatusException(BAD_REQUEST, "Install table is required");
        }
        if (!hasText(config.discoveryModelTable())) {
            throw new ResponseStatusException(BAD_REQUEST, "Discovery model table is required");
        }
        if (!hasText(config.ciTable())) {
            throw new ResponseStatusException(BAD_REQUEST, "CI lookup table is required");
        }
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("servicenow", 0L, null, null);
    }

    private ServiceNowCmdbConfigResponse toResponse(ServiceNowCmdbConfig config) {
        if (config == null) {
            return new ServiceNowCmdbConfigResponse(
                    null,
                    "servicenow",
                    false,
                    "",
                    ServiceNowAuthType.BASIC.name(),
                    "",
                    false,
                    "cmdb_sam_sw_install",
                    "cmdb_sam_sw_discovery_model",
                    "cmdb_ci",
                    "",
                    "",
                    DEFAULT_INSTALL_FIELDS,
                    DEFAULT_DISCOVERY_FIELDS,
                    1000,
                    true,
                    false,
                    1440,
                    null,
                    null,
                    null,
                    null
            );
        }
        return new ServiceNowCmdbConfigResponse(
                config.getId(),
                config.getSourceSystem(),
                hasText(config.getBaseUrl()) && hasText(config.getCredentialSecret()),
                defaultIfBlank(config.getBaseUrl(), ""),
                (config.getAuthType() == null ? ServiceNowAuthType.BASIC : config.getAuthType()).name(),
                defaultIfBlank(config.getUsername(), ""),
                hasText(config.getCredentialSecret()),
                defaultIfBlank(config.getInstallTable(), "cmdb_sam_sw_install"),
                defaultIfBlank(config.getDiscoveryModelTable(), "cmdb_sam_sw_discovery_model"),
                defaultIfBlank(config.getCiTable(), "cmdb_ci"),
                defaultIfBlank(config.getInstallQuery(), ""),
                defaultIfBlank(config.getDiscoveryQuery(), ""),
                defaultIfBlank(config.getInstallFields(), DEFAULT_INSTALL_FIELDS),
                defaultIfBlank(config.getDiscoveryFields(), DEFAULT_DISCOVERY_FIELDS),
                config.getPageSize() == null ? 1000 : config.getPageSize(),
                config.isEnabled(),
                config.isAutoSyncEnabled(),
                config.getIntervalMinutes() == null ? 1440 : config.getIntervalMinutes(),
                config.getLastTestStatus(),
                config.getLastTestMessage(),
                config.getLastTestedAt(),
                config.getLastSyncAt()
        );
    }

    private ServiceNowAuthType parseAuthType(String value) {
        if (!hasText(value)) {
            return ServiceNowAuthType.BASIC;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        try {
            return ServiceNowAuthType.valueOf(normalized);
        } catch (IllegalArgumentException ignored) {
            throw new ResponseStatusException(BAD_REQUEST, "Unsupported ServiceNow auth type: " + value);
        }
    }

    private String joinMessages(ProbeResult ciProbe, ProbeResult installProbe, ProbeResult discoveryProbe) {
        return String.join(
                " ",
                List.of(ciProbe.message(), installProbe.message(), discoveryProbe.message()).stream()
                        .filter(this::hasText)
                        .toList()
        );
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    public record ServiceNowRuntimeConfig(
            String baseUrl,
            ServiceNowAuthType authType,
            String username,
            String credentialSecret,
            String installTable,
            String discoveryModelTable,
            String ciTable,
            String installQuery,
            String discoveryQuery,
            String installFields,
            String discoveryFields,
            Integer pageSize,
            boolean enabled,
            boolean autoSyncEnabled,
            Integer intervalMinutes
    ) {
    }

    private record ProbeResult(
            boolean success,
            String message
    ) {
    }
}
