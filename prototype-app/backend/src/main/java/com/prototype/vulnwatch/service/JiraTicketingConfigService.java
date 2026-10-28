package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.JiraAuthType;
import com.prototype.vulnwatch.domain.JiraTicketingConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.JiraConnectionTestResponse;
import com.prototype.vulnwatch.dto.JiraTicketingConfigRequest;
import com.prototype.vulnwatch.dto.JiraTicketingConfigResponse;
import com.prototype.vulnwatch.repo.JiraTicketingConfigRepository;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * Owns the per-tenant Jira connector record: read, save, and connection test.
 *
 * <p>Mirrors {@link ServiceNowCmdbConfigService} deliberately — same credential encryption,
 * same outbound host allowlist check at save time, same write-only secret handling — so the
 * two ticketing connectors have one security posture rather than two.
 */
@Service
public class JiraTicketingConfigService {

    private static final Logger log = LoggerFactory.getLogger(JiraTicketingConfigService.class);

    /** Provider key used for outbound pacing and host allowlisting. */
    public static final String PROVIDER_KEY = "jira";

    private final JiraTicketingConfigRepository jiraTicketingConfigRepository;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService credentialEncryptionService;
    private final OutboundHostPolicy outboundHostPolicy;

    public JiraTicketingConfigService(
            JiraTicketingConfigRepository jiraTicketingConfigRepository,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService,
            OutboundHostPolicy outboundHostPolicy
    ) {
        this.jiraTicketingConfigRepository = jiraTicketingConfigRepository;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.tenantQuotaService = tenantQuotaService;
        this.credentialEncryptionService = credentialEncryptionService;
        this.outboundHostPolicy = outboundHostPolicy;
    }

    @Transactional(readOnly = true)
    public JiraTicketingConfigResponse get(Tenant tenant) {
        return toResponse(findConfig(tenant).orElse(null));
    }

    @Transactional
    public JiraTicketingConfigResponse save(Tenant tenant, JiraTicketingConfigRequest request) {
        JiraTicketingConfig config = findConfig(tenant).orElseGet(() -> {
            tenantQuotaService.assertCanCreateConnector(tenant, PROVIDER_KEY);
            JiraTicketingConfig created = new JiraTicketingConfig();
            created.setTenant(tenant);
            return created;
        });
        apply(config, request);
        config.touch();
        return toResponse(jiraTicketingConfigRepository.save(config));
    }

    /**
     * Verifies the stored credentials and that the configured project is reachable.
     *
     * <p>Two probes rather than one: credentials valid but project unreachable is the common
     * misconfiguration (wrong project key, or the account lacks Browse Projects), and the
     * operator needs to be told which of the two failed.
     */
    @Transactional
    public JiraConnectionTestResponse test(Tenant tenant) {
        JiraRuntimeConfig runtime = resolveRuntimeConfig(tenant).orElseThrow(
                () -> new ResponseStatusException(BAD_REQUEST, "Jira connector is not configured yet"));
        validate(runtime);

        Instant testedAt = Instant.now();
        ProbeResult credentials = probe(runtime, "/rest/api/3/myself", "Jira credential check");
        ProbeResult project = credentials.success()
                ? probe(runtime, "/rest/api/3/project/" + runtime.projectKey(), "Jira project check")
                : new ProbeResult(false, "Skipped — credentials could not be verified");

        boolean success = credentials.success() && project.success();
        String message = success
                ? "Jira connection succeeded. Project " + runtime.projectKey() + " is reachable."
                : (credentials.success() ? project.message() : credentials.message());

        findConfig(tenant).ifPresent(config -> {
            config.setLastTestStatus(success ? "SUCCESS" : "FAILED");
            config.setLastTestMessage(message);
            config.setLastTestedAt(testedAt);
            config.touch();
            jiraTicketingConfigRepository.save(config);
        });

        return new JiraConnectionTestResponse(
                success ? "SUCCESS" : "FAILED", message, credentials.success(), project.success(), testedAt);
    }

    /**
     * Decrypted, defaulted view of the tenant's Jira settings.
     * Returns empty when no connector row exists — there is deliberately no environment-level
     * fallback, because a shared Jira project across tenants would leak findings between them.
     */
    @Transactional(readOnly = true)
    public Optional<JiraRuntimeConfig> resolveRuntimeConfig(Tenant tenant) {
        return findConfig(tenant).map(config -> new JiraRuntimeConfig(
                trimToNull(config.getBaseUrl()),
                config.getAuthType() == null ? JiraAuthType.BASIC : config.getAuthType(),
                trimToNull(config.getUsername()),
                trimToNull(credentialEncryptionService.decrypt(config.getCredentialSecret())),
                trimToNull(config.getProjectKey()),
                trimToNull(config.getIssueTypeId()),
                defaultIfBlank(config.getIssueTypeName(), "Task"),
                trimToNull(config.getDefaultLabels()),
                config.isIncludePriority(),
                config.isEnabled()
        ));
    }

    /**
     * Whether Jira should receive new tickets for this tenant.
     *
     * <p>Unlike the ServiceNow connector, {@code enabled} is honoured here: turning Jira off is
     * the operator's way of handing ticketing back to ServiceNow, so it has to be respected or
     * the override could never be undone without deleting the connector.
     */
    @Transactional(readOnly = true)
    public boolean isReadyForTicketing(Tenant tenant) {
        return findConfig(tenant)
                .filter(JiraTicketingConfig::isEnabled)
                .filter(config -> hasText(config.getBaseUrl()))
                .filter(config -> hasText(config.getProjectKey()))
                .filter(config -> hasText(config.getCredentialSecret()))
                .isPresent();
    }

    Optional<JiraTicketingConfig> findConfig(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return Optional.empty();
        }
        return jiraTicketingConfigRepository.findByTenant_Id(tenant.getId());
    }

    private void apply(JiraTicketingConfig config, JiraTicketingConfigRequest request) {
        config.setBaseUrl(normalizeBaseUrl(request.baseUrl()));
        config.setAuthType(parseAuthType(request.authType()));
        config.setUsername(trimToNull(request.username()));
        if (hasText(request.credentialSecret())) {
            config.setCredentialSecret(credentialEncryptionService.encrypt(request.credentialSecret().trim()));
        }
        config.setProjectKey(normalizeProjectKey(request.projectKey()));
        config.setIssueTypeId(trimToNull(request.issueTypeId()));
        config.setIssueTypeName(defaultIfBlank(request.issueTypeName(), "Task"));
        config.setDefaultLabels(trimToNull(request.defaultLabels()));
        config.setIncludePriority(request.includePriority() == null || request.includePriority());
        config.setEnabled(request.enabled() == null || request.enabled());

        validate(new JiraRuntimeConfig(
                config.getBaseUrl(),
                config.getAuthType(),
                config.getUsername(),
                config.getCredentialSecret(),
                config.getProjectKey(),
                config.getIssueTypeId(),
                config.getIssueTypeName(),
                config.getDefaultLabels(),
                config.isIncludePriority(),
                config.isEnabled()
        ));
    }

    private void validate(JiraRuntimeConfig config) {
        if (!hasText(config.baseUrl())) {
            throw new ResponseStatusException(BAD_REQUEST, "Jira base URL is required");
        }
        try {
            outboundHostPolicy.validate(PROVIDER_KEY, URI.create(config.baseUrl().trim()));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(BAD_REQUEST,
                    "Jira base URL is not an approved outbound endpoint. Add the host to the "
                            + "'jira=' entry of HTTP_OUTBOUND_ALLOWED_HOSTS.", ex);
        }
        if (config.authType() == JiraAuthType.BASIC && !hasText(config.username())) {
            throw new ResponseStatusException(BAD_REQUEST,
                    "Jira account email is required for basic auth");
        }
        if (!hasText(config.credentialSecret())) {
            throw new ResponseStatusException(BAD_REQUEST, "Jira API token is required");
        }
        if (!hasText(config.projectKey())) {
            throw new ResponseStatusException(BAD_REQUEST, "Jira project key is required");
        }
        if (!hasText(config.issueTypeId()) && !hasText(config.issueTypeName())) {
            throw new ResponseStatusException(BAD_REQUEST, "A Jira issue type id or name is required");
        }
    }

    private ProbeResult probe(JiraRuntimeConfig config, String path, String operationName) {
        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    config.baseUrl() + path,
                    HttpMethod.GET,
                    new HttpEntity<Void>(authHeaders(config)),
                    String.class,
                    operationName,
                    outboundPolicyFactory.forProvider(PROVIDER_KEY, 0L, null, null),
                    context -> new OutboundFailureDecision<RuntimeException>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte
                                    ? rte
                                    : new RuntimeException(operationName + " failed: "
                                            + context.error().getMessage(), context.error())));
            if (response.getStatusCode().is2xxSuccessful()) {
                return new ProbeResult(true, operationName + " succeeded");
            }
            return new ProbeResult(false, operationName + " returned HTTP " + response.getStatusCode().value());
        } catch (RuntimeException ex) {
            log.warn("{} failed: {}", operationName, ex.getMessage());
            return new ProbeResult(false, operationName + " failed: " + ex.getMessage());
        }
    }

    /** Builds the Authorization header for either Jira Cloud basic auth or a Data Center PAT. */
    public static HttpHeaders authHeaders(JiraRuntimeConfig config) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(java.util.List.of(MediaType.APPLICATION_JSON));
        if (config.authType() == JiraAuthType.BEARER) {
            headers.setBearerAuth(config.credentialSecret());
        } else {
            String raw = (config.username() == null ? "" : config.username()) + ":" + config.credentialSecret();
            headers.set(HttpHeaders.AUTHORIZATION, "Basic "
                    + java.util.Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));
        }
        return headers;
    }

    private JiraTicketingConfigResponse toResponse(JiraTicketingConfig config) {
        if (config == null) {
            return new JiraTicketingConfigResponse(
                    null, false, null, JiraAuthType.BASIC.name(), null, false,
                    null, null, "Task", null, true, false, null, null, null);
        }
        return new JiraTicketingConfigResponse(
                config.getId(),
                true,
                config.getBaseUrl(),
                (config.getAuthType() == null ? JiraAuthType.BASIC : config.getAuthType()).name(),
                config.getUsername(),
                hasText(config.getCredentialSecret()),
                config.getProjectKey(),
                config.getIssueTypeId(),
                config.getIssueTypeName(),
                config.getDefaultLabels(),
                config.isIncludePriority(),
                config.isEnabled(),
                config.getLastTestStatus(),
                config.getLastTestMessage(),
                config.getLastTestedAt()
        );
    }

    private static String normalizeBaseUrl(String value) {
        String trimmed = trimToNull(value);
        if (trimmed == null) {
            return null;
        }
        // A trailing slash would produce '//rest/api/3/...' on every request.
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String normalizeProjectKey(String value) {
        String trimmed = trimToNull(value);
        return trimmed == null ? null : trimmed.toUpperCase(Locale.ROOT);
    }

    private static JiraAuthType parseAuthType(String value) {
        if (!hasText(value)) {
            return JiraAuthType.BASIC;
        }
        try {
            return JiraAuthType.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(BAD_REQUEST, "Unsupported Jira auth type: " + value);
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static String trimToNull(String value) {
        return hasText(value) ? value.trim() : null;
    }

    private static String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    /** Decrypted, defaulted Jira settings for a single tenant. */
    public record JiraRuntimeConfig(
            String baseUrl,
            JiraAuthType authType,
            String username,
            String credentialSecret,
            String projectKey,
            String issueTypeId,
            String issueTypeName,
            String defaultLabels,
            boolean includePriority,
            boolean enabled
    ) {
    }

    private record ProbeResult(boolean success, String message) {
    }
}
