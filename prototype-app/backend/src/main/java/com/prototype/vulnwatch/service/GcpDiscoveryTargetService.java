package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GcpServiceAccountKey;
import com.prototype.vulnwatch.client.GcpDiscoveryClient;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.GcpApiException;
import com.prototype.vulnwatch.client.GcpTokenSource;
import com.prototype.vulnwatch.domain.GcpDiscoveryConfig;
import com.prototype.vulnwatch.domain.GcpDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GcpConnectionTestResponse;
import com.prototype.vulnwatch.dto.GcpConnectionTestResponse.PermissionCheck;
import com.prototype.vulnwatch.dto.GcpDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.GcpDiscoveryTargetResponse;
import com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/** Customer GCP projects discovered through a tenant's connector, and their connection tests. */
@Service
public class GcpDiscoveryTargetService {

    private final GcpDiscoveryTargetRepository targets;
    private final GcpDiscoveryConfigRepository configs;
    private final GcpDiscoveryConfigService configService;
    private final GcpDiscoveryClient client;
    private final GcpTokenSource tokens;
    private final TenantQuotaService tenantQuotaService;
    private final ObjectMapper objectMapper;

    public GcpDiscoveryTargetService(
            GcpDiscoveryTargetRepository targets,
            GcpDiscoveryConfigRepository configs,
            GcpDiscoveryConfigService configService,
            GcpDiscoveryClient client,
            GcpTokenSource tokens,
            TenantQuotaService tenantQuotaService,
            ObjectMapper objectMapper
    ) {
        this.targets = targets;
        this.configs = configs;
        this.configService = configService;
        this.client = client;
        this.tokens = tokens;
        this.tenantQuotaService = tenantQuotaService;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public List<GcpDiscoveryTargetResponse> list(Tenant tenant) {
        return configService.findConfig(tenant)
                .map(config -> targets.findByConfigOrderByProjectIdAsc(config).stream().map(this::toResponse).toList())
                .orElse(List.of());
    }

    @Transactional
    public GcpDiscoveryTargetResponse create(Tenant tenant, GcpDiscoveryTargetRequest request) {
        GcpDiscoveryConfig config = configService.requireConfig(tenant);
        String projectId = projectId(request);
        if (targets.findByConfigAndProjectId(config, projectId).isPresent()) {
            throw new ResponseStatusException(CONFLICT, "GCP project " + projectId + " is already a discovery target");
        }
        tenantQuotaService.assertCanCreateConnector(tenant, "gcp-target");
        GcpDiscoveryTarget target = new GcpDiscoveryTarget();
        target.setTenant(tenant);
        target.setConfig(config);
        target.setProjectId(projectId);
        apply(target, request);
        return toResponse(targets.save(target));
    }

    @Transactional
    public GcpDiscoveryTargetResponse update(Tenant tenant, UUID targetId, GcpDiscoveryTargetRequest request) {
        GcpDiscoveryTarget target = requireTarget(tenant, targetId);
        if (request != null && request.projectId() != null && !projectId(request).equals(target.getProjectId())) {
            // Assets and history are keyed by project; a different project is a different target.
            throw new ResponseStatusException(BAD_REQUEST, "A target's project cannot be changed; add a new target instead");
        }
        apply(target, request);
        target.touch();
        return toResponse(targets.save(target));
    }

    @Transactional
    public void delete(Tenant tenant, UUID targetId) {
        targets.delete(requireTarget(tenant, targetId));
    }

    @Transactional
    public GcpConnectionTestResponse test(Tenant tenant, UUID targetId) {
        GcpDiscoveryConfig config = configService.requireConfig(tenant);
        GcpDiscoveryTarget target = requireTarget(tenant, targetId);
        GcpConnectionTestResponse response = probe(config, target);
        target.setLastTestStatus(response.status());
        target.setLastTestMessage(truncate(response.message()));
        target.setLastTestedAt(response.testedAt());
        target.touch();
        targets.save(target);
        return response;
    }

    /** Tests every enabled target and records the aggregate on the connector. */
    @Transactional
    public GcpConnectionTestResponse testAll(Tenant tenant) {
        GcpDiscoveryConfig config = configService.requireConfig(tenant);
        Instant testedAt = Instant.now();
        List<GcpDiscoveryTarget> enabled = targets.findByConfigAndEnabledTrueOrderByProjectIdAsc(config);
        GcpConnectionTestResponse response;
        if (enabled.isEmpty()) {
            response = identityOnly(config, testedAt);
        } else {
            List<PermissionCheck> checks = new ArrayList<>();
            List<String> messages = new ArrayList<>();
            int failed = 0;
            int warned = 0;
            for (GcpDiscoveryTarget target : enabled) {
                GcpConnectionTestResponse result = test(tenant, target.getId());
                checks.addAll(result.permissions().stream()
                        .map(check -> new PermissionCheck(target.getProjectId() + ": " + check.permission(),
                                check.granted(), check.required()))
                        .toList());
                messages.add(target.getProjectId() + ": " + result.message());
                if ("FAILED".equals(result.status())) failed++;
                if ("SUCCESS_WITH_WARNINGS".equals(result.status())) warned++;
            }
            String status = failed == enabled.size() ? "FAILED"
                    : failed > 0 || warned > 0 ? "SUCCESS_WITH_WARNINGS" : "SUCCESS";
            response = new GcpConnectionTestResponse(status, String.join(" ", messages),
                    config.getServiceAccountEmail(), checks, testedAt);
        }
        GcpDiscoveryConfig locked = configs.findById(config.getId()).orElse(config);
        locked.setLastTestStatus(response.status());
        locked.setLastTestMessage(truncate(response.message()));
        locked.setLastTestedAt(testedAt);
        locked.touch();
        configs.save(locked);
        return response;
    }

    private GcpConnectionTestResponse identityOnly(GcpDiscoveryConfig config, Instant testedAt) {
        try {
            tokens.token(configService.credentialJson(config));
        } catch (RuntimeException failure) {
            return new GcpConnectionTestResponse("FAILED", failure.getMessage(), config.getServiceAccountEmail(),
                    List.of(), testedAt);
        }
        return new GcpConnectionTestResponse("SUCCESS_WITH_WARNINGS",
                "The service account key is valid. Add a project to verify its access.",
                config.getServiceAccountEmail(), List.of(), testedAt);
    }

    /** Probes one target: the key, then each required permission on the project. */
    GcpConnectionTestResponse probe(GcpDiscoveryConfig config, GcpDiscoveryTarget target) {
        Instant testedAt = Instant.now();
        String email = config.getServiceAccountEmail();
        List<String> types = resourceTypes(target);
        List<String> required = GcpResourceTypes.requiredPermissions(types);
        String token;
        try {
            token = tokens.token(configService.credentialJson(config));
        } catch (RuntimeException failure) {
            return new GcpConnectionTestResponse("FAILED",
                    "Could not authenticate as " + email + ": " + failure.getMessage(), email, List.of(), testedAt);
        }
        Set<String> granted;
        try {
            granted = client.testPermissions(token, target.getProjectId(), required);
        } catch (GcpApiException failure) {
            String message = failure.status() == 403 || failure.status() == 404
                    ? "The service account cannot see project " + target.getProjectId() + ". Grant "
                            + String.join(", ", GcpDiscoveryConfigService.REQUIRED_ROLES) + " to " + email + " on that project."
                    : failure.getMessage();
            return new GcpConnectionTestResponse("FAILED", message, email, List.of(), testedAt);
        }
        List<PermissionCheck> checks = required.stream()
                .map(permission -> new PermissionCheck(permission, granted.contains(permission),
                        !GcpResourceTypes.isOptional(permission)))
                .toList();
        List<String> missingRequired = checks.stream().filter(c -> c.required() && !c.granted()).map(PermissionCheck::permission).toList();
        List<String> missingOptional = checks.stream().filter(c -> !c.required() && !c.granted()).map(PermissionCheck::permission).toList();
        if (!missingRequired.isEmpty()) {
            return new GcpConnectionTestResponse("FAILED",
                    "Missing permissions on " + target.getProjectId() + ": " + String.join(", ", missingRequired) + ".",
                    email, checks, testedAt);
        }
        if (!missingOptional.isEmpty()) {
            return new GcpConnectionTestResponse("SUCCESS_WITH_WARNINGS",
                    "Resources are readable, but VM packages will not be collected without "
                            + String.join(", ", missingOptional) + " (roles/osconfig.inventoryViewer).",
                    email, checks, testedAt);
        }
        return new GcpConnectionTestResponse("SUCCESS",
                "GCP connection succeeded for project " + target.getProjectId() + ".", email, checks, testedAt);
    }

    @Transactional(readOnly = true)
    public GcpDiscoveryTarget requireTarget(Tenant tenant, UUID targetId) {
        return targets.findByIdAndTenant_Id(targetId, tenant.getId())
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "GCP discovery target not found"));
    }

    List<String> resourceTypes(GcpDiscoveryTarget target) {
        try {
            List<String> stored = objectMapper.readValue(target.getResourceTypesJson(), new TypeReference<List<String>>() { });
            return GcpResourceTypes.normalize(stored);
        } catch (Exception unreadable) {
            return GcpResourceTypes.all();
        }
    }

    private void apply(GcpDiscoveryTarget target, GcpDiscoveryTargetRequest request) {
        GcpDiscoveryTargetRequest safe = request == null ? new GcpDiscoveryTargetRequest(null, null, null, null) : request;
        target.setDisplayName(safe.displayName() == null || safe.displayName().isBlank() ? null : safe.displayName().trim());
        target.setEnabled(safe.enabled() == null || safe.enabled());
        try {
            target.setResourceTypesJson(objectMapper.writeValueAsString(GcpResourceTypes.normalize(safe.resourceTypes())));
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(BAD_REQUEST, invalid.getMessage());
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String projectId(GcpDiscoveryTargetRequest request) {
        try {
            return GcpServiceAccountKey.projectId(request == null ? null : request.projectId());
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(BAD_REQUEST, invalid.getMessage());
        }
    }

    private GcpDiscoveryTargetResponse toResponse(GcpDiscoveryTarget target) {
        return new GcpDiscoveryTargetResponse(
                target.getId(),
                target.getProjectId(),
                target.getDisplayName(),
                target.isEnabled(),
                resourceTypes(target),
                target.getLastTestStatus(),
                target.getLastTestMessage(),
                target.getLastTestedAt(),
                target.getLastSyncAt());
    }

    private static String truncate(String value) {
        return value == null || value.length() <= 2000 ? value : value.substring(0, 2000);
    }
}
