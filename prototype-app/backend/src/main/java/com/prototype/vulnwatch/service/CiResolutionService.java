package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.CiAlias;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiAliasRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class CiResolutionService {

    private final CiRepository ciRepository;
    private final CiAliasRepository ciAliasRepository;
    private final AssetRepository assetRepository;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private TransactionTemplate writeTransactionTemplate;

    public CiResolutionService(
            CiRepository ciRepository,
            CiAliasRepository ciAliasRepository,
            AssetRepository assetRepository,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.ciRepository = ciRepository;
        this.ciAliasRepository = ciAliasRepository;
        this.assetRepository = assetRepository;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.writeTransactionTemplate = null;
            return;
        }
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public Resolution resolve(
            Tenant tenant,
            String requestedSysId,
            String hostName,
            String environment,
            OwnershipDetails ownership,
            BusinessCriticality businessCriticality,
            String sourceSystem
    ) {
        String normalizedSource = normalizeSource(sourceSystem);
        String normalizedHost = normalizeAlias(hostName);
        BusinessCriticality resolvedCriticality = businessCriticality == null ? BusinessCriticality.MEDIUM : businessCriticality;
        OwnershipDetails resolvedOwnership = ownership != null ? ownership : OwnershipDetails.empty();

        if (hasText(requestedSysId)) {
            if (requiresOwnershipLookup(resolvedOwnership)) {
                ServiceNowCiLookup ciLookup = lookupInServiceNowBySysId(tenant, requestedSysId.trim());
                if (ciLookup != null) {
                    resolvedOwnership = new OwnershipDetails(
                            coalesceDisplay(ciLookup.ownerEmail(), resolvedOwnership.ownerEmail()),
                            coalesceDisplay(ciLookup.managedBy(), resolvedOwnership.managedBy()),
                            coalesceDisplay(ciLookup.department(), resolvedOwnership.department()),
                            coalesceDisplay(ciLookup.supportGroup(), resolvedOwnership.supportGroup()),
                            coalesceDisplay(ciLookup.assignedTo(), resolvedOwnership.assignedTo())
                    );
                }
            }
            return upsertCi(
                    tenant,
                    requestedSysId.trim(),
                    hostName,
                    environment,
                    resolvedOwnership,
                    resolvedCriticality,
                    normalizedSource,
                    false,
                    "sys_id"
            );
        }

        Resolution aliasResolution = resolveByAlias(tenant, hostName, environment, normalizedSource);
        if (aliasResolution != null) {
            updateAlias(aliasResolution.ci(), hostName, normalizedHost, normalizedSource, aliasResolution.lowConfidence() ? 0.75 : 0.9);
            return aliasResolution;
        }

        ServiceNowCiLookup lookup = lookupInServiceNow(tenant, hostName);
        if (lookup != null && hasText(lookup.sysId())) {
            // Prefer ownership from CI table lookup over install-row data when available
            OwnershipDetails lookupOwnership = new OwnershipDetails(
                    coalesce(lookup.ownerEmail(), resolvedOwnership.ownerEmail()),
                    coalesce(lookup.managedBy(), resolvedOwnership.managedBy()),
                    coalesce(lookup.department(), resolvedOwnership.department()),
                    coalesce(lookup.supportGroup(), resolvedOwnership.supportGroup()),
                    coalesce(lookup.assignedTo(), resolvedOwnership.assignedTo())
            );
            return upsertCi(
                    tenant,
                    lookup.sysId(),
                    lookup.displayName() == null ? hostName : lookup.displayName(),
                    environment,
                    lookupOwnership,
                    resolvedCriticality,
                    normalizedSource,
                    false,
                    "servicenow-api"
            );
        }

        String fallbackSysId = normalizedSource + ":" + (normalizedHost.isBlank() ? UUID.randomUUID() : normalizedHost);
        return upsertCi(
                tenant,
                fallbackSysId,
                hostName,
                environment,
                resolvedOwnership,
                resolvedCriticality,
                normalizedSource,
                true,
                "fallback-alias"
        );
    }

    public BatchResolutionContext prepareBatchContext(
            Tenant tenant,
            String sourceSystem,
            Collection<HostLookupInput> inputs
    ) {
        if (tenant == null || tenant.getId() == null) {
            return new BatchResolutionContext(tenant, normalizeSource(sourceSystem), new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>());
        }
        return tenantSchemaExecutionService.run(tenant, () -> prepareBatchContextInCurrentTenantSchema(tenant, sourceSystem, inputs));
    }

    private BatchResolutionContext prepareBatchContextInCurrentTenantSchema(
            Tenant tenant,
            String sourceSystem,
            Collection<HostLookupInput> inputs
    ) {
        Set<String> sysIds = new LinkedHashSet<>();
        Set<String> aliasNames = new LinkedHashSet<>();
        Set<String> assetIdentifiers = new LinkedHashSet<>();
        for (HostLookupInput input : inputs == null ? List.<HostLookupInput>of() : inputs) {
            if (input == null) {
                continue;
            }
            String normalizedSysId = trimToNull(input.requestedSysId());
            if (hasText(normalizedSysId)) {
                sysIds.add(normalizedSysId);
                assetIdentifiers.add(assetIdentifier(normalizedSysId));
            }
            String normalizedHost = normalizeAlias(input.hostName());
            if (!normalizedHost.isBlank()) {
                aliasNames.add(normalizedHost);
                String shortHost = shortHost(normalizedHost);
                if (!shortHost.equals(normalizedHost)) {
                    aliasNames.add(shortHost);
                }
            }
        }

        Map<String, Ci> ciBySysId = new LinkedHashMap<>();
        if (!sysIds.isEmpty()) {
            for (Ci ci : ciRepository.findByTenant_IdAndSysIdIn(tenant.getId(), sysIds)) {
                if (ci != null && hasText(ci.getSysId())) {
                    ciBySysId.put(ci.getSysId(), ci);
                }
            }
        }

        Map<String, Asset> assetsByIdentifier = new LinkedHashMap<>();
        if (!assetIdentifiers.isEmpty()) {
            for (Asset asset : assetRepository.findByTenant_IdAndIdentifierIn(tenant.getId(), assetIdentifiers)) {
                if (asset != null && hasText(asset.getIdentifier())) {
                    assetsByIdentifier.put(asset.getIdentifier(), asset);
                }
            }
        }
        for (Ci ci : ciBySysId.values()) {
            if (ci.getAsset() != null && hasText(ci.getAsset().getIdentifier())) {
                assetsByIdentifier.putIfAbsent(ci.getAsset().getIdentifier(), ci.getAsset());
            }
        }

        Map<String, CiAlias> aliasBySourceAndName = new LinkedHashMap<>();
        Map<String, List<CiAlias>> aliasesByNormalizedName = new LinkedHashMap<>();
        if (!aliasNames.isEmpty()) {
            for (CiAlias alias : ciAliasRepository.findByTenant_IdAndNormalizedAliasNameIn(tenant.getId(), aliasNames)) {
                if (alias == null || !hasText(alias.getNormalizedAliasName())) {
                    continue;
                }
                if (alias.getCi() != null && hasText(alias.getCi().getSysId())) {
                    ciBySysId.putIfAbsent(alias.getCi().getSysId(), alias.getCi());
                    if (alias.getCi().getAsset() != null && hasText(alias.getCi().getAsset().getIdentifier())) {
                        assetsByIdentifier.putIfAbsent(alias.getCi().getAsset().getIdentifier(), alias.getCi().getAsset());
                    }
                }
                aliasesByNormalizedName.computeIfAbsent(alias.getNormalizedAliasName(), ignored -> new ArrayList<>()).add(alias);
                aliasBySourceAndName.put(aliasSourceKey(alias.getSourceSystem(), alias.getNormalizedAliasName()), alias);
            }
        }

        return new BatchResolutionContext(
                tenant,
                normalizeSource(sourceSystem),
                ciBySysId,
                assetsByIdentifier,
                aliasBySourceAndName,
                aliasesByNormalizedName
        );
    }

    public Resolution resolve(
            BatchResolutionContext context,
            Tenant tenant,
            String requestedSysId,
            String hostName,
            String environment,
            OwnershipDetails ownership,
            BusinessCriticality businessCriticality,
            String sourceSystem
    ) {
        if (context == null) {
            return resolve(tenant, requestedSysId, hostName, environment, ownership, businessCriticality, sourceSystem);
        }

        String normalizedSource = normalizeSource(sourceSystem);
        String normalizedHost = normalizeAlias(hostName);
        BusinessCriticality resolvedCriticality = businessCriticality == null ? BusinessCriticality.MEDIUM : businessCriticality;
        OwnershipDetails resolvedOwnership = ownership != null ? ownership : OwnershipDetails.empty();

        if (hasText(requestedSysId)) {
            if (requiresOwnershipLookup(resolvedOwnership)) {
                // Batch ingestion has already fetched the install table. Do not do per-row CI API lookups
                // here; they can turn an 8k-row sync into thousands of serial ServiceNow calls.
                Ci cachedCi = context.ciBySysId().get(requestedSysId.trim());
                resolvedOwnership = mergeCachedOwnership(resolvedOwnership, cachedCi);
            }
            return upsertCi(
                    context,
                    tenant,
                    requestedSysId.trim(),
                    hostName,
                    environment,
                    resolvedOwnership,
                    resolvedCriticality,
                    normalizedSource,
                    false,
                    "sys_id"
            );
        }

        Resolution aliasResolution = resolveByAlias(context, hostName, environment, normalizedSource);
        if (aliasResolution != null) {
            updateAlias(context, aliasResolution.ci(), hostName, normalizedHost, normalizedSource, aliasResolution.lowConfidence() ? 0.75 : 0.9);
            return aliasResolution;
        }

        ServiceNowCiLookup lookup = lookupInServiceNow(tenant, hostName);
        if (lookup != null && hasText(lookup.sysId())) {
            OwnershipDetails lookupOwnership = new OwnershipDetails(
                    coalesce(lookup.ownerEmail(), resolvedOwnership.ownerEmail()),
                    coalesce(lookup.managedBy(), resolvedOwnership.managedBy()),
                    coalesce(lookup.department(), resolvedOwnership.department()),
                    coalesce(lookup.supportGroup(), resolvedOwnership.supportGroup()),
                    coalesce(lookup.assignedTo(), resolvedOwnership.assignedTo())
            );
            return upsertCi(
                    context,
                    tenant,
                    lookup.sysId(),
                    lookup.displayName() == null ? hostName : lookup.displayName(),
                    environment,
                    lookupOwnership,
                    resolvedCriticality,
                    normalizedSource,
                    false,
                    "servicenow-api"
            );
        }

        String fallbackSysId = normalizedSource + ":" + (normalizedHost.isBlank() ? UUID.randomUUID() : normalizedHost);
        return upsertCi(
                context,
                tenant,
                fallbackSysId,
                hostName,
                environment,
                resolvedOwnership,
                resolvedCriticality,
                normalizedSource,
                true,
                "fallback-alias"
        );
    }

    private Resolution resolveByAlias(Tenant tenant, String hostName, String environment, String sourceSystem) {
        String normalized = normalizeAlias(hostName);
        if (!hasText(normalized) || tenant == null || tenant.getId() == null) {
            return null;
        }
        return tenantSchemaExecutionService.run(tenant, () -> ciAliasRepository.findByTenant_IdAndNormalizedAliasNameAndSourceSystem(
                tenant.getId(),
                normalized,
                sourceSystem
        ).map(alias -> new Resolution(alias.getCi(), false, false, isLowConfidence(alias.getConfidence()), "alias-cache"))
                .orElseGet(() -> {
                    List<CiAlias> aliases = ciAliasRepository.findByTenant_IdAndNormalizedAliasName(tenant.getId(), normalized);
                    if (aliases.isEmpty()) {
                        String shortHost = shortHost(normalized);
                        if (!shortHost.equals(normalized)) {
                            aliases = ciAliasRepository.findByTenant_IdAndNormalizedAliasName(tenant.getId(), shortHost);
                        }
                    }
                    if (aliases.isEmpty()) {
                        return null;
                    }
                    CiAlias selected = aliases.stream()
                            .sorted(Comparator
                                    .comparing((CiAlias alias) -> matchesEnvironment(alias, environment)).reversed()
                                    .thenComparing(alias -> isLowConfidence(alias.getConfidence()))
                                    .thenComparing(alias -> alias.getCi().getSysId()))
                            .findFirst()
                            .orElse(null);
                    if (selected == null || selected.getCi() == null) {
                        return null;
                    }
                    boolean lowConfidence = aliases.size() > 1 || isLowConfidence(selected.getConfidence());
                    return new Resolution(selected.getCi(), false, false, lowConfidence, aliases.size() > 1 ? "alias-ambiguous" : "alias");
                }));
    }

    private Resolution resolveByAlias(BatchResolutionContext context, String hostName, String environment, String sourceSystem) {
        String normalized = normalizeAlias(hostName);
        if (!hasText(normalized) || context == null || context.tenant() == null || context.tenant().getId() == null) {
            return null;
        }

        CiAlias sourceAlias = context.aliasBySourceAndName().get(aliasSourceKey(sourceSystem, normalized));
        if (sourceAlias != null && sourceAlias.getCi() != null) {
            return new Resolution(sourceAlias.getCi(), false, false, isLowConfidence(sourceAlias.getConfidence()), "alias-cache");
        }

        List<CiAlias> aliases = context.aliasesByNormalizedName().getOrDefault(normalized, List.of());
        if (aliases.isEmpty()) {
            String shortHost = shortHost(normalized);
            if (!shortHost.equals(normalized)) {
                aliases = context.aliasesByNormalizedName().getOrDefault(shortHost, List.of());
            }
        }
        if (aliases.isEmpty()) {
            return null;
        }
        CiAlias selected = aliases.stream()
                .sorted(Comparator
                        .comparing((CiAlias alias) -> matchesEnvironment(alias, environment)).reversed()
                        .thenComparing(alias -> isLowConfidence(alias.getConfidence()))
                        .thenComparing(alias -> alias.getCi().getSysId()))
                .findFirst()
                .orElse(null);
        if (selected == null || selected.getCi() == null) {
            return null;
        }
        boolean lowConfidence = aliases.size() > 1 || isLowConfidence(selected.getConfidence());
        return new Resolution(selected.getCi(), false, false, lowConfidence, aliases.size() > 1 ? "alias-ambiguous" : "alias");
    }

    private Resolution upsertCi(
            Tenant tenant,
            String sysId,
            String hostName,
            String environment,
            OwnershipDetails ownership,
            BusinessCriticality businessCriticality,
            String sourceSystem,
            boolean lowConfidence,
            String method
    ) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() ->
                upsertCiInCurrentTenantSchema(tenant, sysId, hostName, environment, ownership, businessCriticality, sourceSystem, lowConfidence, method)
        ));
    }

    private Resolution upsertCiInCurrentTenantSchema(
            Tenant tenant,
            String sysId,
            String hostName,
            String environment,
            OwnershipDetails ownership,
            BusinessCriticality businessCriticality,
            String sourceSystem,
            boolean lowConfidence,
            String method
    ) {
        Instant now = Instant.now();
        Ci ci = ciRepository.findByTenant_IdAndSysIdIn(tenant.getId(), List.of(sysId))
                .stream()
                .findFirst()
                .orElse(null);
        boolean created = ci == null;
        Asset asset = null;
        if (created) {
            ci = new Ci();
            ci.setTenant(tenant);
            ci.setSysId(sysId);
        } else {
            asset = ci.getAsset();
        }
        if (asset == null) {
            String assetIdentifier = "ci:" + sysId.toLowerCase(Locale.ROOT);
            asset = assetRepository.findByTenant_IdAndIdentifierIn(tenant.getId(), List.of(assetIdentifier))
                    .stream()
                    .findFirst()
                    .orElseGet(Asset::new);
            if (asset.getId() == null) {
                asset.setTenant(tenant);
                asset.setIdentifier(assetIdentifier);
                asset.setType(AssetType.HOST);
            }
        }

        asset.setType(AssetType.HOST);
        asset.setName(trimToFallback(hostName, sysId));
        asset.setEnvironment(trimToNull(environment));
        applyOwnership(asset, ownership);
        asset.setBusinessCriticality(businessCriticality);
        asset.setState(AssetState.ACTIVE);
        asset.setLastCmdbSyncAt(now);
        asset = assetRepository.save(asset);

        ci.setAsset(asset);
        ci.setDisplayName(trimToFallback(hostName, sysId));
        ci.setEnvironment(trimToNull(environment));
        applyOwnership(ci, ownership);
        ci.setBusinessCriticality(businessCriticality);
        ci.setLastCmdbSyncAt(now);
        ci.touch();
        ci = ciRepository.save(ci);

        boolean aliasCreated = updateAlias(ci, hostName, normalizeAlias(hostName), sourceSystem, lowConfidence ? 0.5 : 1.0);
        return new Resolution(ci, created, aliasCreated, lowConfidence, method);
    }

    private Resolution upsertCi(
            BatchResolutionContext context,
            Tenant tenant,
            String sysId,
            String hostName,
            String environment,
            OwnershipDetails ownership,
            BusinessCriticality businessCriticality,
            String sourceSystem,
            boolean lowConfidence,
            String method
    ) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() ->
                upsertCiInCurrentTenantSchema(context, tenant, sysId, hostName, environment, ownership, businessCriticality, sourceSystem, lowConfidence, method)
        ));
    }

    private Resolution upsertCiInCurrentTenantSchema(
            BatchResolutionContext context,
            Tenant tenant,
            String sysId,
            String hostName,
            String environment,
            OwnershipDetails ownership,
            BusinessCriticality businessCriticality,
            String sourceSystem,
            boolean lowConfidence,
            String method
    ) {
        Instant now = Instant.now();
        String normalizedSysId = trimToNull(sysId);
        Ci ci = context.ciBySysId().get(normalizedSysId);
        boolean created = ci == null;
        Asset asset = null;
        if (created) {
            ci = new Ci();
            ci.setTenant(tenant);
            ci.setSysId(normalizedSysId);
        } else {
            asset = ci.getAsset();
        }
        String assetIdentifier = assetIdentifier(normalizedSysId);
        if (asset == null) {
            asset = context.assetsByIdentifier().get(assetIdentifier);
            if (asset == null) {
                asset = new Asset();
                asset.setTenant(tenant);
                asset.setIdentifier(assetIdentifier);
                asset.setType(AssetType.HOST);
            }
        }

        asset.setType(AssetType.HOST);
        asset.setName(trimToFallback(hostName, normalizedSysId));
        asset.setEnvironment(trimToNull(environment));
        applyOwnership(asset, ownership);
        asset.setBusinessCriticality(businessCriticality);
        asset.setState(AssetState.ACTIVE);
        asset.setLastCmdbSyncAt(now);
        asset = assetRepository.save(asset);
        context.assetsByIdentifier().put(assetIdentifier, asset);

        ci.setAsset(asset);
        ci.setDisplayName(trimToFallback(hostName, normalizedSysId));
        ci.setEnvironment(trimToNull(environment));
        applyOwnership(ci, ownership);
        ci.setBusinessCriticality(businessCriticality);
        ci.setLastCmdbSyncAt(now);
        ci.touch();
        ci = ciRepository.save(ci);
        context.ciBySysId().put(normalizedSysId, ci);

        boolean aliasCreated = updateAlias(context, ci, hostName, normalizeAlias(hostName), sourceSystem, lowConfidence ? 0.5 : 1.0);
        return new Resolution(ci, created, aliasCreated, lowConfidence, method);
    }

    private void applyOwnership(Asset asset, OwnershipDetails o) {
        if (o == null) return;
        asset.setOwnerEmail(displayOrNull(o.ownerEmail()));
        asset.setManagedBy(displayOrNull(o.managedBy()));
        asset.setDepartment(displayOrNull(o.department()));
        asset.setSupportGroup(displayOrNull(o.supportGroup()));
        asset.setAssignedTo(displayOrNull(o.assignedTo()));
    }

    private void applyOwnership(Ci ci, OwnershipDetails o) {
        if (o == null) return;
        ci.setOwnerEmail(displayOrNull(o.ownerEmail()));
        ci.setManagedBy(displayOrNull(o.managedBy()));
        ci.setDepartment(displayOrNull(o.department()));
        ci.setSupportGroup(displayOrNull(o.supportGroup()));
        ci.setAssignedTo(displayOrNull(o.assignedTo()));
    }

    private static String coalesce(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }

    private static String coalesceDisplay(String preferred, String fallback) {
        if (hasDisplayText(preferred)) {
            return preferred;
        }
        return hasDisplayText(fallback) ? fallback : preferred;
    }

    private boolean requiresOwnershipLookup(OwnershipDetails ownership) {
        if (ownership == null) {
            return true;
        }
        return !hasDisplayText(ownership.supportGroup())
                || isLikelyServiceNowSysId(ownership.ownerEmail())
                || isLikelyServiceNowSysId(ownership.managedBy())
                || isLikelyServiceNowSysId(ownership.assignedTo());
    }

    private OwnershipDetails mergeCachedOwnership(OwnershipDetails current, Ci ci) {
        if (ci == null) {
            return current;
        }
        return new OwnershipDetails(
                coalesceDisplay(current.ownerEmail(), ci.getOwnerEmail()),
                coalesceDisplay(current.managedBy(), ci.getManagedBy()),
                coalesceDisplay(current.department(), ci.getDepartment()),
                coalesceDisplay(current.supportGroup(), ci.getSupportGroup()),
                coalesceDisplay(current.assignedTo(), ci.getAssignedTo())
        );
    }

    private static boolean hasDisplayText(String value) {
        return value != null && !value.isBlank() && !isLikelyServiceNowSysId(value);
    }

    private String displayOrNull(String value) {
        return hasDisplayText(value) ? value.trim() : null;
    }

    private static boolean isLikelyServiceNowSysId(String value) {
        return value != null && value.trim().matches("(?i)[0-9a-f]{32}");
    }

    private boolean updateAlias(Ci ci, String aliasName, String normalizedAliasName, String sourceSystem, double confidence) {
        if (ci == null || ci.getTenant() == null || ci.getTenant().getId() == null || !hasText(normalizedAliasName)) {
            return false;
        }
        Instant now = Instant.now();
        CiAlias alias = ciAliasRepository.findByTenant_IdAndNormalizedAliasNameAndSourceSystem(
                        ci.getTenant().getId(),
                        normalizedAliasName,
                        sourceSystem
                )
                .orElseGet(CiAlias::new);
        boolean created = alias.getId() == null;
        alias.setTenant(ci.getTenant());
        alias.setCi(ci);
        alias.setAliasName(trimToFallback(aliasName, ci.getDisplayName()));
        alias.setNormalizedAliasName(normalizedAliasName);
        alias.setSourceSystem(sourceSystem);
        if (created) {
            alias.setFirstSeenAt(now);
        }
        alias.setLastSeenAt(now);
        alias.setConfidence(confidence);
        ciAliasRepository.save(alias);

        String shortHost = shortHost(normalizedAliasName);
        if (hasText(shortHost) && !shortHost.equals(normalizedAliasName)) {
            updateAlias(ci, shortHost, shortHost, sourceSystem, confidence);
        }
        return created;
    }

    private boolean updateAlias(
            BatchResolutionContext context,
            Ci ci,
            String aliasName,
            String normalizedAliasName,
            String sourceSystem,
            double confidence
    ) {
        if (context == null || ci == null || ci.getTenant() == null || ci.getTenant().getId() == null || !hasText(normalizedAliasName)) {
            return false;
        }
        Instant now = Instant.now();
        String aliasKey = aliasSourceKey(sourceSystem, normalizedAliasName);
        CiAlias alias = context.aliasBySourceAndName().get(aliasKey);
        if (alias == null) {
            alias = new CiAlias();
        }
        boolean created = alias.getId() == null;
        alias.setTenant(ci.getTenant());
        alias.setCi(ci);
        alias.setAliasName(trimToFallback(aliasName, ci.getDisplayName()));
        alias.setNormalizedAliasName(normalizedAliasName);
        alias.setSourceSystem(sourceSystem);
        if (created) {
            alias.setFirstSeenAt(now);
        }
        alias.setLastSeenAt(now);
        alias.setConfidence(confidence);
        alias = ciAliasRepository.save(alias);
        context.aliasBySourceAndName().put(aliasKey, alias);
        context.aliasesByNormalizedName()
                .computeIfAbsent(normalizedAliasName, ignored -> new ArrayList<>());
        List<CiAlias> aliases = context.aliasesByNormalizedName().get(normalizedAliasName);
        if (!aliases.contains(alias)) {
            aliases.add(alias);
        }

        String shortHost = shortHost(normalizedAliasName);
        if (hasText(shortHost) && !shortHost.equals(normalizedAliasName)) {
            updateAlias(context, ci, shortHost, shortHost, sourceSystem, confidence);
        }
        return created;
    }

    private ServiceNowCiLookup lookupInServiceNow(Tenant tenant, String hostName) {
        if (!hasText(hostName)) {
            return null;
        }
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig runtimeConfig = serviceNowCmdbConfigService.resolveRuntimeConfig(tenant)
                .orElse(null);
        if (runtimeConfig == null || !runtimeConfig.enabled()
                || !hasText(runtimeConfig.baseUrl()) || !hasText(runtimeConfig.ciTable())) {
            return null;
        }
        try {
            String uri = UriComponentsBuilder.fromUriString(runtimeConfig.baseUrl())
                    .path("/api/now/table/{tableName}")
                    .queryParam("sysparm_fields",
                        "sys_id,name,sys_class_name,owned_by,managed_by,assigned_to,department,support_group")
                    .queryParam("sysparm_query", "name=" + hostName)
                    .queryParam("sysparm_display_value", "all")
                    .buildAndExpand(runtimeConfig.ciTable())
                    .toUriString();
            HttpHeaders headers = new HttpHeaders();
            if (runtimeConfig.authType() == com.prototype.vulnwatch.domain.ServiceNowAuthType.BEARER) {
                headers.setBearerAuth(runtimeConfig.credentialSecret());
            } else if (hasText(runtimeConfig.username())) {
                headers.setBasicAuth(
                        runtimeConfig.username(),
                        runtimeConfig.credentialSecret() == null ? "" : runtimeConfig.credentialSecret(),
                        StandardCharsets.UTF_8
                );
            }
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    uri,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class,
                    "ServiceNow CI lookup",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    )
            );
            if (!response.getStatusCode().is2xxSuccessful() || !hasText(response.getBody())) {
                return null;
            }
            JsonNode root = objectMapper.readTree(response.getBody());
            JsonNode results = root.path("result");
            if (!results.isArray() || results.isEmpty()) {
                return null;
            }
            JsonNode selected = results.get(0);
            String sysId = fieldValue(selected.path("sys_id"));
            String displayName = fieldValue(selected.path("name"));
            if (!hasText(sysId)) return null;
            return new ServiceNowCiLookup(
                sysId, displayName,
                fieldValue(selected.path("owned_by")),
                fieldValue(selected.path("managed_by")),
                fieldValue(selected.path("department")),
                fieldValue(selected.path("support_group")),
                fieldValue(selected.path("assigned_to"))
            );
        } catch (Exception ignored) {
            return null;
        }
    }

    private ServiceNowCiLookup lookupInServiceNowBySysId(Tenant tenant, String sysId) {
        if (!hasText(sysId)) {
            return null;
        }
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig runtimeConfig = serviceNowCmdbConfigService.resolveRuntimeConfig(tenant)
                .orElse(null);
        if (runtimeConfig == null || !runtimeConfig.enabled()
                || !hasText(runtimeConfig.baseUrl()) || !hasText(runtimeConfig.ciTable())) {
            return null;
        }
        try {
            String uri = UriComponentsBuilder.fromUriString(runtimeConfig.baseUrl())
                    .path("/api/now/table/{tableName}/{sysId}")
                    .queryParam("sysparm_fields",
                        "sys_id,name,sys_class_name,owned_by,managed_by,assigned_to,department,support_group")
                    .queryParam("sysparm_display_value", "all")
                    .buildAndExpand(runtimeConfig.ciTable(), sysId)
                    .toUriString();
            HttpHeaders headers = new HttpHeaders();
            if (runtimeConfig.authType() == com.prototype.vulnwatch.domain.ServiceNowAuthType.BEARER) {
                headers.setBearerAuth(runtimeConfig.credentialSecret());
            } else if (hasText(runtimeConfig.username())) {
                headers.setBasicAuth(
                        runtimeConfig.username(),
                        runtimeConfig.credentialSecret() == null ? "" : runtimeConfig.credentialSecret(),
                        StandardCharsets.UTF_8
                );
            }
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    uri,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class,
                    "ServiceNow CI lookup by sys_id",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    )
            );
            if (!response.getStatusCode().is2xxSuccessful() || !hasText(response.getBody())) {
                return null;
            }
            JsonNode root = objectMapper.readTree(response.getBody());
            // Direct record GET returns {"result": {...}} not {"result": [...]}
            JsonNode result = root.path("result");
            if (result.isMissingNode() || result.isNull()) {
                return null;
            }
            // Handle both array and object responses
            JsonNode selected = result.isArray() ? (result.isEmpty() ? null : result.get(0)) : result;
            if (selected == null || selected.isMissingNode() || selected.isNull()) {
                return null;
            }
            String resolvedSysId = fieldValue(selected.path("sys_id"));
            String displayName = fieldValue(selected.path("name"));
            if (!hasText(resolvedSysId)) return null;
            return new ServiceNowCiLookup(
                resolvedSysId, displayName,
                fieldValue(selected.path("owned_by")),
                fieldValue(selected.path("managed_by")),
                fieldValue(selected.path("department")),
                fieldValue(selected.path("support_group")),
                fieldValue(selected.path("assigned_to"))
            );
        } catch (Exception ignored) {
            return null;
        }
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("servicenow", 0L, null, null);
    }

    private boolean matchesEnvironment(CiAlias alias, String environment) {
        if (alias == null || alias.getCi() == null) {
            return false;
        }
        String left = normalizeAlias(alias.getCi().getEnvironment());
        String right = normalizeAlias(environment);
        return hasText(left) && left.equals(right);
    }

    private boolean isLowConfidence(Double confidence) {
        return confidence != null && confidence < 0.8;
    }

    private String fieldValue(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            String display = trimToNull(node.path("display_value").asText(null));
            if (hasText(display)) {
                return display;
            }
            return trimToNull(node.path("value").asText(null));
        }
        return trimToNull(node.asText(null));
    }

    private String shortHost(String normalizedHost) {
        if (!hasText(normalizedHost)) {
            return "";
        }
        int dot = normalizedHost.indexOf('.');
        return dot > 0 ? normalizedHost.substring(0, dot) : normalizedHost;
    }

    private String assetIdentifier(String sysId) {
        return "ci:" + sysId.toLowerCase(Locale.ROOT);
    }

    private String aliasSourceKey(String sourceSystem, String normalizedAliasName) {
        return normalizeSource(sourceSystem) + "::" + normalizedAliasName;
    }

    private String normalizeAlias(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeSource(String value) {
        return value == null || value.isBlank() ? "unknown" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String trimToFallback(String value, String fallback) {
        String trimmed = trimToNull(value);
        return trimmed == null ? fallback : trimmed;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public record Resolution(
            Ci ci,
            boolean created,
            boolean aliasCreated,
            boolean lowConfidence,
            String resolutionMethod
    ) {
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }

    public record HostLookupInput(
            String requestedSysId,
            String hostName
    ) {
    }

    public record BatchResolutionContext(
            Tenant tenant,
            String sourceSystem,
            Map<String, Ci> ciBySysId,
            Map<String, Asset> assetsByIdentifier,
            Map<String, CiAlias> aliasBySourceAndName,
            Map<String, List<CiAlias>> aliasesByNormalizedName
    ) {
    }

    private record ServiceNowCiLookup(
            String sysId,
            String displayName,
            String ownerEmail,
            String managedBy,
            String department,
            String supportGroup,
            String assignedTo
    ) {
    }

    public record OwnershipDetails(
            String ownerEmail,
            String managedBy,
            String department,
            String supportGroup,
            String assignedTo
    ) {
        public static OwnershipDetails ofEmail(String ownerEmail) {
            return new OwnershipDetails(ownerEmail, null, null, null, null);
        }
        public static OwnershipDetails empty() {
            return new OwnershipDetails(null, null, null, null, null);
        }
    }
}
