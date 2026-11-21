package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.DiscoveryModel;
import com.prototype.vulnwatch.domain.IdentityLink;
import com.prototype.vulnwatch.domain.IdentityMatchRule;
import com.prototype.vulnwatch.domain.IdentifierType;
import com.prototype.vulnwatch.domain.SoftwareIdentifier;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import com.prototype.vulnwatch.repo.IdentityLinkRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentifierRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import com.prototype.vulnwatch.util.IdentityUtil;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SoftwareIdentityService {

    private static final Pattern MSI_CODE_PATTERN = Pattern.compile("\\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\\}?");

    private final SoftwareIdentityRepository softwareIdentityRepository;
    private final SoftwareIdentifierRepository softwareIdentifierRepository;
    private final IdentityLinkRepository identityLinkRepository;
    private final IdentityGraphService identityGraphService;
    private final ConcurrentMap<String, Optional<ExistingIdentityMatch>> identifierMatchCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Optional<SoftwareIdentity>> canonicalIdentityCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Optional<SoftwareIdentity>> productHashIdentityCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, IdentityLink> genericLinkCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<UUID, Set<String>> cpeCandidateCache = new ConcurrentHashMap<>();

    public SoftwareIdentityService(
            SoftwareIdentityRepository softwareIdentityRepository,
            SoftwareIdentifierRepository softwareIdentifierRepository,
            IdentityLinkRepository identityLinkRepository,
            IdentityGraphService identityGraphService
    ) {
        this.softwareIdentityRepository = softwareIdentityRepository;
        this.softwareIdentifierRepository = softwareIdentifierRepository;
        this.identityLinkRepository = identityLinkRepository;
        this.identityGraphService = identityGraphService;
    }

    @Transactional
    public HostIdentityResolution resolveHostSoftwareIdentity(
            SoftwareInstance instance,
            DiscoveryModel discoveryModel,
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            String sourceSystem
    ) {
        return resolveHostSoftwareIdentity(instance, discoveryModel, normalized, sourceSystem, true);
    }

    @Transactional
    public HostIdentityResolution resolveHostSoftwareIdentity(
            SoftwareInstance instance,
            DiscoveryModel discoveryModel,
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            String sourceSystem,
            boolean allowIdentifierRepositoryLookup
    ) {
        if (instance == null || normalized == null) {
            return new HostIdentityResolution(null, IdentityMatchRule.NORMALIZED_KEY, 0.0, Set.of());
        }

        String source = normalizeSource(sourceSystem);
        ExistingIdentityMatch existing = findExistingIdentity(instance, discoveryModel, normalized, allowIdentifierRepositoryLookup);
        SoftwareIdentity identity = existing == null ? findOrCreateIdentity(normalized, discoveryModel) : existing.identity();
        IdentityMatchRule rule = existing == null ? IdentityMatchRule.NORMALIZED_KEY : existing.matchRule();
        double confidence = existing == null ? 0.90 : existing.confidence();

        if (hydrateIdentity(identity, normalized, discoveryModel)) {
            identity.touch();
            identity = softwareIdentityRepository.save(identity);
        }
        cacheIdentity(identity, normalized, discoveryModel, instance);

        if (allowIdentifierRepositoryLookup) {
            upsertIdentifiers(identity, normalized, discoveryModel, instance, source);
            upsertInstanceLink(instance, identity, rule, confidence, source,
                    "Deterministic host software to canonical identity link");
            if (discoveryModel != null && discoveryModel.getId() != null) {
                IdentityMatchRule discoveryRule = hasText(discoveryModel.getProductHash()) || hasText(discoveryModel.getVersionHash())
                        ? IdentityMatchRule.HASH
                        : IdentityMatchRule.NORMALIZED_KEY;
                upsertGenericLink(
                        "SOFTWARE_INSTANCE",
                        instance.getId(),
                        "DISCOVERY_MODEL",
                        discoveryModel.getId(),
                        discoveryRule,
                        source,
                        discoveryRule == IdentityMatchRule.HASH ? 1.0 : 0.90,
                        "Software instance linked to normalized discovery model row"
                );
            }
        }

        cpeCandidateCache.remove(identity.getId());
        Set<String> cpeCandidates = loadCpeCandidates(identity);
        return new HostIdentityResolution(identity, rule, confidence, cpeCandidates);
    }

    private ExistingIdentityMatch findExistingIdentity(
            SoftwareInstance instance,
            DiscoveryModel discoveryModel,
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            boolean allowIdentifierRepositoryLookup
    ) {
        if (discoveryModel != null && hasText(discoveryModel.getProductHash())) {
            ExistingIdentityMatch hashMatch = findByIdentifier(
                    IdentifierType.PRODUCT_HASH,
                    discoveryModel.getProductHash(),
                    IdentityMatchRule.HASH,
                    1.0,
                    allowIdentifierRepositoryLookup
            );
            if (hashMatch != null) {
                return hashMatch;
            }
            Optional<SoftwareIdentity> identityByHash = productHashIdentityCache.computeIfAbsent(
                    cacheKey(discoveryModel.getProductHash()),
                    ignored -> softwareIdentityRepository.findByProductHash(discoveryModel.getProductHash())
            );
            if (identityByHash.isPresent()) {
                return new ExistingIdentityMatch(identityByHash.get(), IdentityMatchRule.HASH, 1.0);
            }
        }

        String msiCode = extractMsiCode(instance == null ? null : instance.getVersionEvidence());
        if (hasText(msiCode)) {
            ExistingIdentityMatch identifierMatch = findByIdentifier(
                    IdentifierType.MSI_PRODUCT_CODE,
                    msiCode,
                    IdentityMatchRule.IDENTIFIER,
                    1.0,
                    allowIdentifierRepositoryLookup
            );
            if (identifierMatch != null) {
                return identifierMatch;
            }
        }

        if (discoveryModel != null && hasText(discoveryModel.getPrimaryKey())) {
            ExistingIdentityMatch discoveryKeyMatch = findByIdentifier(
                    IdentifierType.VENDOR_PRODUCT_ID,
                    discoveryModel.getPrimaryKey(),
                    IdentityMatchRule.IDENTIFIER,
                    0.98,
                    allowIdentifierRepositoryLookup
            );
            if (discoveryKeyMatch != null) {
                return discoveryKeyMatch;
            }
        }

        String canonicalKey = canonicalKey(normalized);
        return canonicalIdentityCache.computeIfAbsent(
                        cacheKey(canonicalKey),
                        ignored -> softwareIdentityRepository.findByCanonicalKey(canonicalKey)
                )
                .map(identity -> new ExistingIdentityMatch(identity, IdentityMatchRule.NORMALIZED_KEY, 0.90))
                .orElse(null);
    }

    private ExistingIdentityMatch findByIdentifier(
            IdentifierType identifierType,
            String rawValue,
            IdentityMatchRule matchRule,
            double confidence,
            boolean allowRepositoryLookup
    ) {
        if (!hasText(rawValue)) {
            return null;
        }
        String normalizedValue = IdentityUtil.normalize(rawValue);
        Optional<ExistingIdentityMatch> cached = identifierMatchCache.get(identifierCacheKey(identifierType, normalizedValue));
        if (cached != null) {
            return cached.orElse(null);
        }
        if (!allowRepositoryLookup) {
            return null;
        }

        List<SoftwareIdentifier> identifiers = softwareIdentifierRepository.findByIdTypeAndNormalizedValue(
                identifierType,
                normalizedValue
        );
        ExistingIdentityMatch match = identifiers.stream()
                .filter(identifier -> identifier.getSoftwareIdentity() != null)
                .sorted(Comparator.comparing(SoftwareIdentifier::isVerified).reversed()
                        .thenComparing(identifier -> identifier.getConfidence() == null ? 0.0 : identifier.getConfidence(), Comparator.reverseOrder()))
                .findFirst()
                .map(identifier -> new ExistingIdentityMatch(identifier.getSoftwareIdentity(), matchRule, confidence))
                .orElse(null);
        identifierMatchCache.put(identifierCacheKey(identifierType, normalizedValue), Optional.ofNullable(match));
        return match;
    }

    private SoftwareIdentity findOrCreateIdentity(
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            DiscoveryModel discoveryModel
    ) {
        String canonicalKey = canonicalKey(normalized);
        Optional<SoftwareIdentity> cached = canonicalIdentityCache.get(cacheKey(canonicalKey));
        if (cached != null && cached.isPresent()) {
            return cached.get();
        }
        SoftwareIdentity identity = softwareIdentityRepository.findByCanonicalKey(canonicalKey).orElseGet(() -> {
            SoftwareIdentity createdIdentity = new SoftwareIdentity();
            createdIdentity.setCanonicalKey(canonicalKey);
            createdIdentity.setDisplayName(displayName(normalized));
            createdIdentity.setVendor(normalized.normalizedPublisher());
            createdIdentity.setProduct(normalized.normalizedProduct());
            createdIdentity.setProductHash(discoveryModel == null ? null : normalizeText(discoveryModel.getProductHash()));
            createdIdentity.setPurl(normalized.purl());
            createdIdentity.setVendorProductId(discoveryModel == null ? null : trimToNull(discoveryModel.getPrimaryKey()));
            return softwareIdentityRepository.save(createdIdentity);
        });
        canonicalIdentityCache.put(cacheKey(canonicalKey), Optional.of(identity));
        return identity;
    }

    private boolean hydrateIdentity(
            SoftwareIdentity identity,
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            DiscoveryModel discoveryModel
    ) {
        String productHash = identity.getProductHash();
        String vendorProductId = identity.getVendorProductId();
        if (discoveryModel != null) {
            if (!hasText(productHash)) {
                productHash = normalizeText(discoveryModel.getProductHash());
            }
            if (!hasText(vendorProductId)) {
                vendorProductId = trimToNull(discoveryModel.getPrimaryKey());
            }
        }
        String displayName = displayName(normalized);
        if (Objects.equals(identity.getDisplayName(), displayName)
                && Objects.equals(identity.getVendor(), normalized.normalizedPublisher())
                && Objects.equals(identity.getProduct(), normalized.normalizedProduct())
                && Objects.equals(identity.getPurl(), normalized.purl())
                && Objects.equals(identity.getProductHash(), productHash)
                && Objects.equals(identity.getVendorProductId(), vendorProductId)) {
            return false;
        }
        identity.setDisplayName(displayName);
        identity.setVendor(normalized.normalizedPublisher());
        identity.setProduct(normalized.normalizedProduct());
        identity.setPurl(normalized.purl());
        identity.setProductHash(productHash);
        identity.setVendorProductId(vendorProductId);
        return true;
    }

    private void upsertIdentifiers(
            SoftwareIdentity identity,
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            DiscoveryModel discoveryModel,
            SoftwareInstance instance,
            String source
    ) {
        String coordKey = IdentityUtil.coordKey("generic", normalized.normalizedPublisher(), normalized.normalizedProduct());
        identityGraphService.upsertIdentifier(identity, IdentifierType.COORD, coordKey, coordKey, source, true, 0.92);
        identityGraphService.upsertIdentifier(identity, IdentifierType.PURL, normalized.purl(), normalized.purl(), source, true, 0.95);

        if (discoveryModel != null && hasText(discoveryModel.getProductHash())) {
            identityGraphService.upsertIdentifier(
                    identity,
                    IdentifierType.PRODUCT_HASH,
                    discoveryModel.getProductHash(),
                    discoveryModel.getProductHash(),
                    source,
                    true,
                    1.0
            );
            identity.setProductHash(normalizeText(discoveryModel.getProductHash()));
        }
        if (discoveryModel != null && hasText(discoveryModel.getVersionHash())) {
            identityGraphService.upsertIdentifier(
                    identity,
                    IdentifierType.VERSION_HASH,
                    discoveryModel.getVersionHash(),
                    discoveryModel.getVersionHash(),
                    source,
                    true,
                    0.99
            );
        }
        if (discoveryModel != null && hasText(discoveryModel.getPrimaryKey())) {
            identityGraphService.upsertIdentifier(
                    identity,
                    IdentifierType.VENDOR_PRODUCT_ID,
                    discoveryModel.getPrimaryKey(),
                    discoveryModel.getPrimaryKey(),
                    source,
                    true,
                    0.98
            );
        }
        String msiCode = extractMsiCode(instance == null ? null : instance.getVersionEvidence());
        if (hasText(msiCode)) {
            identityGraphService.upsertIdentifier(
                    identity,
                    IdentifierType.MSI_PRODUCT_CODE,
                    msiCode,
                    msiCode,
                    source,
                    true,
                    1.0
            );
        }
        if (hasText(identity.getCpe23())) {
            identityGraphService.upsertIdentifier(
                    identity,
                    IdentifierType.CPE,
                    identity.getCpe23(),
                    identity.getCpe23(),
                    source,
                    true,
                    0.95
            );
        }
    }

    private void upsertInstanceLink(
            SoftwareInstance instance,
            SoftwareIdentity identity,
            IdentityMatchRule matchRule,
            double confidence,
            String source,
            String note
    ) {
        if (instance == null || instance.getId() == null || identity == null || identity.getId() == null) {
            return;
        }
        upsertGenericLink(
                "SOFTWARE_INSTANCE",
                instance.getId(),
                "SOFTWARE_IDENTITY",
                identity.getId(),
                matchRule,
                source,
                confidence,
                note
        );
    }

    private void upsertGenericLink(
            String sourceType,
            UUID sourceId,
            String targetType,
            UUID targetId,
            IdentityMatchRule matchRule,
            String source,
            double confidence,
            String note
    ) {
        if (sourceId == null || targetId == null) {
            return;
        }
        String normalizedSource = normalizeSource(source);
        String cacheKey = genericLinkCacheKey(sourceType, sourceId, targetType, targetId, matchRule, normalizedSource);
        IdentityLink link = genericLinkCache.get(cacheKey);
        if (link == null) {
            link = identityLinkRepository
                    .findBySourceTypeAndSourceIdAndTargetTypeAndTargetIdAndMatchRuleAndSource(
                            sourceType,
                            sourceId.toString(),
                            targetType,
                            targetId.toString(),
                            matchRule,
                            normalizedSource
                    )
                    .orElseGet(() -> {
                        IdentityLink created = new IdentityLink();
                        created.setSourceType(sourceType);
                        created.setSourceId(sourceId.toString());
                        created.setTargetType(targetType);
                        created.setTargetId(targetId.toString());
                        created.setMatchRule(matchRule);
                        created.setLinkType("inventory-correlation");
                        created.setSource(normalizedSource);
                        return created;
                    });
        }
        link.setConfidence(Math.max(link.getConfidence() == null ? 0.0 : link.getConfidence(), confidence));
        link.setProvenanceNote(note);
        link.setLastSeenAt(Instant.now());
        link.setUpdatedAt(Instant.now());
        link = identityLinkRepository.save(link);
        if (link != null) {
            genericLinkCache.put(cacheKey, link);
        }
    }

    private Set<String> loadCpeCandidates(SoftwareIdentity identity) {
        Set<String> candidates = new LinkedHashSet<>();
        if (identity == null || identity.getId() == null) {
            return candidates;
        }
        Set<String> cached = cpeCandidateCache.get(identity.getId());
        if (cached != null) {
            return cached;
        }
        if (hasText(identity.getCpe23())) {
            candidates.add(identity.getCpe23().trim().toLowerCase(Locale.ROOT));
        }
        Set<String> resolved = Set.copyOf(candidates);
        cpeCandidateCache.put(identity.getId(), resolved);
        return resolved;
    }

    private void cacheIdentity(
            SoftwareIdentity identity,
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            DiscoveryModel discoveryModel,
            SoftwareInstance instance
    ) {
        if (identity == null) {
            return;
        }
        canonicalIdentityCache.put(cacheKey(canonicalKey(normalized)), Optional.of(identity));
        if (discoveryModel != null && hasText(discoveryModel.getProductHash())) {
            productHashIdentityCache.put(cacheKey(discoveryModel.getProductHash()), Optional.of(identity));
            identifierMatchCache.put(
                    identifierCacheKey(IdentifierType.PRODUCT_HASH, discoveryModel.getProductHash()),
                    Optional.of(new ExistingIdentityMatch(identity, IdentityMatchRule.HASH, 1.0))
            );
        }
        if (discoveryModel != null && hasText(discoveryModel.getPrimaryKey())) {
            identifierMatchCache.put(
                    identifierCacheKey(IdentifierType.VENDOR_PRODUCT_ID, discoveryModel.getPrimaryKey()),
                    Optional.of(new ExistingIdentityMatch(identity, IdentityMatchRule.IDENTIFIER, 0.98))
            );
        }
        String msiCode = extractMsiCode(instance == null ? null : instance.getVersionEvidence());
        if (hasText(msiCode)) {
            identifierMatchCache.put(
                    identifierCacheKey(IdentifierType.MSI_PRODUCT_CODE, msiCode),
                    Optional.of(new ExistingIdentityMatch(identity, IdentityMatchRule.IDENTIFIER, 1.0))
            );
        }
    }

    private String extractMsiCode(String value) {
        if (!hasText(value)) {
            return null;
        }
        Matcher matcher = MSI_CODE_PATTERN.matcher(value);
        return matcher.find() ? matcher.group().toLowerCase(Locale.ROOT) : null;
    }

    private String canonicalKey(HostSoftwareNormalizationService.NormalizedHostSoftware normalized) {
        return IdentityUtil.canonicalIdentityKey("generic", normalized.normalizedPublisher(), normalized.normalizedProduct());
    }

    private String displayName(HostSoftwareNormalizationService.NormalizedHostSoftware normalized) {
        return normalized.normalizedPublisher() + "/" + normalized.normalizedProduct();
    }

    private String normalizeSource(String source) {
        return source == null || source.isBlank() ? "host-inventory" : source.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeText(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    private String cacheKey(String value) {
        return normalizeText(value);
    }

    private String identifierCacheKey(IdentifierType type, String value) {
        return type.name() + "::" + IdentityUtil.normalize(value);
    }

    private String genericLinkCacheKey(
            String sourceType,
            UUID sourceId,
            String targetType,
            UUID targetId,
            IdentityMatchRule matchRule,
            String source
    ) {
        return sourceType + "::" + sourceId + "::" + targetType + "::" + targetId + "::" + matchRule.name() + "::" + source;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record ExistingIdentityMatch(
            SoftwareIdentity identity,
            IdentityMatchRule matchRule,
            double confidence
    ) {
    }

    public record HostIdentityResolution(
            SoftwareIdentity identity,
            IdentityMatchRule matchRule,
            double confidence,
            Set<String> cpeCandidates
    ) {
    }
}
