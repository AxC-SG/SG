package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.VexAssertion;
import com.prototype.vulnwatch.domain.VulnerabilityIntelObservation;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.VexAssertionRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VexAssertionService {

    private static final Logger LOG = LoggerFactory.getLogger(VexAssertionService.class);

    public record RefreshResult(
            int assertionCount,
            Set<UUID> changedVulnerabilityIds
    ) {
    }

    private final VexAssertionRepository vexAssertionRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository;
    private final VexPolicyService vexPolicyService;
    private final ImpactEvaluationService impactEvaluationService;
    private final ObjectMapper objectMapper;

    public VexAssertionService(
            VexAssertionRepository vexAssertionRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository,
            VexPolicyService vexPolicyService,
            ImpactEvaluationService impactEvaluationService,
            ObjectMapper objectMapper
    ) {
        this.vexAssertionRepository = vexAssertionRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.vulnerabilityIntelObservationRepository = vulnerabilityIntelObservationRepository;
        this.vexPolicyService = vexPolicyService;
        this.impactEvaluationService = impactEvaluationService;
        this.objectMapper = objectMapper;
    }

    private IntelligenceStagingService staging;
    @org.springframework.beans.factory.annotation.Autowired
    void configureStaging(IntelligenceStagingService staging) { this.staging=staging; }

    @Transactional
    public int refreshAssertionsForVulnerabilityIds(Collection<UUID> vulnerabilityIds) {
        return refreshAssertionsForVulnerabilityIdsDetailed(vulnerabilityIds).assertionCount();
    }

    @Transactional
    public RefreshResult refreshAssertionsForVulnerabilityIdsDetailed(Collection<UUID> vulnerabilityIds) {
        if (!IntelligenceWriteContext.publishing()) {
            staging.append("VEX_REBUILD","*",null,"vex",java.util.Map.of(),"VALID");
            return new RefreshResult(0,Set.of());
        }
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return new RefreshResult(0, Set.of());
        }
        Set<UUID> normalizedIds = new LinkedHashSet<>();
        for (UUID vulnerabilityId : vulnerabilityIds) {
            if (vulnerabilityId != null) {
                normalizedIds.add(vulnerabilityId);
            }
        }
        if (normalizedIds.isEmpty()) {
            return new RefreshResult(0, Set.of());
        }
        List<VulnerabilityTarget> targets = vulnerabilityTargetRepository.findAllVexLikeTargetsByVulnerabilityIds(normalizedIds);
        if (targets.isEmpty()) {
            List<VexAssertion> existingAssertions = vexAssertionRepository.findByVulnerability_IdIn(normalizedIds);
            if (!existingAssertions.isEmpty()) {
                vexAssertionRepository.deleteAllInBatch(existingAssertions);
            }
            Set<UUID> deletedIds = existingAssertions.stream()
                    .map(VexAssertion::getVulnerability)
                    .filter(Objects::nonNull)
                    .map(com.prototype.vulnwatch.domain.Vulnerability::getId)
                    .filter(Objects::nonNull)
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
            return new RefreshResult(0, deletedIds);
        }
        return synchronizeAssertionsDetailed(targets);
    }

    @Transactional
    public int refreshAllAssertions() {
        return refreshAllAssertionsDetailed().assertionCount();
    }

    @Transactional
    public RefreshResult refreshAllAssertionsDetailed() {
        if (!IntelligenceWriteContext.publishing()) {
            staging.append("VEX_REBUILD","*",null,"vex",java.util.Map.of(),"VALID");
            return new RefreshResult(0,Set.of());
        }
        List<VulnerabilityTarget> targets = vulnerabilityTargetRepository.findAllVexLikeTargets();
        if (targets.isEmpty()) {
            List<VexAssertion> existingAssertions = vexAssertionRepository.findAll();
            if (!existingAssertions.isEmpty()) {
                vexAssertionRepository.deleteAllInBatch();
            }
            Set<UUID> deletedIds = existingAssertions.stream()
                    .map(VexAssertion::getVulnerability)
                    .filter(Objects::nonNull)
                    .map(com.prototype.vulnwatch.domain.Vulnerability::getId)
                    .filter(Objects::nonNull)
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
            return new RefreshResult(0, deletedIds);
        }
        return synchronizeAssertionsDetailed(targets);
    }

    private int synchronizeAssertions(List<VulnerabilityTarget> targets) {
        return synchronizeAssertionsDetailed(targets).assertionCount();
    }

    private RefreshResult synchronizeAssertionsDetailed(List<VulnerabilityTarget> targets) {
        Set<UUID> vulnerabilityIds = new LinkedHashSet<>();
        for (VulnerabilityTarget target : targets) {
            if (target != null && target.getVulnerability() != null && target.getVulnerability().getId() != null) {
                vulnerabilityIds.add(target.getVulnerability().getId());
            }
        }
        if (vulnerabilityIds.isEmpty()) {
            return new RefreshResult(0, Set.of());
        }

        List<VulnerabilityIntelObservation> observations =
                vulnerabilityIntelObservationRepository.findByVulnerabilityIdIn(vulnerabilityIds);
        ObservationIndex observationIndex = ObservationIndex.from(observations);

        List<VexAssertion> existingAssertions = vexAssertionRepository.findByVulnerability_IdIn(vulnerabilityIds);
        Map<UUID, Map<String, VexAssertion>> existingByVulnerabilityAndKey = new HashMap<>();
        for (VexAssertion assertion : existingAssertions) {
            if (assertion.getVulnerability() == null || assertion.getVulnerability().getId() == null) {
                continue;
            }
            existingByVulnerabilityAndKey
                    .computeIfAbsent(assertion.getVulnerability().getId(), ignored -> new HashMap<>())
                    .put(statementIdentity(assertion.getSourceSystem(), assertion.getDocumentId(), assertion.getStatementKey()), assertion);
        }

        List<VulnerabilityTarget> orderedTargets = new ArrayList<>(targets);
        orderedTargets.sort(Comparator.comparing(VexAssertionService::targetSortKey));

        List<VexAssertion> toSave = new ArrayList<>();
        Set<UUID> retainedExistingIds = new HashSet<>();
        for (VulnerabilityTarget target : orderedTargets) {
            ExtractedAssertion extracted = extractAssertion(target);
            if (extracted == null || target.getVulnerability() == null || target.getVulnerability().getId() == null) {
                continue;
            }
            UUID vulnerabilityId = target.getVulnerability().getId();
            String statementIdentity = statementIdentity(
                    extracted.sourceSystem(),
                    extracted.documentId(),
                    extracted.statementKey()
            );
            VexAssertion assertion = existingByVulnerabilityAndKey
                    .getOrDefault(vulnerabilityId, Map.of())
                    .get(statementIdentity);
            if (assertion == null) {
                assertion = new VexAssertion();
            } else if (assertion.getId() != null) {
                retainedExistingIds.add(assertion.getId());
            }

            apply(assertion, target, extracted, observationIndex.find(target, extracted));
            toSave.add(assertion);
        }

        List<VexAssertion> toDelete = existingAssertions.stream()
                .filter(assertion -> assertion.getId() != null && !retainedExistingIds.contains(assertion.getId()))
                .toList();
        if (!toDelete.isEmpty()) {
            vexAssertionRepository.deleteAllInBatch(toDelete);
        }
        if (!toSave.isEmpty()) {
            vexAssertionRepository.saveAll(toSave);
        }
        return new RefreshResult(toSave.size(), Set.copyOf(vulnerabilityIds));
    }

    private void apply(
            VexAssertion assertion,
            VulnerabilityTarget target,
            ExtractedAssertion extracted,
            VulnerabilityIntelObservation observation
    ) {
        assertion.setVulnerability(target.getVulnerability());
        assertion.setObservation(observation);
        assertion.setTarget(target);
        assertion.setSoftwareIdentity(target.getSoftwareIdentity());
        assertion.setCpeDim(target.getCpeDim());
        assertion.setSourceSystem(extracted.sourceSystem());
        assertion.setProvider(extracted.provider());
        assertion.setDocumentId(extracted.documentId());
        assertion.setStatementKey(extracted.statementKey());
        assertion.setStatus(extracted.status());
        assertion.setTrustTier(extracted.trustTier());
        assertion.setFreshness(extracted.freshness());
        assertion.setEcosystem(target.getEcosystem());
        assertion.setNamespace(target.getNamespace());
        assertion.setPackageName(target.getPackageName());
        assertion.setNormalizedProductKey(extracted.normalizedProductKey());
        assertion.setVersionExact(target.getVersionExact());
        assertion.setVersionStart(target.getVersionStart());
        assertion.setStartInclusive(target.getStartInclusive());
        assertion.setVersionEnd(target.getVersionEnd());
        assertion.setEndInclusive(target.getEndInclusive());
        assertion.setFixedVersion(target.getFixed());
        assertion.setRawTarget(target.getRawTarget());
        assertion.setEvidenceJson(extracted.evidenceJson());
        assertion.setPublishedAt(extracted.publishedAt());
        assertion.setLastSeenAt(extracted.lastSeenAt());
        assertion.touch();
    }

    private ExtractedAssertion extractAssertion(VulnerabilityTarget target) {
        if (target == null || target.getVulnerability() == null || target.getVulnerability().getId() == null) {
            return null;
        }
        JsonNode qualifiers = parseQualifiers(target.getQualifiersJson());
        boolean vexLike = isVexLike(target.getSource(), qualifiers);
        if (!vexLike) {
            return null;
        }

        String rawStatus = textValue(qualifiers, "vexStatus");
        if (!hasText(rawStatus) && hasText(target.getSource()) && target.getSource().toLowerCase(Locale.ROOT).contains("vex")) {
            rawStatus = "UNDER_INVESTIGATION";
        }
        String normalizedStatus = impactEvaluationService.normalizeStatus(rawStatus);
        String provider = impactEvaluationService.normalizeProvider(firstNonBlank(
                textValue(qualifiers, "vexProvider"),
                vexPolicyService.inferProvider(target.getSource())
        ));
        String trustTier = normalizeUpper(firstNonBlank(
                textValue(qualifiers, "vexTrustTier"),
                vexPolicyService.inferTrustTier(provider, target.getSource())
        ));
        Instant publishedAt = parseInstant(textValue(qualifiers, "vexPublishedAt"));
        Instant lastSeenAt = parseInstant(textValue(qualifiers, "vexLastSeenAt"));
        if (lastSeenAt == null) {
            lastSeenAt = Instant.now();
        }
        String normalizedProductKey = firstNonBlank(
                target.getNormalizedTargetKey(),
                target.getPackageName(),
                target.getRawTarget(),
                target.getId() == null ? null : target.getId().toString()
        );
        if (!hasText(normalizedProductKey)) {
            return null;
        }

        String sourceSystem = firstNonBlank(target.getSource(), "unknown");
        String documentId = firstNonBlank(
                textValue(qualifiers, "advisoryDocumentId"),
                textValue(qualifiers, "advisoryUrl"),
                sourceSystem
        );
        String statementKey = statementKey(target, normalizedStatus, normalizedProductKey);
        String freshness = impactEvaluationService.normalizeFreshness(
                vexPolicyService.evaluateFreshness(normalizedStatus, publishedAt, lastSeenAt, null).outcome()
        );

        Map<String, Object> evidence = new LinkedHashMap<>();
        if (hasText(rawStatus)) {
            evidence.put("vexStatus", rawStatus.trim());
        }
        putIfPresent(evidence, "advisoryUrl", textValue(qualifiers, "advisoryUrl"));
        putIfPresent(evidence, "actionStatement", textValue(qualifiers, "actionStatement"));
        putIfPresent(evidence, "advisoryDocumentId", textValue(qualifiers, "advisoryDocumentId"));
        putIfPresent(evidence, "advisoryTitle", textValue(qualifiers, "advisoryTitle"));
        evidence.put("targetId", target.getId());
        evidence.put("targetType", target.getTargetType() == null ? null : target.getTargetType().name());
        evidence.put("normalizedTargetKey", normalizedProductKey);

        return new ExtractedAssertion(
                sourceSystem,
                provider,
                documentId,
                statementKey,
                normalizedStatus,
                trustTier,
                freshness,
                publishedAt,
                lastSeenAt,
                textValue(qualifiers, "advisoryUrl"),
                toJson(evidence),
                normalizedProductKey
        );
    }

    private boolean isVexLike(String source, JsonNode qualifiers) {
        if (hasText(source) && source.trim().toLowerCase(Locale.ROOT).contains("vex")) {
            return true;
        }
        return hasText(textValue(qualifiers, "vexStatus"));
    }

    private JsonNode parseQualifiers(String qualifiersJson) {
        if (!hasText(qualifiersJson)) {
            return objectMapper.getNodeFactory().nullNode();
        }
        try {
            return objectMapper.readTree(qualifiersJson);
        } catch (Exception ignored) {
            return objectMapper.getNodeFactory().nullNode();
        }
    }

    private String statementKey(VulnerabilityTarget target, String normalizedStatus, String normalizedProductKey) {
        String descriptor = String.join(
                "::",
                safe(target.getTargetType() == null ? null : target.getTargetType().name()),
                safe(normalizedProductKey),
                safe(normalizedStatus),
                safe(target.getVersionExact()),
                safe(target.getVersionStart()),
                safe(String.valueOf(target.getStartInclusive())),
                safe(target.getVersionEnd()),
                safe(String.valueOf(target.getEndInclusive())),
                safe(target.getFixed()),
                safe(target.getPackageName())
        );
        return sha256(descriptor);
    }

    private String statementIdentity(String sourceSystem, String documentId, String statementKey) {
        return safe(sourceSystem) + "::" + safe(documentId) + "::" + safe(statementKey);
    }

    private String toJson(Map<String, Object> payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            return "{}";
        }
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to hash VEX statement key", e);
        }
    }

    private static String targetSortKey(VulnerabilityTarget target) {
        UUID vulnerabilityId = target == null || target.getVulnerability() == null ? null : target.getVulnerability().getId();
        return safe(vulnerabilityId == null ? null : vulnerabilityId.toString())
                + "::"
                + safe(target == null || target.getSource() == null ? null : target.getSource())
                + "::"
                + safe(target == null || target.getNormalizedTargetKey() == null ? null : target.getNormalizedTargetKey())
                + "::"
                + safe(target == null || target.getId() == null ? null : target.getId().toString());
    }

    private String textValue(JsonNode node, String field) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        String text = node.path(field).asText("");
        return hasText(text) ? text.trim() : null;
    }

    private Instant parseInstant(String value) {
        if (!hasText(value)) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        } catch (Exception ignored) {
            return null;
        }
    }

    private void putIfPresent(Map<String, Object> payload, String key, String value) {
        if (hasText(value)) {
            payload.put(key, value);
        }
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private String normalizeUpper(String value) {
        return hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : "UNKNOWN";
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record ExtractedAssertion(
            String sourceSystem,
            String provider,
            String documentId,
            String statementKey,
            String status,
            String trustTier,
            String freshness,
            Instant publishedAt,
            Instant lastSeenAt,
            String advisoryUrl,
            String evidenceJson,
            String normalizedProductKey
    ) {
    }

    private record ObservationKey(UUID vulnerabilityId, String sourceSystem, String sourceUrl) {
    }

    private record ObservationIndex(
            Map<ObservationKey, VulnerabilityIntelObservation> byUrl,
            Map<String, VulnerabilityIntelObservation> latestBySource
    ) {
        static ObservationIndex from(List<VulnerabilityIntelObservation> observations) {
            Map<ObservationKey, VulnerabilityIntelObservation> byUrl = new HashMap<>();
            Map<String, VulnerabilityIntelObservation> latestBySource = new HashMap<>();
            for (VulnerabilityIntelObservation observation : observations) {
                if (observation.getVulnerability() == null || observation.getVulnerability().getId() == null) {
                    continue;
                }
                String sourceSystem = normalize(observation.getSourceSystem());
                String sourceUrl = normalizeUrl(observation.getSourceUrl());
                if (sourceUrl != null) {
                    ObservationKey key = new ObservationKey(observation.getVulnerability().getId(), sourceSystem, sourceUrl);
                    byUrl.merge(key, observation, ObservationIndex::laterObservation);
                }
                String latestKey = observation.getVulnerability().getId() + "::" + sourceSystem;
                latestBySource.merge(latestKey, observation, ObservationIndex::laterObservation);
            }
            return new ObservationIndex(byUrl, latestBySource);
        }

        VulnerabilityIntelObservation find(VulnerabilityTarget target, ExtractedAssertion extracted) {
            if (target == null || target.getVulnerability() == null || target.getVulnerability().getId() == null || extracted == null) {
                return null;
            }
            String sourceSystem = normalize(extracted.sourceSystem());
            String sourceUrl = normalizeUrl(extracted.advisoryUrl());
            if (sourceUrl != null) {
                VulnerabilityIntelObservation bySourceUrl = byUrl.get(new ObservationKey(
                        target.getVulnerability().getId(),
                        sourceSystem,
                        sourceUrl
                ));
                if (bySourceUrl != null) {
                    return bySourceUrl;
                }
            }
            return latestBySource.get(target.getVulnerability().getId() + "::" + sourceSystem);
        }

        private static VulnerabilityIntelObservation laterObservation(
                VulnerabilityIntelObservation left,
                VulnerabilityIntelObservation right
        ) {
            Instant leftSeen = left.getLastSeenAt() == null ? Instant.EPOCH : left.getLastSeenAt();
            Instant rightSeen = right.getLastSeenAt() == null ? Instant.EPOCH : right.getLastSeenAt();
            return rightSeen.isAfter(leftSeen) ? right : left;
        }

        private static String normalize(String value) {
            return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        }

        private static String normalizeUrl(String value) {
            return value == null || value.isBlank() ? null : value.trim();
        }
    }
}
