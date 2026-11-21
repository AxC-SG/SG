package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentCpeMap;
import com.prototype.vulnwatch.domain.IdentityLink;
import com.prototype.vulnwatch.domain.IdentityMatchRule;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.repo.IdentityLinkRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.SoftwareInstanceRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.util.IdentityUtil;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class CorrelationCandidateService {

    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;
    private final SoftwareInstanceRepository softwareInstanceRepository;
    private final IdentityLinkRepository identityLinkRepository;

    public CorrelationCandidateService(
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository,
            SoftwareInstanceRepository softwareInstanceRepository,
            IdentityLinkRepository identityLinkRepository
    ) {
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.inventoryComponentCpeMapRepository = inventoryComponentCpeMapRepository;
        this.softwareInstanceRepository = softwareInstanceRepository;
        this.identityLinkRepository = identityLinkRepository;
    }

    public CandidateBundle buildCandidateBundle(List<InventoryComponent> components) {
        if (components == null || components.isEmpty()) {
            return new CandidateBundle(Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of());
        }

        Set<UUID> componentIds = new HashSet<>();
        for (InventoryComponent component : components) {
            if (component != null && component.getId() != null) {
                componentIds.add(component.getId());
            }
        }
        if (componentIds.isEmpty()) {
            return new CandidateBundle(Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of());
        }

        List<InventoryComponentCpeMap> mapRows = inventoryComponentCpeMapRepository.findByComponent_IdIn(componentIds);
        Map<UUID, Set<UUID>> componentCpeIds = new HashMap<>();
        Set<UUID> cpeIds = new HashSet<>();
        for (InventoryComponentCpeMap row : mapRows) {
            if (row.getComponent() == null || row.getComponent().getId() == null
                    || row.getCpeDim() == null || row.getCpeDim().getId() == null) {
                continue;
            }
            UUID componentId = row.getComponent().getId();
            UUID cpeId = row.getCpeDim().getId();
            componentCpeIds.computeIfAbsent(componentId, ignored -> new HashSet<>()).add(cpeId);
            cpeIds.add(cpeId);
        }

        Map<UUID, List<VulnerabilityTarget>> cpeTargetsByCpeId = cpeIds.isEmpty()
                ? Map.of()
                : groupByCpeId(vulnerabilityTargetRepository.findByTargetTypeAndCpeDim_IdIn(
                        VulnerabilityTargetType.CPE,
                        cpeIds
                ));

        Map<UUID, Set<String>> componentPurls = new HashMap<>();
        Map<UUID, Set<String>> componentCoordKeys = new HashMap<>();
        Set<String> purlKeys = new HashSet<>();
        Set<String> coordKeys = new HashSet<>();

        for (InventoryComponent component : components) {
            if (component == null || component.getId() == null) {
                continue;
            }
            String normalizedPurl = IdentityUtil.normalizePurl(component.getPurl());
            if (!normalizedPurl.isBlank()) {
                componentPurls.computeIfAbsent(component.getId(), ignored -> new HashSet<>()).add(normalizedPurl);
                purlKeys.add(normalizedPurl);
            }

            Set<String> resolvedCoordKeys = IdentityUtil.correlationCoordKeys(
                    component.getEcosystem(), component.getPackageName(), component.getPurl());
            if (!resolvedCoordKeys.isEmpty()) {
                componentCoordKeys.computeIfAbsent(component.getId(), ignored -> new HashSet<>()).addAll(resolvedCoordKeys);
                coordKeys.addAll(resolvedCoordKeys);
            }
        }

        Map<String, List<VulnerabilityTarget>> purlTargetsByKey = purlKeys.isEmpty()
                ? Map.of()
                : groupByNormalizedTargetKey(vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(
                        VulnerabilityTargetType.PURL,
                        purlKeys
                ));

        Map<String, List<VulnerabilityTarget>> coordTargetsByKey = coordKeys.isEmpty()
                ? Map.of()
                : groupByNormalizedTargetKey(vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(
                        VulnerabilityTargetType.COORD,
                        coordKeys
                ));

        // ADVISORY_PACKAGE targets use the same coordKey(ecosystem, packageName) format —
        // look them up using the same derived coord keys so GHSA/custom advisory rules match.
        Map<String, List<VulnerabilityTarget>> advisoryPackageTargetsByKey = coordKeys.isEmpty()
                ? Map.of()
                : groupByNormalizedTargetKey(vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(
                        VulnerabilityTargetType.ADVISORY_PACKAGE,
                        coordKeys
                ));

        Map<UUID, UUID> componentSoftwareIdentityIds = new HashMap<>();
        Set<UUID> softwareIdentityIds = new HashSet<>();
        for (InventoryComponent component : components) {
            if (component == null
                    || component.getId() == null
                    || component.getSoftwareIdentity() == null
                    || component.getSoftwareIdentity().getId() == null) {
                continue;
            }
            UUID softwareIdentityId = component.getSoftwareIdentity().getId();
            componentSoftwareIdentityIds.put(component.getId(), softwareIdentityId);
            softwareIdentityIds.add(softwareIdentityId);
        }

        Map<UUID, List<VulnerabilityTarget>> identityTargetsBySoftwareIdentityId = softwareIdentityIds.isEmpty()
                ? Map.of()
                : groupBySoftwareIdentity(vulnerabilityTargetRepository.findBySoftwareIdentityIds(softwareIdentityIds));

        Map<UUID, IdentityMatchRule> hostMatchRulesByComponentId = loadHostMatchRules(componentIds);

        return new CandidateBundle(
                componentCpeIds,
                cpeTargetsByCpeId,
                componentPurls,
                purlTargetsByKey,
                componentCoordKeys,
                coordTargetsByKey,
                advisoryPackageTargetsByKey,
                componentSoftwareIdentityIds,
                identityTargetsBySoftwareIdentityId,
                hostMatchRulesByComponentId
        );
    }

    public List<CandidateMatch> candidatesForComponent(InventoryComponent component, CandidateBundle bundle) {
        if (component == null || component.getId() == null) {
            return List.of();
        }

        Set<UUID> componentCpeIds = bundle.componentCpeIdsByComponentId().getOrDefault(component.getId(), Set.of());
        List<CandidateMatch> matches = new ArrayList<>();
        Set<UUID> dedupeTargetIds = new HashSet<>();

        UUID softwareIdentityId = bundle.componentSoftwareIdentityIdsByComponentId().get(component.getId());
        if (softwareIdentityId != null) {
            IdentityMatchRule matchRule = bundle.hostMatchRulesByComponentId().getOrDefault(component.getId(), IdentityMatchRule.NORMALIZED_KEY);
            appendIdentityMatches(
                    bundle.identityTargetsBySoftwareIdentityId().getOrDefault(softwareIdentityId, List.of()),
                    matchRule,
                    dedupeTargetIds,
                    matches
            );
        }

        List<UUID> orderedCpeIds = componentCpeIds.stream().sorted().toList();
        for (UUID cpeId : orderedCpeIds) {
            List<VulnerabilityTarget> targets = new ArrayList<>(bundle.cpeTargetsByCpeId().getOrDefault(cpeId, List.of()));
            targets.sort(Comparator
                    .comparing((VulnerabilityTarget target) -> target.getCpeWildcardScore() == null ? Integer.MAX_VALUE : target.getCpeWildcardScore())
                    .thenComparing(VulnerabilityTarget::getId, Comparator.nullsLast(Comparator.naturalOrder())));

            for (VulnerabilityTarget target : targets) {
                if (target.getId() == null || !dedupeTargetIds.add(target.getId())) {
                    continue;
                }
                boolean direct = isCpeDirect(target);
                String matchedBy = direct ? "cpe-indexed-direct+version" : "cpe-indexed-fallback+version";
                int rank = (direct ? 0 : 100) + Math.max(0, target.getCpeWildcardScore() == null ? 10 : target.getCpeWildcardScore());
                Map<String, Double> breakdown = confidenceBreakdown(target, matchedBy);
                double confidence = computeConfidence(matchedBy, breakdown);
                matches.add(new CandidateMatch(target, matchedBy, rank, confidence, breakdown));
            }
        }

        appendIndexedMatches(
                bundle.componentPurlsByComponentId().getOrDefault(component.getId(), Set.of()),
                bundle.purlTargetsByNormalizedKey(),
                "purl-indexed-exact+version",
                20,
                dedupeTargetIds,
                matches
        );

        appendIndexedMatches(
                bundle.componentCoordKeysByComponentId().getOrDefault(component.getId(), Set.of()),
                bundle.coordTargetsByNormalizedKey(),
                "coord-indexed-exact+version",
                40,
                dedupeTargetIds,
                matches
        );

        appendIndexedMatches(
                bundle.componentCoordKeysByComponentId().getOrDefault(component.getId(), Set.of()),
                bundle.advisoryPackageTargetsByNormalizedKey(),
                "advisory-pkg-indexed-exact+version",
                50,
                dedupeTargetIds,
                matches
        );

        return matches;
    }

    private void appendIdentityMatches(
            List<VulnerabilityTarget> targets,
            IdentityMatchRule matchRule,
            Set<UUID> dedupeTargetIds,
            List<CandidateMatch> matches
    ) {
        if (targets == null || targets.isEmpty()) {
            return;
        }
        List<VulnerabilityTarget> orderedTargets = new ArrayList<>(targets);
        orderedTargets.sort(Comparator.comparing(VulnerabilityTarget::getId, Comparator.nullsLast(Comparator.naturalOrder())));
        String matchedBy = switch (matchRule) {
            case HASH -> "identity-hash-indexed+version";
            case IDENTIFIER -> "identity-identifier-indexed+version";
            case NORMALIZED_KEY -> "identity-normalized-key+version";
        };
        int baseRank = switch (matchRule) {
            case HASH -> 5;
            case IDENTIFIER -> 8;
            case NORMALIZED_KEY -> 12;
        };
        for (VulnerabilityTarget target : orderedTargets) {
            if (target.getId() == null || !dedupeTargetIds.add(target.getId())) {
                continue;
            }
            int rank = baseRank + rankPenalty(target);
            Map<String, Double> breakdown = confidenceBreakdown(target, matchedBy);
            double confidence = computeConfidence(matchedBy, breakdown);
            matches.add(new CandidateMatch(target, matchedBy, rank, confidence, breakdown));
        }
    }

    private void appendIndexedMatches(
            Set<String> keys,
            Map<String, List<VulnerabilityTarget>> targetsByKey,
            String matchedBy,
            int baseRank,
            Set<UUID> dedupeTargetIds,
            List<CandidateMatch> matches
    ) {
        if (keys == null || keys.isEmpty()) {
            return;
        }
        List<String> orderedKeys = keys.stream().sorted().toList();
        for (String key : orderedKeys) {
            List<VulnerabilityTarget> targets = new ArrayList<>(targetsByKey.getOrDefault(key, List.of()));
            targets.sort(Comparator.comparing(VulnerabilityTarget::getId, Comparator.nullsLast(Comparator.naturalOrder())));
            for (VulnerabilityTarget target : targets) {
                if (target.getId() == null || !dedupeTargetIds.add(target.getId())) {
                    continue;
                }
                int rank = baseRank + rankPenalty(target);
                Map<String, Double> breakdown = confidenceBreakdown(target, matchedBy);
                double confidence = computeConfidence(matchedBy, breakdown);
                matches.add(new CandidateMatch(target, matchedBy, rank, confidence, breakdown));
            }
        }
    }

    private boolean isCpeDirect(VulnerabilityTarget target) {
        Integer wildcardScore = target.getCpeWildcardScore();
        if (wildcardScore == null) {
            return false;
        }
        return wildcardScore <= 2;
    }

    private double computeConfidence(String matchedBy, Map<String, Double> breakdown) {
        double base = breakdown.getOrDefault("base", 0.50);
        double boosts = breakdown.getOrDefault("boosts", 0.0);
        double penalties = breakdown.getOrDefault("penalties", 0.0);
        double raw = base + boosts - penalties;
        double capped = Math.min(capFor(matchedBy), raw);
        return Math.max(0.05, Math.min(0.99, capped));
    }

    private Map<String, Double> confidenceBreakdown(VulnerabilityTarget target, String matchedBy) {
        double base = switch (matcherPrefix(matchedBy)) {
            case "identity-hash-indexed" -> 0.94;
            case "identity-identifier-indexed" -> 0.90;
            case "identity-normalized-key" -> 0.82;
            case "cpe-indexed-direct" -> 0.72;
            case "cpe-indexed-fallback" -> 0.54;
            case "purl-indexed-exact" -> 0.66;
            case "coord-indexed-exact" -> 0.58;
            case "advisory-pkg-indexed-exact" -> 0.60;
            default -> 0.50;
        };

        double boosts = 0.0;
        if (target.getVersionExact() != null && !target.getVersionExact().isBlank()) {
            boosts += 0.06;
        }
        if ((target.getVersionStart() != null && !target.getVersionStart().isBlank())
                || (target.getVersionEnd() != null && !target.getVersionEnd().isBlank())
                || (target.getIntroduced() != null && !target.getIntroduced().isBlank())
                || (target.getFixed() != null && !target.getFixed().isBlank())) {
            boosts += 0.04;
        }

        double penalties = 0.0;
        if ("cpe-indexed-fallback".equals(matcherPrefix(matchedBy))) {
            penalties += 0.05;
        }
        if ("identity-normalized-key".equals(matcherPrefix(matchedBy))) {
            penalties += 0.02;
        }
        if ("coord-indexed-exact".equals(matcherPrefix(matchedBy))) {
            penalties += 0.04;
        }
        if ("advisory-pkg-indexed-exact".equals(matcherPrefix(matchedBy))) {
            penalties += 0.03;
        }

        Map<String, Double> breakdown = new LinkedHashMap<>();
        breakdown.put("base", base);
        breakdown.put("boosts", boosts);
        breakdown.put("penalties", penalties);
        breakdown.put("cap", capFor(matchedBy));
        return breakdown;
    }

    private double capFor(String matchedBy) {
        return switch (matcherPrefix(matchedBy)) {
            case "identity-hash-indexed" -> 0.99;
            case "identity-identifier-indexed" -> 0.97;
            case "identity-normalized-key" -> 0.90;
            case "cpe-indexed-direct" -> 0.90;
            case "cpe-indexed-fallback" -> 0.76;
            case "purl-indexed-exact" -> 0.84;
            case "coord-indexed-exact" -> 0.78;
            case "advisory-pkg-indexed-exact" -> 0.80;
            default -> 0.70;
        };
    }

    private int rankPenalty(VulnerabilityTarget target) {
        int penalty = 0;
        boolean hasRange = (target.getVersionStart() != null && !target.getVersionStart().isBlank())
                || (target.getVersionEnd() != null && !target.getVersionEnd().isBlank())
                || (target.getIntroduced() != null && !target.getIntroduced().isBlank())
                || (target.getFixed() != null && !target.getFixed().isBlank());
        if (!hasRange) {
            penalty += 6;
        }
        if (target.getVersionExact() == null || target.getVersionExact().isBlank()) {
            penalty += 3;
        }
        return penalty;
    }

    private String matcherPrefix(String matchedBy) {
        if (matchedBy == null || matchedBy.isBlank()) {
            return "";
        }
        int index = matchedBy.indexOf('+');
        return index >= 0 ? matchedBy.substring(0, index) : matchedBy;
    }

    private Map<UUID, List<VulnerabilityTarget>> groupByCpeId(List<VulnerabilityTarget> targets) {
        Map<UUID, List<VulnerabilityTarget>> map = new HashMap<>();
        for (VulnerabilityTarget target : targets) {
            if (target.getCpeDim() == null || target.getCpeDim().getId() == null) {
                continue;
            }
            map.computeIfAbsent(target.getCpeDim().getId(), ignored -> new ArrayList<>()).add(target);
        }
        return map;
    }

    private Map<String, List<VulnerabilityTarget>> groupByNormalizedTargetKey(List<VulnerabilityTarget> targets) {
        Map<String, List<VulnerabilityTarget>> map = new HashMap<>();
        for (VulnerabilityTarget target : targets) {
            if (target.getNormalizedTargetKey() == null || target.getNormalizedTargetKey().isBlank()) {
                continue;
            }
            map.computeIfAbsent(target.getNormalizedTargetKey(), ignored -> new ArrayList<>()).add(target);
        }
        return map;
    }

    private Map<UUID, List<VulnerabilityTarget>> groupBySoftwareIdentity(List<VulnerabilityTarget> targets) {
        Map<UUID, List<VulnerabilityTarget>> map = new HashMap<>();
        for (VulnerabilityTarget target : targets) {
            if (target.getSoftwareIdentity() == null || target.getSoftwareIdentity().getId() == null) {
                continue;
            }
            map.computeIfAbsent(target.getSoftwareIdentity().getId(), ignored -> new ArrayList<>()).add(target);
        }
        return map;
    }

    private Map<UUID, IdentityMatchRule> loadHostMatchRules(Set<UUID> componentIds) {
        if (componentIds == null || componentIds.isEmpty()) {
            return Map.of();
        }
        Map<String, UUID> componentIdBySoftwareInstanceId = new HashMap<>();
        for (SoftwareInstance instance : softwareInstanceRepository.findByInventoryComponent_IdIn(componentIds)) {
            if (instance.getId() == null
                    || instance.getInventoryComponent() == null
                    || instance.getInventoryComponent().getId() == null) {
                continue;
            }
            componentIdBySoftwareInstanceId.put(instance.getId().toString(), instance.getInventoryComponent().getId());
        }
        if (componentIdBySoftwareInstanceId.isEmpty()) {
            return Map.of();
        }
        Map<UUID, IdentityMatchRule> rules = new HashMap<>();
        List<IdentityLink> links = identityLinkRepository.findBySourceTypeAndSourceIdInAndTargetType(
                "SOFTWARE_INSTANCE",
                componentIdBySoftwareInstanceId.keySet(),
                "SOFTWARE_IDENTITY"
        );
        for (IdentityLink link : links) {
            UUID componentId = componentIdBySoftwareInstanceId.get(link.getSourceId());
            if (componentId == null || link.getMatchRule() == null) {
                continue;
            }
            rules.merge(componentId, link.getMatchRule(), this::preferredRule);
        }
        return rules;
    }

    private IdentityMatchRule preferredRule(IdentityMatchRule left, IdentityMatchRule right) {
        return precedence(left) <= precedence(right) ? left : right;
    }

    private int precedence(IdentityMatchRule rule) {
        if (rule == null) {
            return Integer.MAX_VALUE;
        }
        return switch (rule) {
            case HASH -> 0;
            case IDENTIFIER -> 1;
            case NORMALIZED_KEY -> 2;
        };
    }

    public record CandidateBundle(
            Map<UUID, Set<UUID>> componentCpeIdsByComponentId,
            Map<UUID, List<VulnerabilityTarget>> cpeTargetsByCpeId,
            Map<UUID, Set<String>> componentPurlsByComponentId,
            Map<String, List<VulnerabilityTarget>> purlTargetsByNormalizedKey,
            Map<UUID, Set<String>> componentCoordKeysByComponentId,
            Map<String, List<VulnerabilityTarget>> coordTargetsByNormalizedKey,
            Map<String, List<VulnerabilityTarget>> advisoryPackageTargetsByNormalizedKey,
            Map<UUID, UUID> componentSoftwareIdentityIdsByComponentId,
            Map<UUID, List<VulnerabilityTarget>> identityTargetsBySoftwareIdentityId,
            Map<UUID, IdentityMatchRule> hostMatchRulesByComponentId
    ) {
    }

    public record CandidateMatch(
            VulnerabilityTarget target,
            String matchedBy,
            int rank,
            double confidence,
            Map<String, Double> confidenceBreakdown
    ) {
    }
}
