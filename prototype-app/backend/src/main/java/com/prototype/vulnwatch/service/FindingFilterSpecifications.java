package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AiBomResourceVulnerabilityLink;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCreationSource;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingsFilter;
import jakarta.persistence.criteria.JoinType;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.jpa.domain.Specification;

public final class FindingFilterSpecifications {

    private FindingFilterSpecifications() {
    }

    public static Specification<Finding> byFilter(Tenant tenant, FindingsFilter filter) {
        if (filter.hasOwnershipFilter()) {
            // The canonical ownership filter exists only on the projection (cursor) path; refusing here keeps both
            // paths from returning different result sets for the same filter.
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,
                    "Owner team and ownership status filters require cursor paging (pass limit or cursor)");
        }
        return byTenant(tenant)
                .and(bySeverity(filter.severity()))
                .and(byStatus(filter.status()))
                .and(byDecisionState(filter.decisionState()))
                .and(byCreationSource(filter.creationSource()))
                .and(byMatchMethod(filter.matchMethod()))
                .and(byVexStatus(filter.vexStatus()))
                .and(byVexFreshness(filter.vexFreshness()))
                .and(byVexProvider(filter.vexProvider()))
                .and(byMinConfidence(filter.minConfidence()))
                .and(byVulnerabilityId(filter.vulnerabilityId()))
                .and(byPackageName(filter.packageName()))
                .and(byEcosystem(filter.ecosystem()))
                .and(byOwnerGroup(filter.ownerGroup()))
                .and(byAssignedTo(filter.assignedTo()))
                .and(byUnassignedOnly(filter.unassignedOnly()))
                .and(byIncidentLinked(filter.incidentLinked()))
                .and(byDueDateBand(filter.dueDateBand()))
                .and(byAssetName(filter.assetName()))
                .and(bySupportGroup(filter.supportGroup()))
                .and(byPatchAvailable(filter.patchAvailable()))
                .and(bySuppressedUntilBand(filter.suppressedUntilBand()))
                .and(byAssetType(filter.assetType()))
                .and((root, query, builder) -> builder.or(builder.isNull(root.get("findingKind")),
                        builder.notEqual(root.get("findingKind"), "AI_RUNTIME")))
                .and(byFindingKind(filter.findingKind()))
                .and(byAffectedAiResourceId(filter.affectedAiResourceId()))
                .and(byHasAffectedAiResource(filter.hasAffectedAiResource()))
                .and(byGroup(filter.groupField(), filter.groupValue()));
    }

    private static Specification<Finding> byGroup(String field, String value) {
        if (!hasText(field) || value == null) return null;
        return (root, query, cb) -> {
            var component = root.join("component", JoinType.LEFT);
            var directAsset = root.join("asset", JoinType.LEFT);
            var componentAsset = component.join("asset", JoinType.LEFT);
            jakarta.persistence.criteria.Expression<String> expression = switch (field) {
                case "severity" -> cb.coalesce(cb.nullif(cb.coalesce(root.<String>get("severityOverride"), root.join("vulnerability", JoinType.LEFT).<String>get("severity")), ""), "UNKNOWN");
                case "status" -> root.get("status").as(String.class);
                case "assetName" -> cb.coalesce(cb.nullif(cb.coalesce(directAsset.<String>get("name"), componentAsset.<String>get("name")), ""), "Unknown");
                case "packageName" -> cb.coalesce(cb.nullif(component.<String>get("packageName"), ""), "Unknown");
                case "vulnerabilityId" -> cb.coalesce(cb.nullif(root.join("vulnerability", JoinType.LEFT).<String>get("externalId"), ""), "Unknown");
                case "owner" -> cb.coalesce(cb.coalesce(
                        cb.nullif(cb.trim(cb.coalesce(directAsset.<String>get("ownerTeam"), componentAsset.<String>get("ownerTeam"))), ""),
                        cb.nullif(cb.trim(cb.coalesce(directAsset.<String>get("ownerEmail"), componentAsset.<String>get("ownerEmail"))), "")), "Unassigned");
                default -> throw new IllegalArgumentException("Unsupported finding group: " + field);
            };
            return cb.equal(expression, value);
        };
    }

    public static Specification<Finding> statusEquals(FindingStatus status) {
        return (root, query, cb) -> cb.equal(root.get("status"), status);
    }

    public static Specification<Finding> severityEquals(String severity) {
        return bySeverity(List.of(severity));
    }

    public static Specification<Finding> incidentLinked(boolean linked) {
        return byIncidentLinked(linked);
    }

    public static Specification<Finding> dueDateBand(String band) {
        return byDueDateBand(band);
    }

    public static List<String> sortByPreferredOrder(Set<String> values, List<String> preferredOrder) {
        Set<String> remaining = new LinkedHashSet<>(values);
        List<String> sorted = new ArrayList<>();
        for (String preferredValue : preferredOrder) {
            if (remaining.remove(preferredValue)) {
                sorted.add(preferredValue);
            }
        }
        sorted.addAll(remaining.stream().sorted().toList());
        return sorted;
    }

    public static Set<String> normalizeUpperFilterValues(List<String> rawValues) {
        return normalizeFilterValues(rawValues).stream()
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    public static Set<String> normalizeLowerFilterValues(List<String> rawValues) {
        return normalizeFilterValues(rawValues).stream()
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    public static Set<String> normalizeFilterValues(List<String> rawValues) {
        if (rawValues == null || rawValues.isEmpty()) {
            return Set.of();
        }
        Set<String> values = new HashSet<>();
        for (String rawValue : rawValues) {
            if (!hasText(rawValue)) {
                continue;
            }
            for (String splitValue : rawValue.split(",")) {
                String normalized = splitValue == null ? "" : splitValue.trim();
                if (normalized.isEmpty() || "ALL".equalsIgnoreCase(normalized)) {
                    continue;
                }
                values.add(normalized);
            }
        }
        return values;
    }

    public static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static Specification<Finding> byTenant(Tenant tenant) {
        return (root, query, cb) -> cb.equal(root.get("tenant"), tenant);
    }

    private static Specification<Finding> bySeverity(List<String> severities) {
        Set<String> normalized = normalizeFilterValues(severities);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<String> upper = normalized.stream().map(String::toUpperCase).collect(Collectors.toSet());
        return (root, query, cb) -> {
            jakarta.persistence.criteria.Expression<String> override = cb.upper(root.<String>get("severityOverride"));
            jakarta.persistence.criteria.Expression<String> vulnSev = cb.upper(root.join("vulnerability").get("severity"));
            jakarta.persistence.criteria.Expression<String> effective = cb.coalesce(override, vulnSev);
            return effective.in(upper);
        };
    }

    /**
     * Restricts to the given finding kinds. Empty means every in-scope kind, which keeps All Findings
     * inclusive by default; AI_RUNTIME is excluded independently at the release boundary.
     *
     * <p>finding_kind is a plain string column on the entity, so this matches on the raw
     * value rather than an enum -- the set is widened by tenant migrations (AI_RUNTIME
     * arrived that way) and an unrecognised value must narrow the result rather than be
     * silently dropped from the predicate, which would widen it instead.
     */
    private static Specification<Finding> byFindingKind(List<String> kinds) {
        Set<String> normalized = normalizeFilterValues(kinds);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<String> upper = new HashSet<>();
        for (String value : normalized) {
            upper.add(value.toUpperCase(Locale.ROOT));
        }
        return (root, query, builder) -> root.get("findingKind").in(upper);
    }

    /**
     * Restricts to findings transitively affecting one of the given declared AI-BOM resource
     * ids (Milestone 3 part 5.1's {@code ai_bom_resource_vulnerability_links} bridge). An
     * existence subquery, not a join: a finding can be reached by more than one declared
     * resource, and a join would multiply result rows.
     */
    private static Specification<Finding> byAffectedAiResourceId(List<String> resourceIds) {
        Set<String> normalized = normalizeFilterValues(resourceIds);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<UUID> ids = new HashSet<>();
        for (String value : normalized) {
            try {
                ids.add(UUID.fromString(value.trim()));
            } catch (IllegalArgumentException ignored) {
            }
        }
        if (ids.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            var subquery = query.subquery(Long.class);
            var linkRoot = subquery.from(AiBomResourceVulnerabilityLink.class);
            subquery.select(cb.literal(1L));
            subquery.where(
                    cb.equal(linkRoot.get("findingId"), root.get("id")),
                    cb.equal(linkRoot.get("status"), "ACTIVE"),
                    linkRoot.get("declaredResourceId").in(ids)
            );
            return cb.exists(subquery);
        };
    }

    /** Same existence-subquery shape as {@link #byAffectedAiResourceId}, with no id restriction. */
    private static Specification<Finding> byHasAffectedAiResource(Boolean hasAffectedAiResource) {
        if (hasAffectedAiResource == null) {
            return null;
        }
        return (root, query, cb) -> {
            var subquery = query.subquery(Long.class);
            var linkRoot = subquery.from(AiBomResourceVulnerabilityLink.class);
            subquery.select(cb.literal(1L));
            subquery.where(cb.equal(linkRoot.get("findingId"), root.get("id")), cb.equal(linkRoot.get("status"), "ACTIVE"));
            return hasAffectedAiResource ? cb.exists(subquery) : cb.not(cb.exists(subquery));
        };
    }

    private static Specification<Finding> byStatus(List<String> statuses) {
        Set<String> normalized = normalizeFilterValues(statuses);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<FindingStatus> findingStatuses = new HashSet<>();
        for (String value : normalized) {
            try {
                findingStatuses.add(FindingStatus.valueOf(value.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException ignored) {
            }
        }
        if (findingStatuses.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> root.get("status").in(findingStatuses);
    }

    private static Specification<Finding> byDecisionState(List<String> decisionStates) {
        Set<String> normalized = normalizeFilterValues(decisionStates);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<FindingDecisionState> states = new HashSet<>();
        for (String value : normalized) {
            try {
                states.add(FindingDecisionState.valueOf(value.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException ignored) {
            }
        }
        if (states.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> root.get("decisionState").in(states);
    }

    private static Specification<Finding> byCreationSource(List<String> creationSources) {
        Set<String> normalized = normalizeFilterValues(creationSources);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<FindingCreationSource> sources = new HashSet<>();
        for (String value : normalized) {
            try {
                sources.add(FindingCreationSource.valueOf(value.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException ignored) {
            }
        }
        if (sources.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> root.get("creationSource").in(sources);
    }

    private static Specification<Finding> byMatchMethod(List<String> matchMethods) {
        Set<String> normalized = normalizeFilterValues(matchMethods);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<String> lower = normalized.stream().map(value -> value.toLowerCase(Locale.ROOT)).collect(Collectors.toSet());
        return (root, query, cb) -> cb.lower(root.get("matchedBy")).in(lower);
    }

    private static Specification<Finding> byVexStatus(List<String> vexStatuses) {
        Set<String> normalized = normalizeUpperFilterValues(vexStatuses);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("UNKNOWN")) {
                predicates.add(cb.isNull(root.get("vexStatus")));
            }
            predicates.add(cb.upper(root.get("vexStatus")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private static Specification<Finding> byVexFreshness(List<String> vexFreshness) {
        Set<String> normalized = normalizeUpperFilterValues(vexFreshness);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("UNKNOWN")) {
                predicates.add(cb.isNull(root.get("vexFreshness")));
            }
            predicates.add(cb.upper(root.get("vexFreshness")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private static Specification<Finding> byVexProvider(List<String> vexProviders) {
        Set<String> normalized = normalizeLowerFilterValues(vexProviders);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("unknown")) {
                predicates.add(cb.isNull(root.get("vexProvider")));
            }
            predicates.add(cb.lower(root.get("vexProvider")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private static Specification<Finding> byMinConfidence(Double minConfidence) {
        if (minConfidence == null) {
            return null;
        }
        return (root, query, cb) -> cb.greaterThanOrEqualTo(root.get("confidenceScore"), minConfidence);
    }

    private static Specification<Finding> byVulnerabilityId(String vulnerabilityId) {
        if (!hasText(vulnerabilityId)) {
            return null;
        }
        String expected = vulnerabilityId.trim().toUpperCase(Locale.ROOT);
        return (root, query, cb) -> cb.equal(cb.upper(root.join("vulnerability").get("externalId")), expected);
    }

    private static Specification<Finding> byPackageName(String packageName) {
        if (!hasText(packageName)) {
            return null;
        }
        String expected = packageName.trim().toLowerCase(Locale.ROOT);
        return (root, query, cb) -> cb.equal(cb.lower(root.join("component").get("packageName")), expected);
    }

    private static Specification<Finding> byEcosystem(String ecosystem) {
        if (!hasText(ecosystem)) {
            return null;
        }
        String expected = ecosystem.trim().toLowerCase(Locale.ROOT);
        return (root, query, cb) -> cb.equal(cb.lower(root.join("component").get("ecosystem")), expected);
    }

    private static Specification<Finding> byOwnerGroup(String ownerGroup) {
        if (!hasText(ownerGroup)) {
            return null;
        }
        String expected = "%" + ownerGroup.trim().toLowerCase(Locale.ROOT) + "%";
        return (root, query, cb) -> cb.like(cb.lower(root.get("ownerGroup")), expected);
    }

    private static Specification<Finding> byAssignedTo(String assignedTo) {
        if (!hasText(assignedTo)) {
            return null;
        }
        String expected = "%" + assignedTo.trim().toLowerCase(Locale.ROOT) + "%";
        return (root, query, cb) -> cb.like(cb.lower(root.get("assignedTo")), expected);
    }

    private static Specification<Finding> byIncidentLinked(Boolean incidentLinked) {
        if (incidentLinked == null) {
            return null;
        }
        return (root, query, cb) -> incidentLinked
                ? cb.and(cb.isNotNull(root.get("incidentId")), cb.notEqual(cb.trim(root.get("incidentId")), ""))
                : cb.or(cb.isNull(root.get("incidentId")), cb.equal(cb.trim(root.get("incidentId")), ""));
    }

    private static Specification<Finding> byUnassignedOnly(Boolean unassignedOnly) {
        if (unassignedOnly == null) {
            return null;
        }
        return (root, query, cb) -> unassignedOnly
                ? cb.or(cb.isNull(root.get("assignedTo")), cb.equal(cb.trim(root.get("assignedTo")), ""))
                : cb.and(cb.isNotNull(root.get("assignedTo")), cb.notEqual(cb.trim(root.get("assignedTo")), ""));
    }

    private static Specification<Finding> byDueDateBand(String dueDateBand) {
        if (!hasText(dueDateBand)) {
            return null;
        }
        String normalized = dueDateBand.trim().toLowerCase(Locale.ROOT);
        Instant now = Instant.now();
        Instant soon = now.plus(7, ChronoUnit.DAYS);
        return (root, query, cb) -> {
            jakarta.persistence.criteria.Path<Instant> dueAt = root.get("dueAt");
            jakarta.persistence.criteria.Predicate open = cb.equal(root.get("status"), FindingStatus.OPEN);
            return switch (normalized) {
                case "overdue" -> cb.and(open, cb.isNotNull(dueAt), cb.lessThan(dueAt, now));
                case "due-soon" -> cb.and(open, cb.isNotNull(dueAt), cb.greaterThanOrEqualTo(dueAt, now), cb.lessThan(dueAt, soon));
                case "on-track" -> cb.and(open, cb.isNotNull(dueAt), cb.greaterThanOrEqualTo(dueAt, soon));
                case "no-sla" -> cb.and(open, cb.isNull(dueAt));
                default -> null;
            };
        };
    }

    private static Specification<Finding> byAssetName(String assetName) {
        if (!hasText(assetName)) {
            return null;
        }
        String expected = "%" + assetName.trim().toLowerCase(Locale.ROOT) + "%";
        return (root, query, cb) -> cb.like(cb.lower(root.join("asset").get("name")), expected);
    }

    /**
     * Findings link to an asset either directly ({@code f.asset}) or indirectly via
     * {@code f.component.asset}; a finding matches if either resolved asset has the type.
     */
    private static Specification<Finding> byAssetType(List<String> assetTypes) {
        Set<String> normalized = normalizeUpperFilterValues(assetTypes);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<AssetType> types = new HashSet<>();
        for (String value : normalized) {
            try {
                types.add(AssetType.valueOf(value));
            } catch (IllegalArgumentException ignored) {
            }
        }
        if (types.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            var directAsset = root.join("asset", JoinType.LEFT);
            var componentAsset = root.join("component", JoinType.LEFT).join("asset", JoinType.LEFT);
            return cb.or(directAsset.get("type").in(types), componentAsset.get("type").in(types));
        };
    }

    private static Specification<Finding> bySupportGroup(String supportGroup) {
        if (!hasText(supportGroup)) {
            return null;
        }
        String expected = "%" + supportGroup.trim().toLowerCase(Locale.ROOT) + "%";
        return (root, query, cb) -> cb.like(cb.lower(root.join("asset").get("supportGroup")), expected);
    }

    private static Specification<Finding> byPatchAvailable(Boolean patchAvailable) {
        if (patchAvailable == null) {
            return null;
        }
        return (root, query, cb) -> {
            var subquery = query.subquery(Long.class);
            var fixRoot = subquery.from(FixRecord.class);
            subquery.select(cb.literal(1L));
            subquery.where(
                    cb.equal(cb.upper(fixRoot.get("cveId")), cb.upper(root.join("vulnerability").get("externalId"))),
                    cb.notEqual(cb.upper(fixRoot.get("fixType")), FixRecord.FixType.NO_FIX.name())
            );
            return patchAvailable ? cb.exists(subquery) : cb.not(cb.exists(subquery));
        };
    }

    private static Specification<Finding> bySuppressedUntilBand(String suppressedUntilBand) {
        if (!hasText(suppressedUntilBand)) {
            return null;
        }
        String normalized = suppressedUntilBand.trim().toLowerCase(Locale.ROOT);
        Instant now = Instant.now();
        Instant soon = now.plus(7, ChronoUnit.DAYS);
        return (root, query, cb) -> {
            jakarta.persistence.criteria.Path<Instant> suppressedUntil = root.get("suppressedUntil");
            jakarta.persistence.criteria.Predicate suppressed = cb.equal(root.get("status"), FindingStatus.SUPPRESSED);
            return switch (normalized) {
                case "expiring-soon" -> cb.and(
                        suppressed,
                        cb.isNotNull(suppressedUntil),
                        cb.greaterThanOrEqualTo(suppressedUntil, now),
                        cb.lessThan(suppressedUntil, soon)
                );
                case "expired" -> cb.and(
                        suppressed,
                        cb.isNotNull(suppressedUntil),
                        cb.lessThan(suppressedUntil, now)
                );
                default -> null;
            };
        };
    }
}
