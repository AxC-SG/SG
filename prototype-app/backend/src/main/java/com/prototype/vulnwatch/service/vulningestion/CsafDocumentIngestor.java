package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.service.IdentityGraphService;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.VulnerabilityIntelligenceService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import com.prototype.vulnwatch.util.CpeUtil;
import com.prototype.vulnwatch.util.IdentityUtil;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class CsafDocumentIngestor {

    private final ObservationIngestionService observationIngestionService;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final IdentityGraphService identityGraphService;
    private final VulnerabilityIngestionCommonSupport support;

    public CsafDocumentIngestor(
            ObservationIngestionService observationIngestionService,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            IdentityGraphService identityGraphService,
            VulnerabilityIngestionCommonSupport support
    ) {
        this.observationIngestionService = observationIngestionService;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.identityGraphService = identityGraphService;
        this.support = support;
    }

    public CsafIngestionCounters ingestDocument(
            CsafProvider provider,
            JsonNode advisoryNode,
            String advisoryUrl,
            boolean vexProfile,
            CsafRunDiagnostics diagnostics,
            VulnerabilitySourceFilterConfigService.RedhatFilters redhatFilters
    ) {
        Map<String, CsafProductRef> productRefs = collectCsafProducts(advisoryNode.path("product_tree"));
        JsonNode vulnerabilitiesNode = advisoryNode.path("vulnerabilities");
        if (!vulnerabilitiesNode.isArray() || vulnerabilitiesNode.isEmpty()) {
            return new CsafIngestionCounters(0, 0, Set.of());
        }

        int inserted = 0;
        int updated = 0;
        Set<UUID> vulnerabilityIds = new LinkedHashSet<>();
        String kbVersion = csafKbVersion(advisoryNode);
        for (JsonNode vulnerabilityNode : vulnerabilitiesNode) {
            Set<String> cveIds = extractCveIds(vulnerabilityNode);
            if (cveIds.isEmpty()) {
                continue;
            }
            Map<String, Set<String>> productStatusGroups = extractProductStatusGroups(vulnerabilityNode.path("product_status"));
            boolean vexContext = vexProfile;
            String sourceTag = (vexContext ? "vex-" : "csaf-") + provider.providerKey();
            Double cvss = extractCvssScore(vulnerabilityNode);
            Double cvssV3 = extractCvssV3Score(vulnerabilityNode);
            String severity = support.severityFromCvss(cvss);
            if (provider == CsafProvider.REDHAT && !matchesRedhatFilters(severity, cvss, cvssV3, redhatFilters)) {
                continue;
            }
            String description = extractDescription(vulnerabilityNode, advisoryNode);
            String referencesJson = extractReferencesJson(vulnerabilityNode, advisoryNode, advisoryUrl);
            String rawPayload = vulnerabilityNode.toString();
            String actionStatement = extractActionStatement(vulnerabilityNode);
            String advisoryDocumentId = csafDocumentTrackingId(advisoryNode);
            String advisoryTitle = csafDocumentTitle(advisoryNode);
            String canonicalSeverity = support.hasText(severity) ? severity : "UNKNOWN";
            String canonicalReferences = support.hasText(referencesJson) ? referencesJson : "[]";
            Instant canonicalPublishedAt = support.parseInstantOrNull(kbVersion);
            if (canonicalPublishedAt == null) {
                canonicalPublishedAt = Instant.now();
            }

            for (String cveId : cveIds) {
                String sourceRecordId = advisoryUrl + "#" + cveId;
                diagnostics.observeCanonicalRecord(
                        cveId,
                        sourceTag,
                        sourceRecordId,
                        canonicalSeverity,
                        cvss,
                        canonicalReferences,
                        canonicalPublishedAt,
                        canonicalPublishedAt
                );
                VulnerabilityIntelligenceService.ObservationUpsertResult upsertResult = observationIngestionService.upsertObservation(
                        new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                                cveId,
                                sourceTag,
                                sourceRecordId,
                                advisoryUrl,
                                cveId,
                                description,
                                canonicalSeverity,
                                cvss,
                                extractCvssVector(vulnerabilityNode),
                                null,
                                null,
                                vexContext ? "UNDER_INVESTIGATION" : null,
                                null,
                                canonicalReferences,
                                null,
                                canonicalPublishedAt,
                                canonicalPublishedAt,
                                rawPayload
                        )
                );
                Vulnerability vulnerability = upsertResult.vulnerability();
                if (vulnerability != null && vulnerability.getId() != null) {
                    vulnerabilityIds.add(vulnerability.getId());
                }
                if (upsertResult.vulnerabilityCreated()) {
                    inserted++;
                } else {
                    updated++;
                }

                support.replaceTargetsForRecord(vulnerability,List.of(sourceTag),sourceRecordId);
                if (!productStatusGroups.isEmpty()) {
                    Map<String, VulnerabilityTarget> existingByKey = support.loadCsafTargetIndex(vulnerability, sourceTag);
                    for (Map.Entry<String, Set<String>> statusEntry : productStatusGroups.entrySet()) {
                        addCsafTargets(
                                vulnerability,
                                statusEntry.getValue(),
                                productRefs,
                                existingByKey,
                                sourceTag,
                                kbVersion,
                                statusEntry.getKey(),
                                advisoryUrl,
                                actionStatement,
                                advisoryDocumentId,
                                advisoryTitle,
                                provider
                        );
                    }
                } else {
                    Set<String> fallbackProducts = extractAffectedProductIds(vulnerabilityNode.path("product_status"));
                    if (!fallbackProducts.isEmpty()) {
                        Map<String, VulnerabilityTarget> existingByKey = support.loadCsafTargetIndex(vulnerability, sourceTag);
                        addCsafTargets(
                                vulnerability,
                                fallbackProducts,
                                productRefs,
                                existingByKey,
                                sourceTag,
                                kbVersion,
                                null,
                                advisoryUrl,
                                actionStatement,
                                advisoryDocumentId,
                                advisoryTitle,
                                provider
                        );
                    }
                }
            }
        }
        return new CsafIngestionCounters(inserted, updated, vulnerabilityIds);
    }

    private void addCsafTargets(
            Vulnerability vulnerability,
            Set<String> affectedProductIds,
            Map<String, CsafProductRef> productRefs,
            Map<String, VulnerabilityTarget> existingByKey,
            String sourceTag,
            String kbVersion,
            String vexStatus,
            String advisoryUrl,
            String actionStatement,
            String advisoryDocumentId,
            String advisoryTitle,
            CsafProvider provider
    ) {
        Set<String> dedupe = new HashSet<>();
        String qualifiersJson = buildCsafQualifiersJson(
                vexStatus,
                advisoryUrl,
                actionStatement,
                advisoryDocumentId,
                advisoryTitle,
                provider == null ? null : provider.providerKey(),
                vexTrustTier(provider),
                kbVersion
        );
        for (String productId : affectedProductIds) {
            CsafProductRef productRef = productRefs.get(productId);
            if (productRef == null) {
                continue;
            }

            String normalizedPurl = IdentityUtil.normalizePurl(productRef.purl());
            ParsedPurl parsedPurl = support.parsePurl(productRef.purl());
            String digest = support.extractDigestFromPurl(productRef.purl());
            String cpe = productRef.cpe();
            CpeUtil.ParsedCpe parsedCpe = CpeUtil.parse(cpe);

            String ecosystem = support.firstNonBlank(parsedPurl.type(), "generic");
            String namespace = parsedPurl.namespace();
            String packageName = support.firstNonBlank(parsedPurl.name(), parsedCpe.product());
            String versionExact = support.nullIfBlank(support.firstNonBlank(parsedPurl.version(), parsedCpe.version()));

            if (!support.hasText(packageName) && !support.hasText(normalizedPurl) && !support.hasText(cpe)) {
                continue;
            }

            SoftwareIdentity identity = identityGraphService.resolveFromTarget(
                    ecosystem,
                    packageName,
                    namespace,
                    productRef.purl(),
                    cpe,
                    null,
                    sourceTag
            );

            if (support.hasText(normalizedPurl) && support.hasText(packageName)) {
                support.saveTargetWithDedupe(
                        dedupe,
                        existingByKey,
                        support.createTarget(
                                vulnerability,
                                identity,
                                VulnerabilityTargetType.PURL,
                                normalizedPurl,
                                ecosystem,
                                namespace,
                                packageName,
                                null,
                                productRef.purl(),
                                versionExact,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                VersionScheme.UNKNOWN,
                                null,
                                null,
                                qualifiersJson,
                                sourceTag,
                                kbVersion
                        )
                );
            }

            if (support.hasText(packageName)) {
                support.saveTargetWithDedupe(
                        dedupe,
                        existingByKey,
                        support.createTarget(
                                vulnerability,
                                identity,
                                VulnerabilityTargetType.COORD,
                                IdentityUtil.coordKey(ecosystem, namespace, packageName),
                                ecosystem,
                                namespace,
                                packageName,
                                null,
                                productRef.name(),
                                versionExact,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                VersionScheme.UNKNOWN,
                                null,
                                null,
                                qualifiersJson,
                                sourceTag,
                                kbVersion
                        )
                );
            }

            if (support.hasText(cpe) && support.hasText(packageName)) {
                support.saveTargetWithDedupe(
                        dedupe,
                        existingByKey,
                        support.createTarget(
                                vulnerability,
                                identity,
                                VulnerabilityTargetType.CPE,
                                IdentityUtil.normalize(cpe),
                                ecosystem,
                                namespace,
                                packageName,
                                null,
                                cpe,
                                versionExact,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                VersionScheme.UNKNOWN,
                                cpe,
                                support.cpeWildcardScore(cpe),
                                qualifiersJson,
                                sourceTag,
                                kbVersion
                        )
                );
            }

            if (support.hasText(digest)) {
                support.saveTargetWithDedupe(
                        dedupe,
                        existingByKey,
                        support.createTarget(
                                vulnerability,
                                identity,
                                VulnerabilityTargetType.DIGEST,
                                digest,
                                ecosystem,
                                namespace,
                                packageName,
                                null,
                                digest,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                VersionScheme.UNKNOWN,
                                null,
                                null,
                                qualifiersJson,
                                sourceTag,
                                kbVersion
                        )
                );
            }
        }
    }

    private Map<String, CsafProductRef> collectCsafProducts(JsonNode productTree) {
        Map<String, CsafProductRef> products = new LinkedHashMap<>();
        collectCsafProductsFromNode(productTree, products);
        return products;
    }

    private void collectCsafProductsFromNode(JsonNode node, Map<String, CsafProductRef> products) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return;
        }

        JsonNode fullNames = node.path("full_product_names");
        if (fullNames.isArray()) {
            for (JsonNode entry : fullNames) {
                addCsafProductEntry(entry, products);
            }
        }

        JsonNode product = node.path("product");
        if (product.isObject()) {
            addCsafProductEntry(product, products);
        }

        JsonNode branches = node.path("branches");
        if (branches.isArray()) {
            for (JsonNode branch : branches) {
                addCsafProductEntry(branch, products);
                collectCsafProductsFromNode(branch, products);
            }
        }
    }

    private void addCsafProductEntry(JsonNode entry, Map<String, CsafProductRef> products) {
        if (entry == null || entry.isNull() || entry.isMissingNode()) {
            return;
        }

        String productId = support.firstNonBlank(
                support.textValue(entry.path("product_id")),
                support.textValue(entry.path("product").path("product_id"))
        );
        if (!support.hasText(productId)) {
            return;
        }

        JsonNode helper = entry.path("product_identification_helper");
        if (!helper.isObject()) {
            helper = entry.path("product").path("product_identification_helper");
        }
        String cpe = support.firstNonBlank(
                support.textValue(helper.path("cpe")),
                support.textValue(helper.path("cpe23Uri"))
        );
        String purl = support.firstNonBlank(
                support.textValue(helper.path("purl")),
                support.textValue(helper.path("purls")),
                support.firstArrayText(helper.path("purls"))
        );
        String name = support.firstNonBlank(
                support.textValue(entry.path("name")),
                support.textValue(entry.path("product").path("name")),
                support.textValue(entry.path("product_name"))
        );
        products.put(
                productId,
                new CsafProductRef(
                        productId,
                        name,
                        support.normalizeNullable(cpe),
                        support.normalizeNullable(purl)
                )
        );
    }

    private Set<String> extractCveIds(JsonNode vulnerabilityNode) {
        Set<String> ids = new LinkedHashSet<>();
        addCveId(ids, support.textValue(vulnerabilityNode.path("cve")));
        JsonNode idsNode = vulnerabilityNode.path("ids");
        if (idsNode.isArray()) {
            for (JsonNode value : idsNode) {
                addCveId(ids, support.textValue(value));
            }
        }
        JsonNode aliases = vulnerabilityNode.path("aliases");
        if (aliases.isArray()) {
            for (JsonNode value : aliases) {
                addCveId(ids, support.textValue(value));
            }
        }
        return ids;
    }

    private void addCveId(Set<String> ids, String rawId) {
        if (!support.hasText(rawId)) {
            return;
        }
        String normalized = rawId.trim().toUpperCase(Locale.ROOT);
        if (normalized.startsWith("CVE-")) {
            ids.add(normalized);
        }
    }

    private Set<String> extractAffectedProductIds(JsonNode productStatus) {
        Set<String> ids = new LinkedHashSet<>();
        if (!productStatus.isObject()) {
            return ids;
        }
        List<String> affectedFields = List.of("known_affected", "first_affected", "under_investigation");
        for (String field : affectedFields) {
            JsonNode array = productStatus.path(field);
            if (!array.isArray()) {
                continue;
            }
            for (JsonNode productId : array) {
                String value = support.textValue(productId);
                if (support.hasText(value)) {
                    ids.add(value);
                }
            }
        }
        return ids;
    }

    private Map<String, Set<String>> extractProductStatusGroups(JsonNode productStatus) {
        Map<String, Set<String>> groups = new LinkedHashMap<>();
        if (!productStatus.isObject()) {
            return groups;
        }
        collectProductStatus(productStatus, "known_affected", "KNOWN_AFFECTED", groups);
        collectProductStatus(productStatus, "first_affected", "KNOWN_AFFECTED", groups);
        collectProductStatus(productStatus, "known_not_affected", "NOT_AFFECTED", groups);
        collectProductStatus(productStatus, "fixed", "FIXED", groups);
        collectProductStatus(productStatus, "first_fixed", "FIXED", groups);
        collectProductStatus(productStatus, "under_investigation", "UNDER_INVESTIGATION", groups);
        return groups;
    }

    private void collectProductStatus(
            JsonNode productStatus,
            String sourceField,
            String normalizedStatus,
            Map<String, Set<String>> sink
    ) {
        JsonNode values = productStatus.path(sourceField);
        if (!values.isArray()) {
            return;
        }
        Set<String> ids = sink.computeIfAbsent(normalizedStatus, ignored -> new LinkedHashSet<>());
        for (JsonNode productId : values) {
            String value = support.textValue(productId);
            if (support.hasText(value)) {
                ids.add(value);
            }
        }
    }

    private String extractActionStatement(JsonNode vulnerabilityNode) {
        JsonNode remediations = vulnerabilityNode.path("remediations");
        if (!remediations.isArray()) {
            return null;
        }
        for (JsonNode remediation : remediations) {
            String details = support.textValue(remediation.path("details"));
            if (support.hasText(details)) {
                return details;
            }
        }
        return null;
    }

    private String buildCsafQualifiersJson(
            String vexStatus,
            String advisoryUrl,
            String actionStatement,
            String advisoryDocumentId,
            String advisoryTitle,
            String vexProvider,
            String vexTrustTier,
            String vexPublishedAt
    ) {
        if (!support.hasText(vexStatus)
                && !support.hasText(advisoryUrl)
                && !support.hasText(actionStatement)
                && !support.hasText(advisoryDocumentId)
                && !support.hasText(advisoryTitle)
                && !support.hasText(vexProvider)
                && !support.hasText(vexTrustTier)
                && !support.hasText(vexPublishedAt)) {
            return null;
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        if (support.hasText(vexStatus)) {
            payload.put("vexStatus", vexStatus);
        }
        if (support.hasText(advisoryUrl)) {
            payload.put("advisoryUrl", advisoryUrl);
        }
        if (support.hasText(actionStatement)) {
            payload.put("actionStatement", actionStatement);
        }
        if (support.hasText(advisoryDocumentId)) {
            payload.put("advisoryDocumentId", advisoryDocumentId);
        }
        if (support.hasText(advisoryTitle)) {
            payload.put("advisoryTitle", advisoryTitle);
        }
        if (support.hasText(vexProvider)) {
            payload.put("vexProvider", vexProvider);
        }
        if (support.hasText(vexTrustTier)) {
            payload.put("vexTrustTier", vexTrustTier);
        }
        if (support.hasText(vexPublishedAt)) {
            payload.put("vexPublishedAt", vexPublishedAt);
        }
        payload.put("vexLastSeenAt", Instant.now().toString());
        return support.toJson(payload);
    }

    private String csafDocumentTrackingId(JsonNode advisoryNode) {
        return support.textValue(advisoryNode.path("document").path("tracking").path("id"));
    }

    private String csafDocumentTitle(JsonNode advisoryNode) {
        return support.textValue(advisoryNode.path("document").path("title"));
    }

    private String vexTrustTier(CsafProvider provider) {
        if (provider == null) {
            return "MEDIUM";
        }
        return switch (provider) {
            case MICROSOFT, REDHAT -> "HIGH";
        };
    }

    private Double extractCvssScore(JsonNode vulnerabilityNode) {
        JsonNode scores = vulnerabilityNode.path("scores");
        if (!scores.isArray()) {
            return null;
        }
        for (JsonNode score : scores) {
            Double v3 = support.numericValue(score.path("cvss_v3").path("baseScore"));
            if (v3 != null) {
                return v3;
            }
            Double v2 = support.numericValue(score.path("cvss_v2").path("baseScore"));
            if (v2 != null) {
                return v2;
            }
        }
        return null;
    }

    private Double extractCvssV3Score(JsonNode vulnerabilityNode) {
        JsonNode scores = vulnerabilityNode.path("scores");
        if (!scores.isArray()) {
            return null;
        }
        for (JsonNode score : scores) {
            Double v3 = support.numericValue(score.path("cvss_v3").path("baseScore"));
            if (v3 != null) {
                return v3;
            }
        }
        return null;
    }

    private String extractCvssVector(JsonNode vulnerabilityNode) {
        JsonNode scores = vulnerabilityNode.path("scores");
        if (!scores.isArray()) {
            return null;
        }
        for (JsonNode score : scores) {
            String v3 = support.firstNonBlank(
                    support.textValue(score.path("cvss_v3").path("vectorString")),
                    support.textValue(score.path("cvss_v3").path("vector_string"))
            );
            if (support.hasText(v3)) {
                return v3;
            }
            String v2 = support.firstNonBlank(
                    support.textValue(score.path("cvss_v2").path("vectorString")),
                    support.textValue(score.path("cvss_v2").path("vector_string"))
            );
            if (support.hasText(v2)) {
                return v2;
            }
        }
        return null;
    }

    private String extractDescription(JsonNode vulnerabilityNode, JsonNode advisoryNode) {
        String title = support.textValue(vulnerabilityNode.path("title"));
        if (support.hasText(title)) {
            return title;
        }
        JsonNode notes = vulnerabilityNode.path("notes");
        if (notes.isArray()) {
            for (JsonNode note : notes) {
                String text = support.textValue(note.path("text"));
                if (support.hasText(text)) {
                    return text;
                }
            }
        }
        return support.textValue(advisoryNode.path("document").path("title"));
    }

    private String extractReferencesJson(JsonNode vulnerabilityNode, JsonNode advisoryNode, String advisoryUrl) {
        List<String> refs = new ArrayList<>();
        refs.add(advisoryUrl);
        JsonNode vulnRefs = vulnerabilityNode.path("references");
        if (vulnRefs.isArray()) {
            for (JsonNode ref : vulnRefs) {
                String url = support.textValue(ref.path("url"));
                if (support.hasText(url)) {
                    refs.add(url);
                }
            }
        }
        JsonNode docRefs = advisoryNode.path("document").path("references");
        if (docRefs.isArray()) {
            for (JsonNode ref : docRefs) {
                String url = support.textValue(ref.path("url"));
                if (support.hasText(url)) {
                    refs.add(url);
                }
            }
        }
        LinkedHashSet<String> dedupe = new LinkedHashSet<>(refs);
        return support.toJson(dedupe);
    }

    private String csafKbVersion(JsonNode advisoryNode) {
        String currentReleaseDate = support.textValue(advisoryNode.path("document").path("tracking").path("current_release_date"));
        if (support.hasText(currentReleaseDate)) {
            return currentReleaseDate;
        }
        String initialReleaseDate = support.textValue(advisoryNode.path("document").path("tracking").path("initial_release_date"));
        if (support.hasText(initialReleaseDate)) {
            return initialReleaseDate;
        }
        return Instant.now().toString();
    }

    private boolean matchesRedhatFilters(
            String severity,
            Double cvssScore,
            Double cvssV3Score,
            VulnerabilitySourceFilterConfigService.RedhatFilters filters
    ) {
        if (filters == null || !filters.configured()) {
            return true;
        }
        if (support.hasText(filters.severity()) && !filters.severity().equalsIgnoreCase(severity)) {
            return false;
        }
        if (filters.cvssScore() != null && (cvssScore == null || cvssScore < filters.cvssScore())) {
            return false;
        }
        if (filters.cvss3Score() != null && (cvssV3Score == null || cvssV3Score < filters.cvss3Score())) {
            return false;
        }
        return true;
    }
}
