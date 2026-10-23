package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.AffectedAiResourceSummary;
import com.prototype.vulnwatch.dto.FindingsFilter;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.dto.FindingPageResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

@Service
public class FindingQueryService {

    private final FindingRepository findingRepository;
    private final ObjectMapper objectMapper;
    private final FindingsScoreService findingsScoreService;
    private final RiskPolicyService riskPolicyService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingListProjectionService findingListProjectionService;
    private final AiBomAffectedResourceSummaryService affectedResourceSummaryService;

    public FindingQueryService(
            FindingRepository findingRepository,
            ObjectMapper objectMapper,
            FindingsScoreService findingsScoreService,
            RiskPolicyService riskPolicyService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingListProjectionService findingListProjectionService,
            AiBomAffectedResourceSummaryService affectedResourceSummaryService
    ) {
        this.findingRepository = findingRepository;
        this.objectMapper = objectMapper;
        this.findingsScoreService = findingsScoreService;
        this.riskPolicyService = riskPolicyService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingListProjectionService = findingListProjectionService;
        this.affectedResourceSummaryService = affectedResourceSummaryService;
    }

    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.jdbc.core.JdbcTemplate intelligenceJdbc;

    @org.springframework.transaction.annotation.Transactional(readOnly=true)
    public java.util.Optional<FindingResponse> history(Tenant tenant,UUID id) {
        return tenantSchemaExecutionService.run(tenant,() -> {
            intelligenceJdbc.queryForObject("select set_config('app.include_ineligible_intelligence','true',true)",String.class);
            return findingRepository.findById(id).filter(finding -> tenant.getId().equals(finding.getTenant().getId())).map(this::toResponse);
        });
    }

    public FindingPageResponse listByTenantPage(
            Tenant tenant,
            int page,
            int size,
            FindingsFilter filter
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(200, size));
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "updatedAt"));

        Specification<Finding> specification = FindingFilterSpecifications.byFilter(tenant, filter);
        Page<Finding> findings = tenantSchemaExecutionService.run(tenant, () -> findingRepository.findAll(specification, pageable));
        // Affected-resource summaries are loaded once for this already-paginated page, not
        // per finding and never via a join into the specification above.
        Map<UUID, List<AffectedAiResourceSummary>> affectedAiResourcesByFindingId =
                affectedResourceSummaryService.summarize(findings.getContent().stream().map(Finding::getId).toList());
        return new FindingPageResponse(
                findings.getContent().stream()
                        .map(finding -> toResponse(finding, affectedAiResourcesByFindingId.get(finding.getId())))
                        .toList(),
                findings.getNumber(),
                findings.getSize(),
                findings.getTotalElements(),
                findings.getTotalPages(),
                null
        );
    }

    public FindingPageResponse listByTenantCursor(
            Tenant tenant,
            String cursor,
            int limit,
            FindingsFilter filter
    ) {
        int safeLimit = Math.max(1, Math.min(200, limit));
        FindingListProjectionService.ProjectionPage projectionPage =
                findingListProjectionService.queryPage(tenant, filter, cursor, safeLimit);
        Map<UUID, Finding> findingsById = tenantSchemaExecutionService.run(tenant, () -> findingRepository.findAllById(projectionPage.findingIds()))
                .stream()
                .collect(Collectors.toMap(Finding::getId, finding -> finding, (left, right) -> left, LinkedHashMap::new));
        // Loaded once for this already-paginated page's ids, same as the offset-page path.
        Map<UUID, List<AffectedAiResourceSummary>> affectedAiResourcesByFindingId =
                affectedResourceSummaryService.summarize(projectionPage.findingIds());
        List<FindingResponse> items = projectionPage.findingIds().stream()
                .map(findingsById::get)
                .filter(Objects::nonNull)
                .map(finding -> toResponse(finding, affectedAiResourcesByFindingId.get(finding.getId())))
                .toList();
        int totalPages = projectionPage.totalItems() == 0
                ? 0
                : (int) Math.ceil((double) projectionPage.totalItems() / safeLimit);
        return new FindingPageResponse(
                items,
                0,
                safeLimit,
                projectionPage.totalItems(),
                totalPages,
                projectionPage.nextCursor()
        );
    }

    public List<Finding> listEntitiesByTenantFilter(Tenant tenant, FindingsFilter filter) {
        Specification<Finding> specification = FindingFilterSpecifications.byFilter(tenant, filter);
        return tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.findAll(specification, Sort.by(Sort.Direction.DESC, "updatedAt"))
        );
    }

    public List<Finding> listEntitiesByTenantAndIds(Tenant tenant, List<UUID> findingIds) {
        if (findingIds == null || findingIds.isEmpty()) {
            return List.of();
        }
        return tenantSchemaExecutionService.run(tenant, () -> findingRepository.findAllById(findingIds)).stream()
                .filter(finding -> !"AI_RUNTIME".equals(finding.getFindingKind()))
                .toList();
    }

    public List<FindingResponse> listByTenant(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> findingRepository.findAllByOrderByUpdatedAtDesc()).stream()
                .filter(finding -> !"AI_RUNTIME".equals(finding.getFindingKind()))
                .map(this::toResponse)
                .toList();
    }

    public FindingFilterValuesResponse listAvailableFilters(Tenant tenant) {
        LinkedHashSet<String> severities = new LinkedHashSet<>();
        tenantSchemaExecutionService.run(tenant, () -> findingRepository.findDistinctSeveritiesByTenant(tenant)).stream()
                .filter(FindingFilterSpecifications::hasText)
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .forEach(severities::add);
        severities.addAll(List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"));

        LinkedHashSet<String> statuses = new LinkedHashSet<>();
        tenantSchemaExecutionService.run(tenant, () -> findingRepository.findDistinctStatusesByTenant(tenant)).stream()
                .filter(Objects::nonNull)
                .map(Enum::name)
                .forEach(statuses::add);
        for (FindingStatus status : FindingStatus.values()) {
            statuses.add(status.name());
        }

        LinkedHashSet<String> decisionStates = new LinkedHashSet<>();
        tenantSchemaExecutionService.run(tenant, () -> findingRepository.findDistinctDecisionStatesByTenant(tenant)).stream()
                .filter(Objects::nonNull)
                .map(Enum::name)
                .forEach(decisionStates::add);
        for (FindingDecisionState decisionState : FindingDecisionState.values()) {
            decisionStates.add(decisionState.name());
        }

        LinkedHashSet<String> matchMethods = new LinkedHashSet<>();
        tenantSchemaExecutionService.run(tenant, () -> findingRepository.findDistinctMatchMethodsByTenant(tenant)).stream()
                .filter(FindingFilterSpecifications::hasText)
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .forEach(matchMethods::add);

        LinkedHashSet<String> vexStatuses = new LinkedHashSet<>();
        tenantSchemaExecutionService.run(tenant, () -> findingRepository.findDistinctVexStatusesByTenant(tenant)).stream()
                .filter(FindingFilterSpecifications::hasText)
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .forEach(vexStatuses::add);
        vexStatuses.addAll(List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "NO_PATCH", "UNDER_INVESTIGATION", "UNKNOWN"));

        LinkedHashSet<String> vexFreshness = new LinkedHashSet<>();
        tenantSchemaExecutionService.run(tenant, () -> findingRepository.findDistinctVexFreshnessByTenant(tenant)).stream()
                .filter(FindingFilterSpecifications::hasText)
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .forEach(vexFreshness::add);
        vexFreshness.addAll(List.of("FRESH", "STALE", "UNKNOWN"));

        LinkedHashSet<String> vexProviders = new LinkedHashSet<>();
        tenantSchemaExecutionService.run(tenant, () -> findingRepository.findDistinctVexProvidersByTenant(tenant)).stream()
                .filter(FindingFilterSpecifications::hasText)
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .forEach(vexProviders::add);
        vexProviders.add("unknown");

        return new FindingFilterValuesResponse(
                FindingFilterSpecifications.sortByPreferredOrder(severities, List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")),
                FindingFilterSpecifications.sortByPreferredOrder(statuses, List.of("OPEN", "RESOLVED", "SUPPRESSED", "AUTO_CLOSED")),
                FindingFilterSpecifications.sortByPreferredOrder(
                        decisionStates,
                        List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION", "NEEDS_REVIEW")
                ),
                matchMethods.stream().sorted().toList(),
                FindingFilterSpecifications.sortByPreferredOrder(vexStatuses, List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "NO_PATCH", "UNDER_INVESTIGATION", "UNKNOWN")),
                FindingFilterSpecifications.sortByPreferredOrder(vexFreshness, List.of("FRESH", "STALE", "UNKNOWN")),
                vexProviders.stream().sorted().toList()
        );
    }

    public List<FindingResponse> listLatestByTenant(Tenant tenant, int limit) {
        Pageable pageable = PageRequest.of(0, Math.max(1, Math.min(200, limit)), Sort.by(Sort.Direction.DESC, "updatedAt"));
        return tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.findAllByOrderByUpdatedAtDesc(pageable)
        ).getContent().stream()
                .map(this::toResponse)
                .toList();
    }

    public long countOpen(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> findingRepository.countByStatus(FindingStatus.OPEN));
    }

    public long countCritical(Tenant tenant) {
        return tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.countByStatusAndRiskScoreGreaterThanEqual(FindingStatus.OPEN, 9.0)
        );
    }

    public FindingResponse toResponse(Finding finding) {
        return toResponse(finding, null);
    }

    public FindingResponse toResponse(Finding finding, List<AffectedAiResourceSummary> affectedAiResources) {
        Vulnerability vulnerability = finding.getVulnerability();
        InventoryComponent component = finding.getComponent();
        Asset asset = finding.getAsset() != null ? finding.getAsset() : component != null ? component.getAsset() : null;
        Map<String, Object> evidencePayload = readEvidencePayload(finding.getEvidence());

        String scoreConfig = riskPolicyService.getFindingsScoreConfig(finding.getTenant());
        Double findingsScore = safeFindingsScore(scoreConfig, finding);

        return new FindingResponse(
                finding.getId(),
                finding.getDisplayId(),
                component != null ? component.getId() : null,
                asset != null ? asset.getName() : null,
                asset != null ? asset.getIdentifier() : null,
                asset != null && asset.getType() != null ? asset.getType().name() : null,
                component != null ? component.getPackageName() : null,
                component != null ? component.getVersion() : null,
                vulnerability != null ? vulnerability.getExternalId() : null,
                vulnerability != null && vulnerability.getSource() != null ? vulnerability.getSource().name() : null,
                finding.getCreationSource(),
                finding.getSeverityOverride() != null
                        ? finding.getSeverityOverride()
                        : finding.getIntelligenceSeverity() != null ? finding.getIntelligenceSeverity() : vulnerability != null ? vulnerability.getSeverity() : null,
                finding.getIntelligenceInKev() != null ? finding.getIntelligenceInKev() : vulnerability != null && vulnerability.isInKev(),
                finding.getIntelligenceRevision() > 0 ? finding.getIntelligenceEpss() : vulnerability != null ? vulnerability.getEpssScore() : null,
                finding.getRiskScore(),
                finding.getConfidenceScore(),
                finding.getMatchedBy(),
                finding.getAssignedTo(),
                finding.getDueAt(),
                finding.getSuppressionReason(),
                finding.getSuppressedUntil(),
                finding.getEvidence(),
                finding.getPrecedenceTrace(),
                finding.getVexStatus(),
                finding.getVexProvider(),
                finding.getVexFreshness(),
                finding.getMatchedVexAssertionId(),
                traceString(evidencePayload, "impactReason"),
                finding.getFirstObservedAt(),
                finding.getLastObservedAt(),
                finding.getDecisionState(),
                finding.getStatus(),
                finding.getUpdatedAt(),
                component != null ? component.getEolSlug() : null,
                component != null ? component.getEolCycle() : null,
                component != null ? component.getEolDate() : null,
                component != null ? component.getIsEol() : null,
                component != null && component.getEolDate() != null
                        ? (int) ChronoUnit.DAYS.between(LocalDate.now(), component.getEolDate())
                        : null,
                finding.getIncidentId(),
                finding.getIncidentStatus(),
                findingsScore,
                finding.getSuppressedByRuleId(),
                finding.getSuppressedByRuleName(),
                finding.getOwnerGroup(),
                finding.getConsecutiveMisses(),
                finding.getAutoCloseEligibleAt(),
                finding.getClosedAt(),
                finding.getClosedBy(),
                finding.getClosedReason(),
                finding.getClosedRuleId(),
                asset == null ? Map.of("displayName", "Unassigned") : Map.of(
                        "displayName", hasText(asset.getOwnerTeam()) ? asset.getOwnerTeam().trim()
                                : hasText(asset.getOwnerEmail()) ? asset.getOwnerEmail().trim() : "Unassigned",
                        "supportGroup", asset.getSupportGroup() == null ? "" : asset.getSupportGroup()),
                affectedAiResources == null ? List.of() : affectedAiResources,
                finding.getIntelligenceEligibility(),finding.getIntelligenceReleaseId(),finding.getIntelligenceRevision(),finding.getIntelligenceMergedIntoId());
    }

    private Double safeFindingsScore(String scoreConfig, Finding finding) {
        if (finding.getIntelligenceRevision() > 0) return finding.getRiskScore();
        try {
            return findingsScoreService.compute(scoreConfig, finding);
        } catch (RuntimeException ignored) {
            return finding.getRiskScore();
        }
    }

    private Map<String, Object> readEvidencePayload(String evidence) {
        if (!hasText(evidence)) {
            return new LinkedHashMap<>();
        }
        try {
            JsonNode node = objectMapper.readTree(evidence);
            return objectMapper.convertValue(node, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ignored) {
            return new LinkedHashMap<>();
        }
    }

    private String traceString(Map<String, Object> trace, String key) {
        if (trace == null || trace.isEmpty() || key == null || key.isBlank()) {
            return null;
        }
        Object value = trace.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
