package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecordResponse;
import com.prototype.vulnwatch.dto.PlatformVulnIntelDetailResponse;
import com.prototype.vulnwatch.dto.PlatformVulnRepoPageResponse;
import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelSummarySourceRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PlatformVulnRepoService {

    private static final String EXTERNAL_ID_PREFIX = "CVE-";
    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");
    private static final List<UUID> UNSCOPED_VULNERABILITY_IDS = List.of(new UUID(0L, 0L));

    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository;
    private final VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository;
    private final VulnerabilityIntelDescriptionService vulnerabilityIntelDescriptionService;
    private final FindingRepository findingRepository;
    private final NamedParameterJdbcTemplate jdbcTemplate;

    public PlatformVulnRepoService(
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository,
            VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository,
            VulnerabilityIntelDescriptionService vulnerabilityIntelDescriptionService,
            FindingRepository findingRepository,
            NamedParameterJdbcTemplate jdbcTemplate
    ) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.vulnerabilityIntelSummarySourceRepository = vulnerabilityIntelSummarySourceRepository;
        this.vulnerabilityIntelObservationRepository = vulnerabilityIntelObservationRepository;
        this.vulnerabilityIntelDescriptionService = vulnerabilityIntelDescriptionService;
        this.findingRepository = findingRepository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional(readOnly = true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public PlatformVulnRepoPageResponse listVulnerabilities(
            int page,
            int size,
            String query,
            Boolean inKev,
            String severity,
            String source
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.min(200, Math.max(1, size));
        String normalizedQueryUpper = hasText(query) ? query.trim().toUpperCase(Locale.ROOT) : null;
        String normalizedSeverity = hasText(severity) ? severity.trim().toUpperCase(Locale.ROOT) : null;
        String normalizedSource = hasText(source) ? source.trim().toLowerCase(Locale.ROOT) : null;
        var pageable = PageRequest.of(safePage, safeSize);
        ScopedVulnerabilityIds scopedVulnerabilityIds = resolveSourceScopedVulnerabilityIds(normalizedSource);

        if (scopedVulnerabilityIds.empty()) {
            return new PlatformVulnRepoPageResponse(List.of(), safePage, safeSize, 0L, 0);
        }

        Page<Vulnerability> vulnerabilityPage = normalizedQueryUpper == null
                ? vulnerabilityRepository.searchVulnerabilityIntelWithoutQueryScoped(
                        EXTERNAL_ID_PREFIX,
                        null,
                        scopedVulnerabilityIds.enabled(),
                        scopedVulnerabilityIds.vulnerabilityIds(),
                        normalizedSeverity != null,
                        normalizedSeverity == null ? List.of() : List.of(normalizedSeverity),
                        false,
                        List.of(),
                        inKev,
                        pageable
                )
                : vulnerabilityRepository.searchVulnerabilityIntelScoped(
                        EXTERNAL_ID_PREFIX,
                        normalizedQueryUpper,
                        null,
                        scopedVulnerabilityIds.enabled(),
                        scopedVulnerabilityIds.vulnerabilityIds(),
                        normalizedSeverity != null,
                        normalizedSeverity == null ? List.of() : List.of(normalizedSeverity),
                        false,
                        List.of(),
                        inKev,
                        pageable
                );

        List<Vulnerability> vulnerabilities = vulnerabilityPage.getContent();
        List<UUID> vulnerabilityIds = vulnerabilities.stream()
                .map(Vulnerability::getId)
                .filter(Objects::nonNull)
                .toList();

        Map<UUID, List<String>> sourcesByVulnerability = new HashMap<>();
        if (!vulnerabilityIds.isEmpty()) {
            vulnerabilityIntelSummarySourceRepository.findByVulnerabilityIdIn(vulnerabilityIds)
                    .forEach(row -> sourcesByVulnerability
                            .computeIfAbsent(row.getVulnerabilityId(), ignored -> new ArrayList<>())
                            .add(row.getSourceSystem()));
        }

        Map<UUID, String> euvdIdByVulnerability = new HashMap<>();
        Map<UUID, String> jvndbIdByVulnerability = new HashMap<>();
        if (!vulnerabilityIds.isEmpty()) {
            vulnerabilityIntelObservationRepository
                    .findFirstSourceRecordIdByVulnerabilityIds(vulnerabilityIds, "euvd")
                    .forEach(row -> euvdIdByVulnerability.put(row.getVulnerabilityId(), row.getSourceRecordId()));
            vulnerabilityIntelObservationRepository
                    .findFirstSourceRecordIdByVulnerabilityIds(vulnerabilityIds, "japan-vulndb")
                    .forEach(row -> jvndbIdByVulnerability.put(row.getVulnerabilityId(), row.getSourceRecordId()));
        }

        Map<UUID, Long> openFindingsByVulnerability = new HashMap<>();
        if (!vulnerabilityIds.isEmpty()) {
            findingRepository.countByVulnerabilityIdsAndStatus(vulnerabilityIds, FindingStatus.OPEN)
                    .forEach(row -> openFindingsByVulnerability.put((UUID) row[0], (Long) row[1]));
        }

        List<OrgSpecificCveExposureRecordResponse> items = vulnerabilities.stream()
                .map(vulnerability -> {
                    List<String> sources = normalizeSources(sourcesByVulnerability.get(vulnerability.getId()), vulnerability.isInKev());
                    return new OrgSpecificCveExposureRecordResponse(
                        syntheticRecordId(vulnerability),
                        vulnerability.getId(),
                        vulnerability.getExternalId(),
                        firstNonBlank(vulnerability.getTitle(), vulnerability.getExternalId()),
                        vulnerabilityIntelDescriptionService.toDescriptionSnippet(vulnerability.getDescription()),
                        "UNKNOWN",
                        false,
                        "UNKNOWN",
                        null,
                        null,
                        normalizeSeverity(vulnerability.getSeverity()),
                        vulnerability.getCvssScore(),
                        vulnerability.getEpssScore(),
                        vulnerability.isInKev(),
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        openFindingsByVulnerability.getOrDefault(vulnerability.getId(), 0L),
                        null,
                        0L,
                        0L,
                        false,
                        null,
                        null,
                        false,
                        null,
                        null,
                        null,
                        null,
                        sources,
                        euvdIdByVulnerability.get(vulnerability.getId()),
                        jvndbIdByVulnerability.get(vulnerability.getId()),
                        true,
                        sources,
                        List.of()
                );
                })
                .toList();

        return new PlatformVulnRepoPageResponse(
                items,
                vulnerabilityPage.getNumber(),
                vulnerabilityPage.getSize(),
                vulnerabilityPage.getTotalElements(),
                vulnerabilityPage.getTotalPages()
        );
    }

    @Transactional(readOnly = true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public VulnRepoDashboardResponse getDashboard() {
        Instant now = Instant.now();
        Instant weekAgo = now.minus(7, ChronoUnit.DAYS);
        long trackedCount = vulnerabilityRepository.countByExternalIdStartingWith(EXTERNAL_ID_PREFIX);
        long trackedAddedLastWeek = countByUpdatedSince(weekAgo);
        long criticalCount = countBySeverity("CRITICAL");
        long exploitCount = countExploitAvailable();
        int exploitCoveragePercent = trackedCount <= 0L ? 0 : (int) Math.round((double) exploitCount * 100.0d / (double) trackedCount);

        return new VulnRepoDashboardResponse(
                now,
                new VulnRepoDashboardResponse.SummaryCards(
                        trackedCount,
                        trackedAddedLastWeek,
                        trackedCount,
                        trackedAddedLastWeek,
                        0L,
                        0L,
                        0L,
                        0L,
                        criticalCount,
                        exploitCount,
                        exploitCoveragePercent,
                        0L,
                        0L,
                        0L,
                        0L,
                        countKev(),
                        countKevAddedSince(weekAgo),
                        0L,
                        0L
                ),
                loadSeverityBreakdown(),
                new VulnRepoDashboardResponse.ResolutionStatus(0L, 0L, 0L, 0L),
                List.of(),
                List.of(),
                loadRecentAdvisories(),
                List.of()
        );
    }

    private long countByUpdatedSince(Instant start) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where not v.intelligence_withdrawn and v.external_id like :prefix
                  and coalesce(v.updated_at, v.last_modified_at, v.published_at) >= :start
                """,
                new MapSqlParameterSource()
                        .addValue("prefix", EXTERNAL_ID_PREFIX + "%")
                        .addValue("start", Timestamp.from(start)),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private ScopedVulnerabilityIds resolveSourceScopedVulnerabilityIds(String normalizedSource) {
        if (!hasText(normalizedSource)) {
            return ScopedVulnerabilityIds.unscopedScope();
        }
        List<UUID> vulnerabilityIds =
                vulnerabilityIntelObservationRepository.findDistinctVulnerabilityIdsBySourceSystems(List.of(normalizedSource));
        if (vulnerabilityIds.isEmpty()) {
            return ScopedVulnerabilityIds.emptyScope();
        }
        return ScopedVulnerabilityIds.scopedScope(vulnerabilityIds);
    }

    private long countBySeverity(String severity) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where not v.intelligence_withdrawn and v.external_id like :prefix
                  and upper(coalesce(v.severity, 'UNKNOWN')) = :severity
                """,
                new MapSqlParameterSource()
                        .addValue("prefix", EXTERNAL_ID_PREFIX + "%")
                        .addValue("severity", severity),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countExploitAvailable() {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where not v.intelligence_withdrawn and v.external_id like :prefix
                  and (v.in_kev = true or coalesce(v.epss_score, 0) >= 0.9)
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countKev() {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where not v.intelligence_withdrawn and v.external_id like :prefix
                  and v.in_kev = true
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countKevAddedSince(Instant start) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where not v.intelligence_withdrawn and v.external_id like :prefix
                  and v.in_kev = true
                  and coalesce(v.updated_at, v.last_modified_at, v.published_at) >= :start
                """,
                new MapSqlParameterSource()
                        .addValue("prefix", EXTERNAL_ID_PREFIX + "%")
                        .addValue("start", Timestamp.from(start)),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private List<VulnRepoDashboardResponse.SeverityBreakdownItem> loadSeverityBreakdown() {
        Map<String, Long> counts = new LinkedHashMap<>();
        SEVERITY_ORDER.forEach(severity -> counts.put(severity, 0L));
        counts.put("UNKNOWN", 0L);

        jdbcTemplate.query(
                """
                select upper(coalesce(v.severity, 'UNKNOWN')) as severity, count(*) as total
                from vulnerabilities v
                where not v.intelligence_withdrawn and v.external_id like :prefix
                group by upper(coalesce(v.severity, 'UNKNOWN'))
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                (RowCallbackHandler) rs -> counts.put(rs.getString("severity"), rs.getLong("total"))
        );

        List<VulnRepoDashboardResponse.SeverityBreakdownItem> items = new ArrayList<>();
        counts.forEach((severity, total) -> {
            if (total > 0L || !"UNKNOWN".equals(severity)) {
                items.add(new VulnRepoDashboardResponse.SeverityBreakdownItem(severity, total));
            }
        });
        return items;
    }

    private List<VulnRepoDashboardResponse.RecentAdvisoryItem> loadRecentAdvisories() {
        return jdbcTemplate.query(
                """
                select
                  v.external_id,
                  coalesce(nullif(v.title, ''), nullif(v.description_snippet, ''), v.external_id) as title,
                  coalesce(nullif(v.description_snippet, ''), nullif(v.title, ''), v.external_id) as description_snippet,
                  upper(coalesce(v.severity, 'UNKNOWN')) as severity,
                  upper(cast(v.source as text)) as source,
                  v.published_at,
                  v.last_modified_at
                from vulnerabilities v
                where not v.intelligence_withdrawn and v.external_id like :prefix
                order by coalesce(v.updated_at, v.last_modified_at, v.published_at) desc, v.external_id asc
                limit 5
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                (rs, rowNum) -> new VulnRepoDashboardResponse.RecentAdvisoryItem(
                        rs.getString("external_id"),
                        rs.getString("title"),
                        rs.getString("description_snippet"),
                        rs.getString("severity"),
                        rs.getString("source"),
                        rs.getTimestamp("published_at") == null ? null : rs.getTimestamp("published_at").toInstant(),
                        rs.getTimestamp("last_modified_at") == null ? null : rs.getTimestamp("last_modified_at").toInstant()
                )
        );
    }

    @Transactional(readOnly = true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public Map<String, Object> getSourceStats() {
        Map<String, Map<String, Long>> bySourceSeverity = new LinkedHashMap<>();
        jdbcTemplate.query(
                """
                select s.source_system,
                       upper(coalesce(v.severity, 'UNKNOWN')) as severity,
                       count(*) as total
                from vulnerability_intel_summary_sources s
                join vulnerabilities v on v.id = s.vulnerability_id
                where not v.intelligence_withdrawn and v.external_id like :prefix
                group by s.source_system, upper(coalesce(v.severity, 'UNKNOWN'))
                order by s.source_system, severity
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                (RowCallbackHandler) rs -> {
                    String src = rs.getString("source_system");
                    String sev = rs.getString("severity");
                    long total = rs.getLong("total");
                    bySourceSeverity.computeIfAbsent(src, k -> new java.util.HashMap<>()).put(sev, total);
                }
        );
        Map<String, Map<String, Long>> sources = new LinkedHashMap<>();
        bySourceSeverity.forEach((src, sevCounts) -> {
            long critical = sevCounts.getOrDefault("CRITICAL", 0L);
            long high     = sevCounts.getOrDefault("HIGH",     0L);
            long medium   = sevCounts.getOrDefault("MEDIUM",   0L);
            long low      = sevCounts.getOrDefault("LOW",      0L);
            long unknown  = sevCounts.getOrDefault("UNKNOWN",  0L);
            Map<String, Long> sourceStat = new LinkedHashMap<>();
            sourceStat.put("total", critical + high + medium + low + unknown);
            sourceStat.put("critical", critical);
            sourceStat.put("high", high);
            sourceStat.put("medium", medium);
            sourceStat.put("low", low);
            sourceStat.put("unknown", unknown);
            sources.put(src, sourceStat);
        });
        return Map.of("sources", sources);
    }

    @Transactional(readOnly = true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public PlatformVulnIntelDetailResponse getIntelDetail(String externalId) {
        Vulnerability v = vulnerabilityRepository.findByExternalId(externalId.trim().toUpperCase(Locale.ROOT))
                .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND, "Vulnerability not found: " + externalId));

        // Sources
        List<String> sourceList = new ArrayList<>();
        vulnerabilityIntelSummarySourceRepository.findByVulnerabilityIdIn(List.of(v.getId()))
                .forEach(row -> sourceList.add(row.getSourceSystem()));
        if (v.isInKev() && sourceList.stream().noneMatch(s -> s.equalsIgnoreCase("kev"))) {
            sourceList.add("kev");
        }

        // EUVD / JVNDB IDs
        String euvdId = vulnerabilityIntelObservationRepository
                .findFirstSourceRecordIdByVulnerabilityIds(List.of(v.getId()), "euvd")
                .stream().findFirst().map(r -> r.getSourceRecordId()).orElse(null);
        String jvndbId = vulnerabilityIntelObservationRepository
                .findFirstSourceRecordIdByVulnerabilityIds(List.of(v.getId()), "japan-vulndb")
                .stream().findFirst().map(r -> r.getSourceRecordId()).orElse(null);

        // Per-source observations
        List<com.prototype.vulnwatch.domain.VulnerabilityIntelObservation> obsEntities =
                vulnerabilityIntelObservationRepository.findByVulnerabilityOrderByLastSeenAtDesc(v);
        String fullDescription = pickBestDescription(obsEntities);
        List<PlatformVulnIntelDetailResponse.SourceObservation> observations = obsEntities.stream()
                .map(o -> new PlatformVulnIntelDetailResponse.SourceObservation(
                        o.getSourceSystem(),
                        o.getSourceRecordId(),
                        o.getSourceUrl(),
                        o.getTitle(),
                        o.getDescription(),
                        normalizeSeverity(o.getSeverity()),
                        o.getCvssScore(),
                        o.getCvssVector(),
                        o.getPublishedAt() != null ? o.getPublishedAt().toString() : null,
                        o.getLastModifiedAt() != null ? o.getLastModifiedAt().toString() : null
                ))
                .toList();

        // CPEs from vulnerability_targets
        List<String> cpes = loadDistinctCpes(v.getId());

        // References from referencesJson
        List<String> references = parseReferences(v.getReferencesJson());

        return new PlatformVulnIntelDetailResponse(
                v.getExternalId(),
                firstNonBlank(v.getTitle(), v.getExternalId()),
                v.getDescription(),
                fullDescription,
                normalizeSeverity(v.getSeverity()),
                v.getCvssScore(),
                v.getCvssVector(),
                v.getEpssScore(),
                v.getCweIds(),
                v.getVulnStatus(),
                v.getPublishedAt() != null ? v.getPublishedAt().toString() : null,
                v.getLastModifiedAt() != null ? v.getLastModifiedAt().toString() : null,
                v.isInKev(),
                v.getKevDateAdded() != null ? v.getKevDateAdded().toString() : null,
                v.getKevDueDate() != null ? v.getKevDueDate().toString() : null,
                v.getKevRequiredAction(),
                sourceList,
                euvdId,
                jvndbId,
                cpes,
                references,
                observations
        );
    }

    private String pickBestDescription(List<com.prototype.vulnwatch.domain.VulnerabilityIntelObservation> observations) {
        // Priority: nvd > euvd > ghsa > longest available
        List<String> preferred = List.of("nvd", "euvd", "ghsa");
        for (String src : preferred) {
            String desc = observations.stream()
                    .filter(o -> src.equalsIgnoreCase(o.getSourceSystem()) && hasText(o.getDescription()))
                    .map(com.prototype.vulnwatch.domain.VulnerabilityIntelObservation::getDescription)
                    .findFirst().orElse(null);
            if (desc != null) return desc;
        }
        return observations.stream()
                .filter(o -> hasText(o.getDescription()))
                .map(com.prototype.vulnwatch.domain.VulnerabilityIntelObservation::getDescription)
                .max(java.util.Comparator.comparingInt(String::length))
                .orElse(null);
    }

    private List<String> loadDistinctCpes(UUID vulnerabilityId) {
        return jdbcTemplate.queryForList(
                """
                select distinct cpe
                from vulnerability_targets
                where vulnerability_id = :vulnerabilityId
                  and cpe is not null
                  and trim(cpe) <> ''
                order by cpe
                """,
                new MapSqlParameterSource().addValue("vulnerabilityId", vulnerabilityId),
                String.class
        );
    }

    private List<String> parseReferences(String referencesJson) {
        if (!hasText(referencesJson)) return List.of();
        List<String> urls = new ArrayList<>();
        try {
            // Simple extraction: find all "url":"..." patterns
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"url\"\\s*:\\s*\"([^\"]+)\"");
            java.util.regex.Matcher matcher = pattern.matcher(referencesJson);
            while (matcher.find()) {
                String url = matcher.group(1);
                if (hasText(url)) urls.add(url);
            }
            if (!urls.isEmpty()) return urls;
            // Fallback: it might be a plain string array
            java.util.regex.Pattern plain = java.util.regex.Pattern.compile("\"(https?://[^\"]+)\"");
            java.util.regex.Matcher pm = plain.matcher(referencesJson);
            while (pm.find()) urls.add(pm.group(1));
        } catch (Exception ignored) {}
        return urls;
    }

    private List<String> normalizeSources(List<String> sources, boolean inKev) {
        List<String> normalized = new ArrayList<>();
        if (sources != null) {
            for (String source : sources) {
                if (hasText(source) && normalized.stream().noneMatch(existing -> existing.equalsIgnoreCase(source))) {
                    normalized.add(source);
                }
            }
        }
        if (inKev && normalized.stream().noneMatch(existing -> existing.equalsIgnoreCase("kev"))) {
            normalized.add("kev");
        }
        return normalized;
    }

    private UUID syntheticRecordId(Vulnerability vulnerability) {
        return UUID.nameUUIDFromBytes(("platform::" + vulnerability.getExternalId()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private String normalizeSeverity(String severity) {
        if (!hasText(severity)) {
            return "UNKNOWN";
        }
        return severity.trim().toUpperCase(Locale.ROOT);
    }

    private String firstNonBlank(String primary, String fallback) {
        return hasText(primary) ? primary : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record ScopedVulnerabilityIds(boolean enabled, boolean empty, List<UUID> vulnerabilityIds) {
        private static ScopedVulnerabilityIds unscopedScope() {
            return new ScopedVulnerabilityIds(false, false, UNSCOPED_VULNERABILITY_IDS);
        }

        private static ScopedVulnerabilityIds scopedScope(List<UUID> vulnerabilityIds) {
            return new ScopedVulnerabilityIds(true, false, vulnerabilityIds.stream().distinct().toList());
        }

        private static ScopedVulnerabilityIds emptyScope() {
            return new ScopedVulnerabilityIds(true, true, UNSCOPED_VULNERABILITY_IDS);
        }
    }
}
