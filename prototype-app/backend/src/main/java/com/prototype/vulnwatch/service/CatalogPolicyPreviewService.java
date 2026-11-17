package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.CatalogPolicyPreview.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CatalogPolicyPreviewService {
    private static final int BATCH_SIZE = 100;
    private static final int OBSERVATION_FETCH_SIZE = 128;
    private final CatalogPolicyEvaluator evaluator;
    private final WorkspaceService workspace;
    private final VulnerabilitySourceFilterConfigService sourceConfig;
    private final NamedParameterJdbcTemplate jdbc;
    public CatalogPolicyPreviewService(CatalogPolicyEvaluator evaluator, WorkspaceService workspace,
            VulnerabilitySourceFilterConfigService sourceConfig, NamedParameterJdbcTemplate jdbc) {
        this.evaluator = evaluator; this.workspace = workspace; this.sourceConfig = sourceConfig; this.jdbc = jdbc;
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ, timeout = 15, noRollbackFor = ResponseStatusException.class)
    public Snapshot snapshot(com.prototype.vulnwatch.dto.CatalogPolicy policy) {
        if (TenantContext.getCurrentTenantId() == null || TenantContext.isPlatformContext())
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "An active tenant context is required");
        var tenant = workspace.getWorkspace();
        evaluator.validate(policy);
        var enabled = sourceConfig.enabledSourcesForCorrelation(tenant);
        if (!enabled.containsAll(policy.sources()))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Policy includes disabled tenant sources");
        // Append-only history makes both counts monotonic. Expiry changes invalidate continuation too.
        String overrideState = jdbc.queryForObject("""
                select count(*)::text || ':' || count(*) filter (where expires_at <= now())::text
                from intelligence_catalog_overrides where tenant_id=:tenant
                """, Map.of("tenant", tenant.getId()), String.class);
        Long generation = jdbc.queryForObject("select generation from platform.intelligence_active_state where singleton=true",
                Map.of(), Long.class);
        if (generation == null) throw new ResponseStatusException(HttpStatus.CONFLICT, "Published generation is unavailable");
        return new Snapshot(generation, overrideState,
                String.join(",", new TreeSet<>(enabled)) + ":" + sourceConfigurationFingerprint(tenant.getId()));
    }

    private String sourceConfigurationFingerprint(UUID tenantId) {
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
        jdbc.query("""
                select id,source_system,enabled_for_correlation,filters_json,updated_at
                from vulnerability_source_filter_configs where tenant_id=:tenant
                order by lower(source_system),id
                """, Map.of("tenant", tenantId), rs -> {
            fingerprintPart(digest, rs.getString("id"));
            fingerprintPart(digest, rs.getString("source_system"));
            fingerprintPart(digest, Boolean.toString(rs.getBoolean("enabled_for_correlation")));
            fingerprintPart(digest, rs.getString("filters_json"));
            fingerprintPart(digest, rs.getString("updated_at"));
        });
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void fingerprintPart(MessageDigest digest, String value) {
        if (value == null) {
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(-1).array());
        } else {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
            digest.update(bytes);
        }
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ, timeout = 15, noRollbackFor = ResponseStatusException.class)
    public Response preview(Request request) {
        if (request == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Preview request is required");
        var state = snapshot(request.policy());
        var tenant = workspace.getWorkspace();
        if (request.afterId() != null && (request.expectedGeneration() == null || request.expectedOverrideState() == null || request.expectedSourceState() == null))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Incomplete cursor; restart preview");
        if (request.expectedGeneration() != null && state.generation() != request.expectedGeneration())
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Published intelligence changed; restart preview");
        if (request.expectedOverrideState() != null && !state.overrideState().equals(request.expectedOverrideState()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Catalog overrides changed; restart preview");
        if (request.expectedSourceState() != null && !state.sourceState().equals(request.expectedSourceState()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Tenant sources changed; restart preview");
        var params = new MapSqlParameterSource("after", request.afterId()).addValue("limit", BATCH_SIZE + 1);
        var rows = jdbc.query("""
                select id, external_id from platform.vulnerabilities
                where intelligence_withdrawn=false and (cast(:after as uuid) is null or id > cast(:after as uuid))
                order by id limit :limit
                """, params, (rs, n) -> new Candidate(rs.getObject("id", UUID.class), rs.getString("external_id")));
        boolean complete = rows.size() <= BATCH_SIZE;
        var batch = rows.stream().limit(BATCH_SIZE).toList();
        Map<UUID, String> overrides = new HashMap<>();
        if (!batch.isEmpty()) {
            // Choose latest first: expired/restored instructions must not resurrect older overrides.
            jdbc.query("""
                    select * from (
                        select distinct on (vulnerability_id) vulnerability_id, operation, expires_at
                        from intelligence_catalog_overrides
                        where tenant_id=:tenant and vulnerability_id in (:ids)
                        order by vulnerability_id, revision desc
                    ) latest where operation <> 'RESTORE' and (expires_at is null or expires_at > now())
                    """, Map.of("tenant", tenant.getId(), "ids", batch.stream().map(Candidate::id).toList()),
                    rs -> { overrides.put(rs.getObject("vulnerability_id", UUID.class), rs.getString("operation")); });
        }
        Map<UUID, EvidenceAccumulator> evidence = new HashMap<>();
        if (!batch.isEmpty()) {
            // Scalar projection avoids loading raw source payloads or N+1 queries.
            jdbc.execute("""
                    select id, vulnerability_id, source_system, source_record_id, payload_hash,
                           published_at, cvss_score, cvss_version, epss_score, in_kev
                    from platform.vulnerability_intel_observations where vulnerability_id in (:ids)
                    """, new MapSqlParameterSource("ids", batch.stream().map(Candidate::id).toList()), statement -> {
                statement.setFetchSize(OBSERVATION_FETCH_SIZE);
                try (var rs = statement.executeQuery()) {
                    while (rs.next()) {
                        String source = IntelligenceSourceRegistry.setting(rs.getString("source_system"));
                        if (!request.policy().sources().contains(source)) continue;
                        var published = rs.getTimestamp("published_at");
                        evidence.computeIfAbsent(rs.getObject("vulnerability_id", UUID.class),
                                ignored -> new EvidenceAccumulator(request.policy().scoreResolution()))
                                .accept(new Evidence(rs.getObject("id", UUID.class), source, rs.getString("source_record_id"),
                                        rs.getString("payload_hash"), rs.getString("cvss_version"),
                                        published == null ? null : published.toInstant().atZone(ZoneOffset.UTC).getYear(),
                                        (Double) rs.getObject("cvss_score"), (Double) rs.getObject("epss_score"), (Boolean) rs.getObject("in_kev")));
                    }
                }
                return null;
            });
        }
        var matches = new ArrayList<Match>();
        for (var row : batch) {
            String override = overrides.get(row.id());
            if ("EXCLUDE".equals(override)) continue;
            boolean included = "INCLUDE".equals(override);
            if (!included && !request.policy().includeNonCve() && !row.externalId().startsWith("CVE-")) continue;
            var allowed = evidence.get(row.id());
            if (allowed == null) continue; // Missing predicates cannot admit records without allowed evidence.
            var resolved = allowed.resolve();
            if (included || evaluator.matches(request.policy().rule(), resolved.facts(), true))
                matches.add(new Match(row.id(), row.externalId(), resolved.facts(),
                        included ? "MANUAL_INCLUDE" : "POLICY", resolved.attribution()));
        }
        return new Response(state.generation(), batch.size(), matches.size(),
                complete ? null : batch.get(batch.size() - 1).id(), complete, matches, state.overrideState(), state.sourceState());
    }

    private static final class EvidenceAccumulator {
        private static final Comparator<Evidence> ID_ORDER = Comparator.comparing(item -> item.id().toString());
        private static final Comparator<Evidence> YEAR_ORDER = Comparator.comparing(Evidence::year).thenComparing(ID_ORDER);
        private static final Comparator<Evidence> SCORE_ORDER = Comparator.comparing(Evidence::cvss).reversed().thenComparing(ID_ORDER);
        private static final Comparator<Evidence> EPSS_ORDER = Comparator.comparing(Evidence::epss).reversed().thenComparing(ID_ORDER);
        private static final Comparator<Evidence> SOURCE_ORDER = Comparator.comparing(Evidence::source).thenComparing(ID_ORDER);
        private final com.prototype.vulnwatch.dto.CatalogPolicy.ScoreResolution scoreResolution;
        private Evidence year;
        private Evidence cvss;
        private Evidence epss;
        private Evidence kev;
        private Evidence sourcePresence;

        private EvidenceAccumulator(com.prototype.vulnwatch.dto.CatalogPolicy.ScoreResolution scoreResolution) {
            this.scoreResolution = scoreResolution;
        }

        private void accept(Evidence item) {
            sourcePresence = preferred(sourcePresence, item, SOURCE_ORDER);
            if (item.year() != null) year = preferred(year, item, YEAR_ORDER);
            if (validScore(item.cvss(), 10) && switch (scoreResolution) {
                case MAX_ALLOWED_OBSERVATION_V1 -> true;
                case MAX_ALLOWED_CVSS_V3_1 -> "3.1".equals(item.cvssVersion());
                case MAX_ALLOWED_CVSS_V4_0 -> "4.0".equals(item.cvssVersion());
            }) cvss = preferred(cvss, item, SCORE_ORDER);
            if (validScore(item.epss(), 1)) epss = preferred(epss, item, EPSS_ORDER);
            if (item.source().equals("kev") && Boolean.TRUE.equals(item.kev())) kev = preferred(kev, item, ID_ORDER);
        }

        private Resolved resolve() {
            return new Resolved(new CatalogPolicyEvaluator.Facts(year == null ? null : year.year(),
                    cvss == null ? null : cvss.cvss(), epss == null ? null : epss.epss(), kev == null ? null : true),
                    new Attribution(provenance(year), provenance(cvss), provenance(epss), provenance(kev), provenance(sourcePresence)));
        }

        private static Evidence preferred(Evidence current, Evidence candidate, Comparator<Evidence> order) {
            return current == null || order.compare(candidate, current) < 0 ? candidate : current;
        }
    }
    private static boolean validScore(Double value, int max) {
        return value != null && Double.isFinite(value) && value >= 0 && value <= max;
    }
    private static FactEvidence provenance(Evidence evidence) {
        return evidence == null ? null : new FactEvidence(evidence.id(), evidence.source(),
                evidence.sourceRecordId(), evidence.payloadHash(), evidence.cvssVersion());
    }
    private record Candidate(UUID id, String externalId) {}
    private record Evidence(UUID id, String source, String sourceRecordId, String payloadHash, String cvssVersion,
                            Integer year, Double cvss, Double epss, Boolean kev) {}
    private record Resolved(CatalogPolicyEvaluator.Facts facts, Attribution attribution) {}
}
