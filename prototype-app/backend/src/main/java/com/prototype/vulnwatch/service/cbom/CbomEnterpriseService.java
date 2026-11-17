package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignOwnerBucket;
import com.prototype.vulnwatch.service.CampaignLedger;
import com.prototype.vulnwatch.service.CampaignOutcomeClassifier.Outcome;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Consumer;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Enterprise governance read models and PQC migration (plan Milestone 5): post-quantum migration
 * campaigns built from canonical QUANTUM_VULNERABLE CRYPTO findings with owners, dates and progress,
 * and portfolio rollups by business unit, owner team, environment or criticality. Progress uses the campaign outcome
 * rules and owner buckets (Phase 0B §4.5, §4.8); the owner-team rollup groups by stable team ID (§3.7).
 */
@Service
public class CbomEnterpriseService {
    /** Portfolio grouping key -> asset column. Values are fixed; never interpolate caller input. */
    private static final Map<String, String> GROUPS = Map.of(
            "department", "a.department", "ownerTeam", "a.owner_team", "environment", "a.environment",
            "businessCriticality", "a.business_criticality", "supportGroup", "a.support_group");

    /** {@code ownerGroup} and the free-text {@code assignedTo} are rejected with 400 (Phase 0B §4.2, §4.12). */
    public record PqcCampaignRequest(String name, String summary, Instant dueAt, UUID assigneePrincipalId,
            String environment, UUID assetId, String launchNote, com.fasterxml.jackson.databind.JsonNode ownerGroup,
            com.fasterxml.jackson.databind.JsonNode assignedTo) { }

    /**
     * {@code active} is OPEN plus REOPENED members; {@code remediated} counts REMEDIATED only, so suppressed,
     * accepted-risk and otherwise closed members are never progress (§4.8). {@code owners} are the current owner
     * buckets of the campaign's quantum-vulnerable members: teams by ID, Unowned, Conflict or Pending Migration.
     */
    public record PqcCampaignProgress(UUID campaignId, String name, String status, Instant dueAt, String createdBy, int findings,
            int active, int remediated, int overdue, BigDecimal percentComplete, Map<String, Long> outcomes,
            List<CampaignOwnerBucket> owners) { }

    public record PqcProgress(int openQuantumVulnerable, int inCampaigns, int notInCampaign, List<PqcCampaignProgress> campaigns) { }

    /**
     * {@code teamId} and {@code ownerBucket} (TEAM, UNOWNED, CONFLICT or PENDING_MIGRATION) are set only for the
     * owner-team grouping. A PENDING_MIGRATION group keeps the legacy owner-team label (§3.7).
     */
    public record PortfolioGroup(String group, int assets, int components, int openCritical, int openHigh, int openMedium,
            int openLow, int quantumVulnerable, int openCryptoFindings, int overdueCryptoFindings, BigDecimal averagePostureScore,
            UUID teamId, String ownerBucket) { }

    public record Portfolio(String groupBy, List<PortfolioGroup> groups) { }

    private final JdbcTemplate jdbc;
    private final CryptoRemediationService remediation;
    private final CampaignLedger ledger;
    private final OwnershipReadAdapter reads;

    public CbomEnterpriseService(JdbcTemplate jdbc, CryptoRemediationService remediation, CampaignLedger ledger, OwnershipReadAdapter reads) {
        this.jdbc = jdbc; this.remediation = remediation; this.ledger = ledger; this.reads = reads;
    }

    /** Creates a campaign over every open quantum-vulnerable CRYPTO finding in scope, optionally assigned. */
    public CampaignDetailResponse createPqcCampaign(Tenant tenant, PqcCampaignRequest request, String actor) {
        if (request == null || request.name() == null || request.name().isBlank()) throw new IllegalArgumentException("name is required");
        if (request.dueAt() == null) throw new IllegalArgumentException("dueAt is required for a PQC migration campaign");
        if (request.ownerGroup() != null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Campaigns do not set ownership; ownerGroup is not accepted");
        if (request.assignedTo() != null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "assignedTo is not accepted; use assigneePrincipalId");
        List<Object> args = new ArrayList<>();
        StringBuilder sql = new StringBuilder("""
                SELECT f.id FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
                 WHERE f.finding_kind = 'CRYPTO' AND f.status = 'OPEN' AND f.reason_code = 'QUANTUM_VULNERABLE'""");
        if (request.environment() != null && !request.environment().isBlank()) {
            sql.append(" AND lower(a.environment) = ?"); args.add(request.environment().trim().toLowerCase(Locale.ROOT));
        }
        if (request.assetId() != null) { sql.append(" AND f.asset_id = ?"); args.add(request.assetId()); }
        sql.append(" ORDER BY f.created_at LIMIT ").append(com.prototype.vulnwatch.service.CampaignService.MAX_CAMPAIGN_FINDINGS + 1);
        List<UUID> ids = jdbc.queryForList(sql.toString(), UUID.class, args.toArray());
        if (ids.isEmpty()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No open quantum-vulnerable findings match this scope");
        if (ids.size() > com.prototype.vulnwatch.service.CampaignService.MAX_CAMPAIGN_FINDINGS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "More than " + com.prototype.vulnwatch.service.CampaignService.MAX_CAMPAIGN_FINDINGS
                    + " findings match; narrow the scope by environment or asset");
        }
        return remediation.createCampaign(tenant, new CampaignFromFindingsRequest(request.name(),
                request.summary() == null ? "Post-quantum migration of quantum-vulnerable cryptography" : request.summary(),
                ids, request.dueAt(), request.assigneePrincipalId(), request.launchNote(), request.ownerGroup(), request.assignedTo()), actor);
    }

    public PqcProgress pqcProgress() {
        Integer open = jdbc.queryForObject("""
                SELECT count(*) FROM findings WHERE finding_kind = 'CRYPTO' AND status = 'OPEN' AND reason_code = 'QUANTUM_VULNERABLE'
                """, Integer.class);
        Integer inCampaign = jdbc.queryForObject("""
                SELECT count(DISTINCT f.id) FROM findings f JOIN campaign_findings cf ON cf.finding_id = f.id
                  JOIN campaigns c ON c.id = cf.campaign_id
                 WHERE f.finding_kind = 'CRYPTO' AND f.status = 'OPEN' AND f.reason_code = 'QUANTUM_VULNERABLE'
                   AND c.status NOT IN ('CLOSED', 'CANCELLED')
                """, Integer.class);
        Map<UUID, CampaignLedger.KindProgress> byCampaign = ledger.progressByCampaign(
                "f.finding_kind = 'CRYPTO' AND f.reason_code = 'QUANTUM_VULNERABLE'");
        List<PqcCampaignProgress> campaigns = byCampaign.isEmpty() ? List.of() : jdbc.query("""
                SELECT id, name, status, due_at, created_by FROM campaigns WHERE id = ANY (?::uuid[])
                 ORDER BY due_at NULLS LAST, name
                """, (rs, row) -> {
                    UUID id = rs.getObject(1, UUID.class);
                    CampaignLedger.KindProgress progress = byCampaign.get(id);
                    int total = (int) progress.members(), remediated = (int) progress.count(Outcome.REMEDIATED);
                    return new PqcCampaignProgress(id, rs.getString(2), rs.getString(3),
                            rs.getTimestamp(4) == null ? null : rs.getTimestamp(4).toInstant(), rs.getString(5), total,
                            (int) (progress.count(Outcome.OPEN) + progress.count(Outcome.REOPENED)), remediated, (int) progress.overdueActive(),
                            total == 0 ? null : BigDecimal.valueOf(remediated).divide(BigDecimal.valueOf(total), 5, RoundingMode.HALF_UP),
                            CampaignLedger.outcomeMap(progress.outcomes()), progress.owners());
                }, "{" + byCampaign.keySet().stream().map(UUID::toString).collect(java.util.stream.Collectors.joining(",")) + "}");
        int openCount = open == null ? 0 : open, campaignCount = inCampaign == null ? 0 : inCampaign;
        return new PqcProgress(openCount, campaignCount, Math.max(0, openCount - campaignCount), campaigns);
    }

    public Portfolio portfolio(String groupBy) {
        String key = groupBy == null || groupBy.isBlank() ? "department" : groupBy.trim();
        String column = GROUPS.get(key);
        if (column == null) throw new IllegalArgumentException("groupBy must be one of " + GROUPS.keySet());
        List<Object> args = new ArrayList<>();
        String ga;
        if ("ownerTeam".equals(key)) {
            // Phase 0B §3.7: group by the asset's current owner team ID. An asset whose domain is not canonical for
            // inventory reads keeps its legacy owner-team label and is marked PENDING_MIGRATION, never UNOWNED.
            String canonical = canonicalAssetTypes();
            args.add(canonical);
            args.add(canonical);
            args.add(canonical);
            args.add(canonical);
            ga = """
                    SELECT a.id,
                           CASE WHEN a.type = ANY (?::text[]) THEN
                                   CASE WHEN a.ownership_subject_id IS NULL THEN 'Unowned'
                                        WHEN e.ownership_status = 'OWNED' THEN t.name
                                        WHEN e.ownership_status = 'CONFLICT' THEN 'Conflict' ELSE 'Unowned' END
                                ELSE coalesce(nullif(trim(a.owner_team), ''), 'Unassigned') END AS grp,
                           CASE WHEN a.type = ANY (?::text[]) THEN
                                   CASE WHEN a.ownership_subject_id IS NULL THEN 'UNOWNED'
                                        WHEN e.ownership_status = 'OWNED' THEN 'TEAM|' || e.owner_team_id::text
                                        WHEN e.ownership_status = 'CONFLICT' THEN 'CONFLICT' ELSE 'UNOWNED' END
                                ELSE 'PENDING_MIGRATION|' || coalesce(nullif(trim(a.owner_team), ''), 'Unassigned') END AS gkey,
                           CASE WHEN a.type = ANY (?::text[]) AND a.ownership_subject_id IS NOT NULL AND e.ownership_status = 'OWNED'
                                THEN e.owner_team_id END AS team_id,
                           CASE WHEN a.type = ANY (?::text[]) THEN
                                   CASE WHEN a.ownership_subject_id IS NULL THEN 'UNOWNED'
                                        WHEN e.ownership_status = 'OWNED' THEN 'TEAM'
                                        WHEN e.ownership_status = 'CONFLICT' THEN 'CONFLICT' ELSE 'UNOWNED' END
                                ELSE 'PENDING_MIGRATION' END AS bucket
                      FROM assets a
                      LEFT JOIN ownership_effective_assignment e ON e.subject_id = a.ownership_subject_id
                      LEFT JOIN team t ON t.id = e.owner_team_id""";
        } else {
            String group = "coalesce(nullif(trim(" + column + "), ''), 'Unassigned')";
            ga = "SELECT a.id, " + group + " AS grp, " + group + " AS gkey, NULL::uuid AS team_id, NULL::text AS bucket FROM assets a";
        }
        List<PortfolioGroup> groups = jdbc.query("""
                WITH ga AS (%1$s),
                comp AS (
                    SELECT ga.gkey, max(ga.grp) AS grp, (array_agg(ga.team_id))[1] AS team_id, max(ga.bucket) AS bucket,
                           count(DISTINCT ga.id) AS assets, count(DISTINCT c.id) AS components,
                           count(DISTINCT r.id) FILTER (WHERE r.severity = 'CRITICAL') AS critical,
                           count(DISTINCT r.id) FILTER (WHERE r.severity = 'HIGH') AS high,
                           count(DISTINCT r.id) FILTER (WHERE r.severity = 'MEDIUM') AS medium,
                           count(DISTINCT r.id) FILTER (WHERE r.severity = 'LOW') AS low,
                           count(DISTINCT r.id) FILTER (WHERE r.risk_class = 'QUANTUM_VULNERABLE') AS quantum
                      FROM cbom_components c JOIN ga ON ga.id = c.asset_id
                      LEFT JOIN cbom_risk_findings r ON r.cbom_component_id = c.id AND r.status = 'OPEN' AND r.evidence_state <> 'WITHDRAWN'
                     WHERE c.active GROUP BY ga.gkey),
                fnd AS (
                    SELECT ga.gkey, count(*) FILTER (WHERE f.status = 'OPEN') AS open,
                           count(*) FILTER (WHERE f.status = 'OPEN' AND f.due_at < now()) AS overdue
                      FROM findings f JOIN ga ON ga.id = f.asset_id WHERE f.finding_kind = 'CRYPTO' GROUP BY ga.gkey),
                pos AS (SELECT ga.gkey, avg(p.posture_score) AS score FROM cbom_posture_summary p JOIN ga ON ga.id = p.asset_id GROUP BY ga.gkey)
                SELECT comp.grp, comp.assets, comp.components, comp.critical, comp.high, comp.medium, comp.low, comp.quantum,
                       coalesce(fnd.open, 0), coalesce(fnd.overdue, 0), pos.score, comp.team_id, comp.bucket
                  FROM comp LEFT JOIN fnd ON fnd.gkey = comp.gkey LEFT JOIN pos ON pos.gkey = comp.gkey
                 ORDER BY comp.critical DESC, comp.high DESC, comp.grp
                """.formatted(ga),
                (rs, row) -> new PortfolioGroup(rs.getString(1), rs.getInt(2), rs.getInt(3), rs.getInt(4), rs.getInt(5), rs.getInt(6),
                        rs.getInt(7), rs.getInt(8), rs.getInt(9), rs.getInt(10),
                        rs.getBigDecimal(11) == null ? null : rs.getBigDecimal(11).setScale(2, RoundingMode.HALF_UP),
                        rs.getObject(12, UUID.class), rs.getString(13)), args.toArray());
        return new Portfolio(key, groups);
    }

    /** Asset types whose ownership domain is canonical for inventory reads, as a Postgres text array literal. */
    private String canonicalAssetTypes() {
        List<String> types = new ArrayList<>();
        for (String type : List.of("APPLICATION", "HOST", "CONTAINER_IMAGE", "CLOUD_ACCOUNT", "CLOUD_RESOURCE")) {
            Domain domain = OwnershipAuthorityService.domainFor(type);
            if (reads.canonical(Consumer.INVENTORY, domain)) types.add(type);
        }
        return "{" + String.join(",", types) + "}";
    }
}
