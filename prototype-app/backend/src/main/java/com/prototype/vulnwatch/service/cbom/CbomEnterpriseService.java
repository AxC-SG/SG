package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
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
 * and portfolio rollups by business unit, owner team, environment or criticality.
 */
@Service
public class CbomEnterpriseService {
    /** Portfolio grouping key -> asset column. Values are fixed; never interpolate caller input. */
    private static final Map<String, String> GROUPS = Map.of(
            "department", "a.department", "ownerTeam", "a.owner_team", "environment", "a.environment",
            "businessCriticality", "a.business_criticality", "supportGroup", "a.support_group");

    public record PqcCampaignRequest(String name, String summary, Instant dueAt, String assignedTo, String ownerGroup,
            String environment, UUID assetId, String launchNote) { }

    public record PqcCampaignProgress(UUID campaignId, String name, String status, Instant dueAt, String createdBy, int findings,
            int open, int resolved, int overdue, BigDecimal percentComplete, List<String> owners) { }

    public record PqcProgress(int openQuantumVulnerable, int inCampaigns, int notInCampaign, List<PqcCampaignProgress> campaigns) { }

    public record PortfolioGroup(String group, int assets, int components, int openCritical, int openHigh, int openMedium,
            int openLow, int quantumVulnerable, int openCryptoFindings, int overdueCryptoFindings, BigDecimal averagePostureScore) { }

    public record Portfolio(String groupBy, List<PortfolioGroup> groups) { }

    private final JdbcTemplate jdbc;
    private final CryptoRemediationService remediation;

    public CbomEnterpriseService(JdbcTemplate jdbc, CryptoRemediationService remediation) {
        this.jdbc = jdbc; this.remediation = remediation;
    }

    /** Creates a campaign over every open quantum-vulnerable CRYPTO finding in scope, optionally assigned. */
    public CampaignDetailResponse createPqcCampaign(Tenant tenant, PqcCampaignRequest request, String actor) {
        if (request == null || request.name() == null || request.name().isBlank()) throw new IllegalArgumentException("name is required");
        if (request.dueAt() == null) throw new IllegalArgumentException("dueAt is required for a PQC migration campaign");
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
                ids, request.dueAt(), request.assignedTo(), request.ownerGroup(), request.launchNote()), actor);
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
        List<PqcCampaignProgress> campaigns = jdbc.query("""
                SELECT c.id, c.name, c.status, c.due_at, c.created_by, count(*),
                       count(*) FILTER (WHERE f.status = 'OPEN'),
                       count(*) FILTER (WHERE f.status IN ('RESOLVED', 'AUTO_CLOSED')),
                       count(*) FILTER (WHERE f.status = 'OPEN' AND f.due_at < now()),
                       string_agg(DISTINCT coalesce(f.assigned_to, f.owner_group), ',')
                  FROM campaigns c JOIN campaign_findings cf ON cf.campaign_id = c.id JOIN findings f ON f.id = cf.finding_id
                 WHERE f.finding_kind = 'CRYPTO' AND f.reason_code = 'QUANTUM_VULNERABLE'
                 GROUP BY c.id, c.name, c.status, c.due_at, c.created_by
                 ORDER BY c.due_at NULLS LAST, c.name
                """, (rs, row) -> {
                    int total = rs.getInt(6), resolved = rs.getInt(8);
                    String owners = rs.getString(10);
                    return new PqcCampaignProgress(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                            rs.getTimestamp(4) == null ? null : rs.getTimestamp(4).toInstant(), rs.getString(5), total, rs.getInt(7),
                            resolved, rs.getInt(9), total == 0 ? null : BigDecimal.valueOf(resolved).divide(BigDecimal.valueOf(total), 5, RoundingMode.HALF_UP),
                            owners == null ? List.of() : List.of(owners.split(",")));
                });
        int openCount = open == null ? 0 : open, campaignCount = inCampaign == null ? 0 : inCampaign;
        return new PqcProgress(openCount, campaignCount, Math.max(0, openCount - campaignCount), campaigns);
    }

    public Portfolio portfolio(String groupBy) {
        String key = groupBy == null || groupBy.isBlank() ? "department" : groupBy.trim();
        String column = GROUPS.get(key);
        if (column == null) throw new IllegalArgumentException("groupBy must be one of " + GROUPS.keySet());
        String group = "coalesce(nullif(trim(" + column + "), ''), 'Unassigned')";
        List<PortfolioGroup> groups = jdbc.query("""
                WITH ga AS (SELECT a.id, %1$s AS grp FROM assets a),
                comp AS (
                    SELECT ga.grp, count(DISTINCT ga.id) AS assets, count(DISTINCT c.id) AS components,
                           count(DISTINCT r.id) FILTER (WHERE r.severity = 'CRITICAL') AS critical,
                           count(DISTINCT r.id) FILTER (WHERE r.severity = 'HIGH') AS high,
                           count(DISTINCT r.id) FILTER (WHERE r.severity = 'MEDIUM') AS medium,
                           count(DISTINCT r.id) FILTER (WHERE r.severity = 'LOW') AS low,
                           count(DISTINCT r.id) FILTER (WHERE r.risk_class = 'QUANTUM_VULNERABLE') AS quantum
                      FROM cbom_components c JOIN ga ON ga.id = c.asset_id
                      LEFT JOIN cbom_risk_findings r ON r.cbom_component_id = c.id AND r.status = 'OPEN' AND r.evidence_state <> 'WITHDRAWN'
                     WHERE c.active GROUP BY ga.grp),
                fnd AS (
                    SELECT ga.grp, count(*) FILTER (WHERE f.status = 'OPEN') AS open,
                           count(*) FILTER (WHERE f.status = 'OPEN' AND f.due_at < now()) AS overdue
                      FROM findings f JOIN ga ON ga.id = f.asset_id WHERE f.finding_kind = 'CRYPTO' GROUP BY ga.grp),
                pos AS (SELECT ga.grp, avg(p.posture_score) AS score FROM cbom_posture_summary p JOIN ga ON ga.id = p.asset_id GROUP BY ga.grp)
                SELECT comp.grp, comp.assets, comp.components, comp.critical, comp.high, comp.medium, comp.low, comp.quantum,
                       coalesce(fnd.open, 0), coalesce(fnd.overdue, 0), pos.score
                  FROM comp LEFT JOIN fnd ON fnd.grp = comp.grp LEFT JOIN pos ON pos.grp = comp.grp
                 ORDER BY comp.critical DESC, comp.high DESC, comp.grp
                """.formatted(group),
                (rs, row) -> new PortfolioGroup(rs.getString(1), rs.getInt(2), rs.getInt(3), rs.getInt(4), rs.getInt(5), rs.getInt(6),
                        rs.getInt(7), rs.getInt(8), rs.getInt(9), rs.getInt(10),
                        rs.getBigDecimal(11) == null ? null : rs.getBigDecimal(11).setScale(2, RoundingMode.HALF_UP)));
        return new Portfolio(key, groups);
    }
}
