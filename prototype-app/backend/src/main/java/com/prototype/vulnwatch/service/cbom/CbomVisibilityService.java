package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomVisibilityDtos.*;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Tenant-scoped CBOM visibility read models (plan sections 5.5 and 9, Milestone 2): executive
 * overview, daily trend snapshots, the filterable analyst inventory and the component evidence
 * drawer. All queries run in the caller's tenant schema; risk counts consider only open findings
 * whose evidence is still supported on active components.
 */
@Service
public class CbomVisibilityService {
    private static final Logger LOG = LoggerFactory.getLogger(CbomVisibilityService.class);
    public static final int MAX_PAGE_SIZE = 200;
    public static final int TOTAL_CAP = 10_000;
    public static final int MAX_TREND_DAYS = 365;
    private static final Set<String> SEVERITIES = Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");
    private static final Set<String> ASSET_TYPES = Set.of("ALGORITHM", "CERTIFICATE", "PROTOCOL", "RELATED_CRYPTO_MATERIAL", "UNKNOWN");
    private static final Set<String> EVIDENCE_STATES = Set.of("SUPPORTED", "WITHDRAWN", "CONFLICTING", "LEGACY_UNKNOWN");
    private static final String OPEN_SUPPORTED = "r.status = 'OPEN' AND r.evidence_state <> 'WITHDRAWN' AND c.active";

    private final JdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService schemas;
    private final TransactionTemplate transactions;
    private BackgroundTaskExecutionPolicy policy = BackgroundTaskExecutionPolicy.allowAll();
    private Clock clock = Clock.systemUTC();
    private int snapshotRetentionDays = 400;

    public CbomVisibilityService(JdbcTemplate jdbc, TenantService tenants, TenantSchemaExecutionService schemas,
            TransactionTemplate transactions) {
        this.jdbc = jdbc; this.tenants = tenants; this.schemas = schemas; this.transactions = transactions;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy value) {
        policy = value == null ? BackgroundTaskExecutionPolicy.allowAll() : value;
    }
    void setClock(Clock value) { clock = value; }
    @Value("${app.cbom.trends.snapshot-retention-days:400}") public void setSnapshotRetentionDays(int value) { snapshotRetentionDays = Math.max(MAX_TREND_DAYS, value); }

    // ------------------------------------------------------------------ overview

    @Transactional(readOnly = true)
    public Overview overview(Tenant tenant) {
        UUID id = tenant.getId();
        LocalDate today = LocalDate.now(clock);
        Map<String, Integer> severity = new LinkedHashMap<>();
        int[] quantum = new int[2];
        jdbc.query("SELECT r.severity, r.risk_class, count(*), count(DISTINCT r.cbom_component_id) FROM cbom_risk_findings r"
                + " JOIN cbom_components c ON c.id = r.cbom_component_id WHERE r.tenant_id = ? AND " + OPEN_SUPPORTED
                + " GROUP BY r.severity, r.risk_class", rs -> {
                    severity.merge(rs.getString(1), rs.getInt(3), Integer::sum);
                    if ("QUANTUM_VULNERABLE".equals(rs.getString(2))) { quantum[0] += rs.getInt(3); quantum[1] += rs.getInt(4); }
                }, id);
        Integer[] assetsAtRisk = jdbc.queryForObject("""
                SELECT count(DISTINCT c.asset_id),
                       count(DISTINCT c.asset_id) FILTER (WHERE lower(coalesce(a.environment, '')) IN ('prod', 'production'))
                  FROM cbom_risk_findings r JOIN cbom_components c ON c.id = r.cbom_component_id
                  JOIN assets a ON a.id = c.asset_id
                 WHERE r.tenant_id = ? AND r.severity IN ('CRITICAL', 'HIGH') AND""" + " " + OPEN_SUPPORTED,
                (rs, row) -> new Integer[] {rs.getInt(1), rs.getInt(2)}, id);
        List<ProductionAsset> production = jdbc.query("""
                SELECT a.id, a.name, a.environment,
                       count(*) FILTER (WHERE r.severity = 'CRITICAL'), count(*) FILTER (WHERE r.severity = 'HIGH')
                  FROM cbom_risk_findings r JOIN cbom_components c ON c.id = r.cbom_component_id
                  JOIN assets a ON a.id = c.asset_id
                 WHERE r.tenant_id = ? AND r.severity IN ('CRITICAL', 'HIGH')
                   AND lower(coalesce(a.environment, '')) IN ('prod', 'production') AND""" + " " + OPEN_SUPPORTED + """
                 GROUP BY a.id, a.name, a.environment
                 ORDER BY 4 DESC, 5 DESC, a.name LIMIT 10
                """, (rs, row) -> new ProductionAsset(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getInt(4), rs.getInt(5)), id);
        BigDecimal posture = jdbc.queryForObject("SELECT avg(posture_score) FROM cbom_posture_summary WHERE tenant_id = ?", BigDecimal.class, id);

        Map<String, Integer> byType = new LinkedHashMap<>();
        int[] rotation = new int[4];
        jdbc.query("""
                SELECT asset_type, count(*),
                       count(*) FILTER (WHERE not_after < ?),
                       count(*) FILTER (WHERE not_after >= ? AND not_after <= ?),
                       count(*) FILTER (WHERE not_after >= ? AND not_after <= ?),
                       count(*) FILTER (WHERE not_after >= ? AND not_after <= ?)
                  FROM cbom_components WHERE tenant_id = ? AND active GROUP BY asset_type ORDER BY asset_type
                """, rs -> {
                    byType.put(rs.getString(1), rs.getInt(2));
                    for (int i = 0; i < 4; i++) rotation[i] += rs.getInt(3 + i);
                }, today, today, today.plusDays(30), today, today.plusDays(60), today, today.plusDays(90), id);

        Assurance assurance = assurance(id);
        Remediation remediation = remediation();
        return new Overview(Instant.now(clock),
                new Risk(severity.getOrDefault("CRITICAL", 0), severity.getOrDefault("HIGH", 0), severity.getOrDefault("MEDIUM", 0),
                        severity.getOrDefault("LOW", 0), scale(posture, 4), assetsAtRisk[0], assetsAtRisk[1]),
                assurance, remediation, new Rotation(rotation[0], rotation[1], rotation[2], rotation[3]),
                new Pqc(quantum[0], quantum[1]), production, byType,
                "Open CRYPTO findings are canonical findings: they appear in the Findings queue and count toward finding totals,"
                        + " but they are not CVE exposures and do not change Exposure CVE counts or CVE risk scores.");
    }

    private Assurance assurance(UUID tenantId) {
        Object[] totals = jdbc.queryForObject("""
                WITH active AS (
                    SELECT id FROM bom_ingestion_records WHERE tenant_id = ? AND bom_type = 'CBOM' AND status = 'ACTIVE'),
                latest AS (
                    SELECT DISTINCT ON (r.bom_id) r.id, r.confidence_score, r.completeness_score
                      FROM cbom_assessment_runs r JOIN active b ON b.id = r.bom_id
                     WHERE r.status = 'SUCCEEDED' ORDER BY r.bom_id, r.completed_at DESC NULLS LAST, r.created_at DESC)
                SELECT (SELECT count(*) FROM active), count(*), avg(confidence_score), avg(completeness_score) FROM latest
                """, (rs, row) -> new Object[] {rs.getInt(1), rs.getInt(2), rs.getBigDecimal(3), rs.getBigDecimal(4)}, tenantId);
        Map<String, Integer> claims = new LinkedHashMap<>();
        jdbc.query("""
                WITH latest AS (
                    SELECT DISTINCT ON (r.bom_id) r.id FROM cbom_assessment_runs r
                      JOIN bom_ingestion_records b ON b.id = r.bom_id
                     WHERE r.tenant_id = ? AND b.bom_type = 'CBOM' AND b.status = 'ACTIVE' AND r.status = 'SUCCEEDED'
                     ORDER BY r.bom_id, r.completed_at DESC NULLS LAST, r.created_at DESC)
                SELECT a.assurance_level, count(*) FROM cbom_claim_assurances a JOIN latest l ON l.id = a.assessment_run_id
                 GROUP BY a.assurance_level ORDER BY a.assurance_level
                """, rs -> { claims.put(rs.getString(1), rs.getInt(2)); }, tenantId);
        int active = (Integer) totals[0];
        int assessed = (Integer) totals[1];
        BigDecimal coverage = active == 0 ? null : BigDecimal.valueOf(assessed).divide(BigDecimal.valueOf(active), 5, RoundingMode.HALF_UP);
        return new Assurance(active, assessed, coverage, scale((BigDecimal) totals[2], 5), scale((BigDecimal) totals[3], 5), claims);
    }

    private Remediation remediation() {
        return jdbc.queryForObject("""
                SELECT count(*) FILTER (WHERE status = 'OPEN'),
                       count(*) FILTER (WHERE status = 'OPEN' AND due_at < now()),
                       count(*) FILTER (WHERE status = 'SUPPRESSED'),
                       count(*) FILTER (WHERE status = 'SUPPRESSED' AND suppressed_until >= now() AND suppressed_until < now() + interval '30 days'),
                       count(*) FILTER (WHERE status IN ('RESOLVED', 'AUTO_CLOSED') AND closed_at >= now() - interval '30 days')
                  FROM findings WHERE finding_kind = 'CRYPTO'
                """, (rs, row) -> {
                    int open = rs.getInt(1), overdue = rs.getInt(2);
                    BigDecimal sla = open == 0 ? null : BigDecimal.valueOf(open - overdue).divide(BigDecimal.valueOf(open), 5, RoundingMode.HALF_UP);
                    return new Remediation(open, overdue, sla, rs.getInt(3), rs.getInt(4), rs.getInt(5));
                });
    }

    // ------------------------------------------------------------------ trends

    @Transactional(readOnly = true)
    public Trends trends(Tenant tenant, int days) {
        int window = Math.max(1, Math.min(MAX_TREND_DAYS, days));
        LocalDate today = LocalDate.now(clock);
        List<TrendPoint> points = new ArrayList<>(jdbc.query("""
                SELECT snapshot_date, active_components, active_artifacts, assessed_artifacts, open_critical, open_high,
                       open_medium, open_low, quantum_vulnerable, average_risk_score, average_confidence, average_completeness,
                       open_crypto_findings, overdue_crypto_findings, suppressed_crypto_findings
                  FROM cbom_posture_snapshots WHERE tenant_id = ? AND snapshot_date > ? AND snapshot_date < ?
                 ORDER BY snapshot_date
                """, (rs, row) -> point(rs, false), tenant.getId(), today.minusDays(window), today));
        points.add(live(tenant, today));
        return new Trends(window, points);
    }

    private TrendPoint point(ResultSet rs, boolean live) throws SQLException {
        return new TrendPoint(rs.getObject(1, LocalDate.class), live, rs.getInt(2), rs.getInt(3), rs.getInt(4), rs.getInt(5),
                rs.getInt(6), rs.getInt(7), rs.getInt(8), rs.getInt(9), rs.getBigDecimal(10), rs.getBigDecimal(11),
                rs.getBigDecimal(12), rs.getInt(13), rs.getInt(14), rs.getInt(15));
    }

    private TrendPoint live(Tenant tenant, LocalDate today) {
        Overview o = overview(tenant);
        int components = o.componentsByType().values().stream().mapToInt(Integer::intValue).sum();
        return new TrendPoint(today, true, components, o.assurance().activeArtifacts(), o.assurance().assessedArtifacts(),
                o.risk().openCritical(), o.risk().openHigh(), o.risk().openMedium(), o.risk().openLow(),
                o.pqc().quantumVulnerableFindings(), o.risk().averagePostureScore(), o.assurance().averageConfidence(),
                o.assurance().averageCompleteness(), o.remediation().open(), o.remediation().overdue(), o.remediation().suppressed());
    }

    /** Idempotent per day; called inside the tenant's schema and transaction. */
    public void snapshot(Tenant tenant) {
        LocalDate today = LocalDate.now(clock);
        TrendPoint p = live(tenant, today);
        jdbc.update("""
                INSERT INTO cbom_posture_snapshots (tenant_id, snapshot_date, active_components, active_artifacts, assessed_artifacts,
                    open_critical, open_high, open_medium, open_low, quantum_vulnerable, average_risk_score, average_confidence,
                    average_completeness, open_crypto_findings, overdue_crypto_findings, suppressed_crypto_findings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, snapshot_date) DO UPDATE SET
                    active_components = EXCLUDED.active_components, active_artifacts = EXCLUDED.active_artifacts,
                    assessed_artifacts = EXCLUDED.assessed_artifacts, open_critical = EXCLUDED.open_critical,
                    open_high = EXCLUDED.open_high, open_medium = EXCLUDED.open_medium, open_low = EXCLUDED.open_low,
                    quantum_vulnerable = EXCLUDED.quantum_vulnerable, average_risk_score = EXCLUDED.average_risk_score,
                    average_confidence = EXCLUDED.average_confidence, average_completeness = EXCLUDED.average_completeness,
                    open_crypto_findings = EXCLUDED.open_crypto_findings, overdue_crypto_findings = EXCLUDED.overdue_crypto_findings,
                    suppressed_crypto_findings = EXCLUDED.suppressed_crypto_findings, created_at = now()
                """, tenant.getId(), today, p.activeComponents(), p.activeArtifacts(), p.assessedArtifacts(), p.openCritical(),
                p.openHigh(), p.openMedium(), p.openLow(), p.quantumVulnerable(), p.averageRiskScore(), p.averageConfidence(),
                p.averageCompleteness(), p.openCryptoFindings(), p.overdueCryptoFindings(), p.suppressedCryptoFindings());
        jdbc.update("DELETE FROM cbom_posture_snapshots WHERE tenant_id = ? AND snapshot_date < ?", tenant.getId(),
                today.minusDays(snapshotRetentionDays));
    }

    @Scheduled(cron = "${app.cbom.trends.snapshot-cron:0 30 0 * * *}", zone = "UTC")
    public void scheduledSnapshots() {
        if (!policy.allowsBackgroundTask("cbom-trends.snapshot")) return;
        for (Tenant tenant : TenantContext.runAsPlatform(() -> tenants.listActiveTenants())) {
            try {
                schemas.run(tenant, () -> transactions.execute(tx -> { snapshot(tenant); return null; }));
            } catch (RuntimeException failure) {
                LOG.warn("CBOM posture snapshot failed for tenant {}: {}", tenant.getId(), failure.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------ analyst inventory

    public record InventoryFilter(String assetType, String primitive, String severity, String evidenceState, String custody,
            String environment, UUID assetId, UUID bomId, String query, boolean includeInactive) { }

    @Transactional(readOnly = true)
    public InventoryPage inventory(Tenant tenant, InventoryFilter filter, int page, int size) {
        int boundedSize = Math.max(1, Math.min(MAX_PAGE_SIZE, size));
        int boundedPage = Math.max(0, page);
        List<Object> args = new ArrayList<>();
        String where = where(tenant.getId(), filter, args);
        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(boundedSize + 1);
        pageArgs.add((long) boundedPage * boundedSize);
        List<InventoryItem> rows = new ArrayList<>(jdbc.query(SELECT_ITEM + where
                + " ORDER BY c.risk_score DESC NULLS LAST, c.id LIMIT ? OFFSET ?", (rs, row) -> item(rs), pageArgs.toArray()));
        boolean hasNext = rows.size() > boundedSize;
        if (hasNext) rows.remove(rows.size() - 1);
        List<Object> countArgs = new ArrayList<>(args);
        countArgs.add(TOTAL_CAP + 1);
        long total = jdbc.queryForObject("SELECT count(*) FROM (SELECT 1 FROM cbom_components c"
                + " LEFT JOIN assets a ON a.id = c.asset_id" + where + " LIMIT ?) capped", Long.class, countArgs.toArray());
        boolean capped = total > TOTAL_CAP;
        return new InventoryPage(rows, boundedPage, boundedSize, capped ? TOTAL_CAP : total, capped, hasNext);
    }

    private static final String SELECT_ITEM = """
            SELECT c.id, c.name, c.asset_type, c.primitive, c.key_size, c.curve, c.protocol_version, c.storage_location,
                   c.not_after, c.risk_score, c.asset_id, a.name, a.environment, c.source_bom_id, b.document_name,
                   (SELECT count(*) FROM cbom_risk_findings r WHERE r.cbom_component_id = c.id AND r.status = 'OPEN'
                       AND r.evidence_state <> 'WITHDRAWN'),
                   (SELECT r.severity FROM cbom_risk_findings r WHERE r.cbom_component_id = c.id AND r.status = 'OPEN'
                       AND r.evidence_state <> 'WITHDRAWN'
                     ORDER BY CASE r.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END
                     LIMIT 1),
                   (SELECT r.evidence_state FROM cbom_risk_findings r WHERE r.cbom_component_id = c.id
                     ORDER BY r.last_seen_at DESC NULLS LAST LIMIT 1)
              FROM cbom_components c
              LEFT JOIN assets a ON a.id = c.asset_id
              LEFT JOIN bom_ingestion_records b ON b.id = c.source_bom_id
            """;

    private String where(UUID tenantId, InventoryFilter f, List<Object> args) {
        StringBuilder sql = new StringBuilder(" WHERE c.tenant_id = ?");
        args.add(tenantId);
        if (f == null) return sql.append(" AND c.active").toString();
        if (!f.includeInactive()) sql.append(" AND c.active");
        if (present(f.assetType())) {
            String value = allowed(f.assetType(), ASSET_TYPES, "assetType");
            sql.append(" AND c.asset_type = ?"); args.add(value);
        }
        if (present(f.primitive())) { sql.append(" AND lower(c.primitive) LIKE ?"); args.add(like(f.primitive())); }
        if (present(f.custody())) { sql.append(" AND lower(c.storage_location) LIKE ?"); args.add(like(f.custody())); }
        if (present(f.environment())) { sql.append(" AND lower(a.environment) = ?"); args.add(f.environment().trim().toLowerCase(Locale.ROOT)); }
        if (f.assetId() != null) { sql.append(" AND c.asset_id = ?"); args.add(f.assetId()); }
        if (f.bomId() != null) { sql.append(" AND c.source_bom_id = ?"); args.add(f.bomId()); }
        if (present(f.query())) {
            sql.append(" AND (lower(c.name) LIKE ? OR lower(coalesce(c.bom_ref, '')) LIKE ?)");
            args.add(like(f.query())); args.add(like(f.query()));
        }
        if (present(f.severity())) {
            String value = allowed(f.severity(), SEVERITIES, "severity");
            sql.append(" AND EXISTS (SELECT 1 FROM cbom_risk_findings r WHERE r.cbom_component_id = c.id AND r.status = 'OPEN'"
                    + " AND r.evidence_state <> 'WITHDRAWN' AND r.severity = ?)");
            args.add(value);
        }
        if (present(f.evidenceState())) {
            String value = allowed(f.evidenceState(), EVIDENCE_STATES, "evidenceState");
            sql.append(" AND EXISTS (SELECT 1 FROM cbom_risk_findings r WHERE r.cbom_component_id = c.id AND r.evidence_state = ?)");
            args.add(value);
        }
        return sql.toString();
    }

    private InventoryItem item(ResultSet rs) throws SQLException {
        return new InventoryItem(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4),
                (Integer) rs.getObject(5), rs.getString(6), rs.getString(7), rs.getString(8), rs.getObject(9, LocalDate.class),
                rs.getBigDecimal(10), rs.getObject(11, UUID.class), rs.getString(12), rs.getString(13), rs.getObject(14, UUID.class),
                rs.getString(15), rs.getInt(16), rs.getString(17), rs.getString(18));
    }

    // ------------------------------------------------------------------ evidence drawer

    @Transactional(readOnly = true)
    public ComponentDetail component(Tenant tenant, UUID componentId) {
        List<Object> args = new ArrayList<>(List.of(tenant.getId(), componentId));
        List<InventoryItem> found = jdbc.query(SELECT_ITEM + " WHERE c.tenant_id = ? AND c.id = ?", (rs, row) -> item(rs), args.toArray());
        if (found.isEmpty()) throw new IllegalArgumentException("CBOM component not found");
        InventoryItem item = found.get(0);
        Map<String, Object> properties = jdbc.queryForObject("""
                SELECT bom_ref, component_fingerprint, description, component_type, parameter_set_identifier, padding, state, format,
                       transmission, sensitivity, used_in, not_before, issuer, subject, serial_number, signature_algorithm, key_usage,
                       active, created_at, updated_at
                  FROM cbom_components WHERE id = ?
                """, (rs, row) -> {
                    Map<String, Object> values = new LinkedHashMap<>();
                    var meta = rs.getMetaData();
                    for (int i = 1; i <= meta.getColumnCount(); i++) {
                        Object value = rs.getObject(i);
                        if (value instanceof java.sql.Date d) value = d.toLocalDate();
                        else if (value instanceof Timestamp t) value = t.toInstant();
                        else if (value instanceof java.time.OffsetDateTime o) value = o.toInstant();
                        if (value != null) values.put(camel(meta.getColumnLabel(i)), value);
                    }
                    return values;
                }, componentId);
        List<Provenance> provenance = jdbc.query("""
                SELECT b.id, b.document_name, b.serial_number, b.checksum_sha256, b.source_type, b.source_method, b.source_label,
                       b.status, b.ingested_at, r.id, r.rule_package_id || '@' || r.rule_package_version, r.rule_package_digest,
                       r.evaluator_version, r.completed_at
                  FROM bom_ingestion_records b
                  LEFT JOIN LATERAL (SELECT * FROM cbom_assessment_runs x WHERE x.bom_id = b.id AND x.status = 'SUCCEEDED'
                                      ORDER BY x.completed_at DESC NULLS LAST LIMIT 1) r ON true
                 WHERE b.id = ?
                """, (rs, row) -> new Provenance(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8), instant(rs.getTimestamp(9)),
                        rs.getObject(10, UUID.class), rs.getString(11), rs.getString(12), rs.getString(13), instant(rs.getTimestamp(14))),
                item.sourceBomId());
        Provenance source = provenance.isEmpty() ? null : provenance.get(0);
        List<Claim> claims = source == null || source.assessmentRunId() == null ? List.of() : jdbc.query("""
                SELECT claim_path, assurance_level, evidence_state, explanation FROM cbom_claim_assurances
                 WHERE assessment_run_id = ? AND cbom_component_id = ? ORDER BY claim_path
                """, (rs, row) -> new Claim(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)),
                source.assessmentRunId(), componentId);
        List<FindingEvidence> findings = jdbc.query("""
                SELECT r.id, r.rule_id, r.rule_version, r.severity, r.risk_class, r.title, r.detail, r.evidence::text,
                       r.recommendation, r.status, r.evidence_state, r.first_seen_at, r.last_seen_at,
                       f.id, f.display_id, f.status, f.assigned_to, f.due_at, f.suppressed_until
                  FROM cbom_risk_findings r
                  LEFT JOIN findings f ON f.finding_kind = 'CRYPTO' AND f.fingerprint = 'cbom:' || r.id::text
                 WHERE r.cbom_component_id = ?
                 ORDER BY CASE r.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, r.rule_id
                """, (rs, row) -> new FindingEvidence(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8), rs.getString(9), rs.getString(10),
                        rs.getString(11), instant(rs.getTimestamp(12)), instant(rs.getTimestamp(13)),
                        rs.getObject(14) == null ? null : new CanonicalFinding(rs.getObject(14, UUID.class), rs.getString(15),
                                rs.getString(16), rs.getString(17), instant(rs.getTimestamp(18)), instant(rs.getTimestamp(19)))), componentId);
        List<Relationship> relationships = jdbc.query("""
                SELECT 'OUTBOUND', x.relationship_type, x.target_type, x.target_id, coalesce(t.name, ta.name), x.evidence_kind
                  FROM cbom_relationships x
                  LEFT JOIN cbom_components t ON x.target_type = 'COMPONENT' AND t.id = x.target_id
                  LEFT JOIN assets ta ON x.target_type = 'ASSET' AND ta.id = x.target_id
                 WHERE x.tenant_id = ? AND x.source_type = 'COMPONENT' AND x.source_id = ?
                UNION ALL
                SELECT 'INBOUND', x.relationship_type, x.source_type, x.source_id, coalesce(s.name, sa.name), x.evidence_kind
                  FROM cbom_relationships x
                  LEFT JOIN cbom_components s ON x.source_type = 'COMPONENT' AND s.id = x.source_id
                  LEFT JOIN assets sa ON x.source_type = 'ASSET' AND sa.id = x.source_id
                 WHERE x.tenant_id = ? AND x.target_type = 'COMPONENT' AND x.target_id = ?
                 LIMIT 100
                """, (rs, row) -> new Relationship(rs.getString(1), rs.getString(2), rs.getString(3), rs.getObject(4, UUID.class),
                        rs.getString(5), rs.getString(6)), tenant.getId(), componentId, tenant.getId(), componentId);
        return new ComponentDetail(item, properties, source, claims, findings, relationships);
    }

    private static boolean present(String value) { return value != null && !value.isBlank(); }
    private static String like(String value) {
        return "%" + value.trim().toLowerCase(Locale.ROOT).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
    }
    private static String allowed(String value, Set<String> allowed, String name) {
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if (!allowed.contains(normalized)) throw new IllegalArgumentException("Unsupported " + name + ": " + value);
        return normalized;
    }
    private static BigDecimal scale(BigDecimal value, int places) { return value == null ? null : value.setScale(places, RoundingMode.HALF_UP); }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }
    private static String camel(String snake) {
        StringBuilder out = new StringBuilder();
        boolean upper = false;
        for (char ch : snake.toCharArray()) {
            if (ch == '_') { upper = true; continue; }
            out.append(upper ? Character.toUpperCase(ch) : ch);
            upper = false;
        }
        return out.toString();
    }
}
