package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomAssessmentResponse;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Persisted, reproducible CBOM assessment reports (plan section 5.10): idempotent requests, durable
 * {@code CBOM_REPORT} generation jobs, tenant-local content with checksum and UNSIGNED labelling,
 * audited downloads, regeneration and retention expiry. Reports are only streamed after the
 * caller's current authorization; there are no shareable download URLs.
 */
@Service
public class CbomReportService {
    private static final Logger LOG = LoggerFactory.getLogger(CbomReportService.class);
    public static final String SCHEMA_VERSION = "1.1";
    public static final String UNSIGNED_NOTICE = "Unsigned report — checksum verifies content consistency, not authenticity";

    public record ReportMetadata(UUID id, UUID bomId, UUID assessmentRunId, String format, String status, UUID regeneratedFrom,
            String requestedBy, String schemaVersion, String checksumSha256, String filename, Long sizeBytes, String errorMessage,
            Instant createdAt, Instant completedAt, Instant expiresAt, int downloadCount, Instant lastDownloadedAt,
            String signatureStatus) { }

    public record Download(String contentType, String filename, byte[] content, String checksum) { }

    private final JdbcTemplate jdbc;
    private final CbomAssessmentService assessments;
    private final CbomSemanticDiffService diffs;
    private final CbomRulePackageRegistry registry;
    private final IngestionJobService jobs;
    private final TenantSchemaExecutionService schemas;
    private final TransactionTemplate transactions;
    private final TenantService tenants;
    private final AuditEventService audit;
    private final ObjectMapper mapper;
    private BackgroundTaskExecutionPolicy policy = BackgroundTaskExecutionPolicy.allowAll();
    private Clock clock = Clock.systemUTC();
    private int retentionDays = 90;
    private int maxPendingPerTenant = 20;

    public CbomReportService(JdbcTemplate jdbc, CbomAssessmentService assessments, CbomSemanticDiffService diffs,
            CbomRulePackageRegistry registry, IngestionJobService jobs, TenantSchemaExecutionService schemas,
            TransactionTemplate transactions, TenantService tenants, AuditEventService audit, ObjectMapper mapper) {
        this.jdbc = jdbc; this.assessments = assessments; this.diffs = diffs; this.registry = registry; this.jobs = jobs;
        this.schemas = schemas; this.transactions = transactions; this.tenants = tenants; this.audit = audit; this.mapper = mapper;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy value) {
        policy = value == null ? BackgroundTaskExecutionPolicy.allowAll() : value;
    }
    void setClock(Clock value) { clock = value; }
    @Value("${app.cbom.reports.retention-days:90}") public void setRetentionDays(int value) { retentionDays = Math.max(1, value); }
    @Value("${app.cbom.reports.max-pending-per-tenant:20}") public void setMaxPendingPerTenant(int value) { maxPendingPerTenant = Math.max(1, value); }

    // ------------------------------------------------------------------ requests (HTTP, tenant context already set)

    public ReportMetadata request(Tenant tenant, UUID bomId, UUID runId, String format, String idempotencyKey, String actor) {
        return request(tenant, bomId, runId, format, idempotencyKey, actor, null);
    }

    public ReportMetadata regenerate(Tenant tenant, UUID bomId, UUID reportId, String idempotencyKey, String actor) {
        ReportMetadata source = get(tenant, bomId, reportId);
        return request(tenant, bomId, source.assessmentRunId(), source.format(), idempotencyKey, actor, reportId);
    }

    private ReportMetadata request(Tenant tenant, UUID bomId, UUID runId, String format, String idempotencyKey, String actor, UUID from) {
        String normalizedFormat = format(format);
        String key = idempotencyKey(idempotencyKey);
        record Admission(ReportMetadata metadata, boolean created) { }
        Admission admission = transactions.execute(tx -> {
            CbomAssessmentResponse run = assessments.get(tenant, runId);
            if (!run.bomId().equals(bomId)) throw new IllegalArgumentException("The assessment does not belong to this CBOM");
            if (!"SUCCEEDED".equals(run.status())) throw new IllegalArgumentException("Reports require a successful assessment");
            UUID id = UUID.randomUUID();
            int inserted = jdbc.update("""
                    INSERT INTO cbom_report_artifacts (id, tenant_id, bom_id, assessment_run_id, format, idempotency_key,
                        regenerated_from, requested_by)
                    SELECT ?, ?, ?, ?, ?, ?, ?, ?
                     WHERE (SELECT count(*) FROM cbom_report_artifacts WHERE tenant_id = ? AND status IN ('QUEUED', 'GENERATING')) < ?
                    ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
                    """, id, tenant.getId(), bomId, runId, normalizedFormat, key, from, actor, tenant.getId(), maxPendingPerTenant);
            List<ReportMetadata> existing = jdbc.query(SELECT_METADATA + " WHERE tenant_id = ? AND idempotency_key = ?",
                    (rs, row) -> metadata(rs), tenant.getId(), key);
            if (existing.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                        "Too many CBOM reports are already being generated for this workspace; retry shortly");
            }
            ReportMetadata row = existing.get(0);
            if (!row.bomId().equals(bomId) || !row.assessmentRunId().equals(runId) || !row.format().equals(normalizedFormat)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "The idempotency key was already used for a different report");
            }
            if (inserted == 1) {
                audit.record(from == null ? "cbom.report.requested" : "cbom.report.regenerated", "cbom_report", id.toString(),
                        "{\"bomId\":\"" + bomId + "\",\"assessmentRunId\":\"" + runId + "\",\"format\":\"" + normalizedFormat + "\"}");
            }
            return new Admission(row, inserted == 1);
        });
        if (admission.created()) jobs.enqueueCbomReportJob(tenant, admission.metadata().id(), actor);
        return admission.metadata();
    }

    public List<ReportMetadata> list(Tenant tenant, UUID bomId) {
        return transactions.execute(tx -> jdbc.query(SELECT_METADATA + " WHERE tenant_id = ? AND bom_id = ? ORDER BY created_at DESC LIMIT 100",
                (rs, row) -> metadata(rs), tenant.getId(), bomId));
    }

    public ReportMetadata get(Tenant tenant, UUID bomId, UUID reportId) {
        return transactions.execute(tx -> jdbc.query(SELECT_METADATA + " WHERE tenant_id = ? AND bom_id = ? AND id = ?",
                (rs, row) -> metadata(rs), tenant.getId(), bomId, reportId).stream().findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "CBOM report not found")));
    }

    /** Streams content only for READY reports and audits every download. */
    public Download download(Tenant tenant, UUID bomId, UUID reportId, String actor) {
        return transactions.execute(tx -> {
            ReportMetadata row = get(tenant, bomId, reportId);
            if ("EXPIRED".equals(row.status())) throw new ResponseStatusException(HttpStatus.GONE, "The CBOM report expired under the retention policy; regenerate it");
            if (!"READY".equals(row.status())) throw new ResponseStatusException(HttpStatus.CONFLICT, "The CBOM report is not ready");
            byte[] content = jdbc.queryForObject("SELECT content FROM cbom_report_artifacts WHERE id = ?", byte[].class, reportId);
            String contentType = jdbc.queryForObject("SELECT content_type FROM cbom_report_artifacts WHERE id = ?", String.class, reportId);
            jdbc.update("""
                    UPDATE cbom_report_artifacts SET download_count = download_count + 1, last_downloaded_at = now(), last_downloaded_by = ?
                     WHERE id = ?
                    """, actor, reportId);
            audit.record("cbom.report.downloaded", "cbom_report", reportId.toString(),
                    "{\"bomId\":\"" + bomId + "\",\"checksumSha256\":\"" + row.checksumSha256() + "\"}");
            return new Download(contentType, row.filename(), content, row.checksumSha256());
        });
    }

    // ------------------------------------------------------------------ generation (worker; tenant context + tx by caller)

    /** Generates one report. Idempotent: anything but QUEUED/GENERATING is left alone. */
    public void generate(Tenant tenant, UUID reportId) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT bom_id, assessment_run_id, format, status FROM cbom_report_artifacts WHERE id = ? FOR UPDATE", reportId);
        if (rows.isEmpty()) throw new IllegalArgumentException("CBOM report not found");
        Map<String, Object> row = rows.get(0);
        String status = (String) row.get("status");
        if (!"QUEUED".equals(status) && !"GENERATING".equals(status)) return;
        jdbc.update("UPDATE cbom_report_artifacts SET status = 'GENERATING' WHERE id = ?", reportId);
        UUID bomId = (UUID) row.get("bom_id");
        UUID runId = (UUID) row.get("assessment_run_id");
        String format = (String) row.get("format");
        Instant generatedAt = Instant.now(clock);
        Map<String, Object> body = body(tenant, reportId, bomId, runId, generatedAt);
        String canonical = write(body);
        String checksum = sha256(canonical);
        body.put("checksumSha256", checksum);
        byte[] content;
        String contentType;
        String filename;
        if ("HTML".equals(format)) {
            content = html(body, checksum).getBytes(StandardCharsets.UTF_8);
            contentType = "text/html;charset=UTF-8";
            filename = "cbom-assessment-" + runId + ".html";
        } else {
            content = write(body).getBytes(StandardCharsets.UTF_8);
            contentType = "application/json";
            filename = "cbom-assessment-" + runId + ".json";
        }
        jdbc.update("""
                UPDATE cbom_report_artifacts SET status = 'READY', schema_version = ?, checksum_sha256 = ?, content_type = ?,
                       filename = ?, size_bytes = ?, content = ?, error_message = NULL, completed_at = ?, expires_at = ?
                 WHERE id = ?
                """, SCHEMA_VERSION, checksum, contentType, filename, (long) content.length, content, Timestamp.from(generatedAt),
                Timestamp.from(generatedAt.plus(Duration.ofDays(retentionDays))), reportId);
    }

    public void markFailed(UUID reportId, String message) {
        jdbc.update("UPDATE cbom_report_artifacts SET status = 'FAILED', error_message = ?, completed_at = now() WHERE id = ? AND status <> 'READY'",
                message == null ? "Report generation failed" : message.substring(0, Math.min(500, message.length())), reportId);
    }

    /** The assessment record contract. Values are data only; HTML rendering escapes every string. */
    Map<String, Object> body(Tenant tenant, UUID reportId, UUID bomId, UUID runId, Instant generatedAt) {
        CbomAssessmentResponse run = assessments.get(tenant, runId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", SCHEMA_VERSION);
        body.put("signatureStatus", "UNSIGNED");
        body.put("limitation", "Checksum verifies content consistency, not authenticity");
        body.put("reportId", reportId);
        body.put("generatedAt", generatedAt);
        body.put("customer", jdbc.queryForMap("SELECT id AS \"tenantId\", name AS \"tenantName\" FROM platform.tenants WHERE id = ?", tenant.getId()));
        body.put("source", jdbc.queryForMap("""
                SELECT b.id AS "bomId", b.document_name AS "documentName", b.serial_number AS "serialNumber",
                       b.checksum_sha256 AS "checksumSha256", b.status AS "status", b.ingested_at AS "ingestedAt",
                       a.id AS "assetId", a.name AS "assetName", a.environment AS "environment"
                  FROM bom_ingestion_records b LEFT JOIN assets a ON a.id = b.asset_id WHERE b.id = ?
                """, bomId));
        body.put("assessment", run);
        Map<String, Integer> assurance = new LinkedHashMap<>();
        Map<String, Integer> presence = new LinkedHashMap<>();
        for (var claim : run.claimAssurances()) {
            assurance.merge(claim.assuranceLevel(), 1, Integer::sum);
            presence.merge(claim.evidenceState(), 1, Integer::sum);
        }
        body.put("assuranceSummary", assurance);
        body.put("presenceSummary", presence);
        body.put("findings", jdbc.queryForList("""
                SELECT r.rule_id AS "ruleId", r.rule_version AS "ruleVersion", r.severity AS "severity", r.risk_class AS "riskClass",
                       r.title AS "title", r.status AS "status", r.evidence_state AS "evidenceState",
                       r.recommendation AS "recommendation", c.name AS "component",
                       f.display_id AS "findingDisplayId", f.status AS "findingStatus", f.assigned_to AS "owner",
                       f.due_at AS "dueAt", f.suppression_reason AS "suppressionReason", f.suppressed_until AS "suppressedUntil",
                       (SELECT q.decided_by FROM finding_suppression_requests q WHERE q.finding_id = f.id AND q.status = 'APPROVED'
                         ORDER BY q.decided_at DESC LIMIT 1) AS "suppressionApprovedBy"
                  FROM cbom_risk_findings r JOIN cbom_components c ON c.id = r.cbom_component_id
                  LEFT JOIN findings f ON f.finding_kind = 'CRYPTO' AND f.fingerprint = 'cbom:' || r.id::text
                 WHERE c.source_bom_id = ?
                 ORDER BY CASE r.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                          r.rule_id, c.name
                """, bomId));
        var diff = diffs.diff(tenant, bomId, null);
        Map<String, Object> changes = new LinkedHashMap<>();
        changes.put("baselineBomId", diff.baselineBomId());
        changes.put("baselineSource", diff.baselineSource());
        changes.put("componentSummary", diff.componentSummary());
        changes.put("findingSummary", diff.findingSummary());
        body.put("changesFromPrevious", changes);
        boolean executable = registry.find(run.rulePackageId(), run.rulePackageVersion())
                .map(p -> CbomRulePackageRegistry.SUPPORTED_EVALUATOR_MAJORS.contains(p.evaluatorMajor()) && !p.retired(generatedAt))
                .orElse(false);
        Map<String, Object> reproducibility = new LinkedHashMap<>();
        reproducibility.put("rulePackage", run.rulePackageId() + "@" + run.rulePackageVersion());
        reproducibility.put("rulePackageDigest", run.rulePackageDigest());
        reproducibility.put("evaluatorVersion", run.evaluatorVersion());
        reproducibility.put("artifactChecksum", run.artifactChecksum());
        reproducibility.put("reExecutionSupported", executable);
        reproducibility.put("label", executable ? "REPRODUCIBLE_WITHIN_SUPPORT_WINDOW" : "HISTORICAL_UNSUPPORTED_FOR_RE_EXECUTION");
        body.put("reproducibility", reproducibility);
        body.put("limitations", List.of(
                "Claims the CBOM did not declare are reported as UNKNOWN assurance, not as failed controls.",
                "Assurance levels reflect submitted CBOM evidence only; no runtime collector evidence is included.",
                "No external enrichment steps run during assessment; none failed.",
                "Exact re-execution is promised only while the recorded evaluator and rule package remain supported."));
        return body;
    }

    // The casts below are safe: body() builds every one of these values with exactly these types.
    private String html(Map<String, Object> body, String checksum) {
        @SuppressWarnings("unchecked") Map<String, Object> source = (Map<String, Object>) body.get("source");
        @SuppressWarnings("unchecked") Map<String, Object> customer = (Map<String, Object>) body.get("customer");
        @SuppressWarnings("unchecked") Map<String, Object> reproducibility = (Map<String, Object>) body.get("reproducibility");
        @SuppressWarnings("unchecked") List<Map<String, Object>> findings = (List<Map<String, Object>>) body.get("findings");
        @SuppressWarnings("unchecked") List<String> limitations = (List<String>) body.get("limitations");
        CbomAssessmentResponse run = (CbomAssessmentResponse) body.get("assessment");
        StringBuilder out = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">")
                .append("<title>CBOM Assessment</title><style>body{font-family:sans-serif;margin:2rem;max-width:72rem}")
                .append("table{border-collapse:collapse;width:100%}td,th{border:1px solid #999;padding:4px;text-align:left}</style></head><body>")
                .append("<h1>Cryptographic Security Assessment</h1><p role=\"note\"><strong>").append(escape(UNSIGNED_NOTICE)).append("</strong></p><dl>");
        dl(out, "Customer", customer.get("tenantName"));
        dl(out, "Asset", source.get("assetName"));
        dl(out, "Environment", source.get("environment"));
        dl(out, "Source CBOM", source.get("documentName"));
        dl(out, "Serial number", source.get("serialNumber"));
        dl(out, "Source SHA-256", source.get("checksumSha256"));
        dl(out, "Assessed at", run.completedAt());
        dl(out, "Rule package", reproducibility.get("rulePackage") + " (" + reproducibility.get("rulePackageDigest") + ")");
        dl(out, "Evaluator", run.evaluatorVersion());
        dl(out, "Validation", run.validationOutcome());
        dl(out, "Completeness", run.completenessScore());
        dl(out, "Confidence", run.confidenceScore());
        dl(out, "Reproducibility", reproducibility.get("label"));
        dl(out, "Generated at", body.get("generatedAt"));
        dl(out, "Report checksum (SHA-256)", checksum);
        out.append("</dl><h2>Assurance</h2><p>").append(escape(String.valueOf(body.get("assuranceSummary"))))
                .append("</p><p>Evidence presence: ").append(escape(String.valueOf(body.get("presenceSummary")))).append("</p>")
                .append("<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Component</th><th>Title</th>")
                .append("<th>Status</th><th>Owner</th><th>Suppression</th></tr></thead><tbody>");
        for (Map<String, Object> f : findings) {
            out.append("<tr><td>").append(escape(f.get("severity"))).append("</td><td>").append(escape(f.get("ruleId")))
                    .append("</td><td>").append(escape(f.get("component"))).append("</td><td>").append(escape(f.get("title")))
                    .append("</td><td>").append(escape(f.get("findingStatus") == null ? f.get("status") : f.get("findingStatus")))
                    .append("</td><td>").append(escape(f.get("owner"))).append("</td><td>")
                    .append(f.get("suppressionReason") == null ? "" : escape(f.get("suppressionReason") + " until " + f.get("suppressedUntil")
                            + (f.get("suppressionApprovedBy") == null ? "" : " (approved by " + f.get("suppressionApprovedBy") + ")")))
                    .append("</td></tr>");
        }
        out.append("</tbody></table><h2>Changes from the preceding CBOM</h2><p>").append(escape(String.valueOf(body.get("changesFromPrevious"))))
                .append("</p><h2>Validation issues</h2><ul>");
        run.validationIssues().forEach(v -> out.append("<li>").append(escape(v.code() + " " + v.jsonPointer() + ": " + v.message())).append("</li>"));
        out.append("</ul><h2>Assumptions and limitations</h2><ul>");
        limitations.forEach(l -> out.append("<li>").append(escape(l)).append("</li>"));
        return out.append("</ul></body></html>").toString();
    }

    // ------------------------------------------------------------------ retention

    @Scheduled(fixedDelayString = "${app.cbom.reports.retention-interval-ms:3600000}", initialDelayString = "${app.cbom.reports.retention-initial-delay-ms:300000}")
    public void scheduledRetention() {
        if (!policy.allowsBackgroundTask("cbom-reports.retention")) return;
        for (Tenant tenant : TenantContext.runAsPlatform(() -> tenants.listActiveTenants())) {
            try { expire(tenant); }
            catch (RuntimeException failure) { LOG.warn("CBOM report retention failed for tenant {}: {}", tenant.getId(), failure.getMessage()); }
        }
    }

    /** Clears content of reports past retention and marks them EXPIRED; metadata and audit remain. */
    public int expire(Tenant tenant) {
        return schemas.run(tenant, () -> transactions.execute(tx -> jdbc.update("""
                UPDATE cbom_report_artifacts SET status = 'EXPIRED', content = NULL
                 WHERE tenant_id = ? AND status = 'READY' AND expires_at < ?
                """, tenant.getId(), Timestamp.from(Instant.now(clock)))));
    }

    // ------------------------------------------------------------------ helpers

    private static final String SELECT_METADATA = """
            SELECT id, bom_id, assessment_run_id, format, status, regenerated_from, requested_by, schema_version, checksum_sha256,
                   filename, size_bytes, error_message, created_at, completed_at, expires_at, download_count, last_downloaded_at
              FROM cbom_report_artifacts""";

    private static ReportMetadata metadata(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new ReportMetadata(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getObject(3, UUID.class), rs.getString(4),
                rs.getString(5), rs.getObject(6, UUID.class), rs.getString(7), rs.getString(8), rs.getString(9), rs.getString(10),
                (Long) rs.getObject(11), rs.getString(12), instant(rs.getTimestamp(13)), instant(rs.getTimestamp(14)),
                instant(rs.getTimestamp(15)), rs.getInt(16), instant(rs.getTimestamp(17)), "UNSIGNED");
    }

    private static String format(String format) {
        String value = format == null ? "JSON" : format.trim().toUpperCase(Locale.ROOT);
        if (!List.of("JSON", "HTML").contains(value)) throw new IllegalArgumentException("Unsupported report format: " + format);
        return value;
    }

    private static String idempotencyKey(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Idempotency-Key is required");
        String trimmed = value.trim();
        if (trimmed.length() > 120 || !trimmed.matches("[A-Za-z0-9._:-]+")) throw new IllegalArgumentException("Idempotency-Key must be 1-120 URL-safe characters");
        return trimmed;
    }

    private static void dl(StringBuilder out, String term, Object value) {
        out.append("<dt>").append(escape(term)).append("</dt><dd>").append(escape(value)).append("</dd>");
    }

    static String escape(Object value) {
        if (value == null) return "";
        return value.toString().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    private String write(Object value) {
        try { return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(value); }
        catch (Exception e) { throw new IllegalStateException("Report generation failed", e); }
    }

    private static String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }
}
