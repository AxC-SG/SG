package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.service.CampaignService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.ticketing.TicketRef;
import com.prototype.vulnwatch.ticketing.TicketRequest;
import com.prototype.vulnwatch.ticketing.TicketingService;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Remediation operations for CRYPTO findings (plan Milestone 3): crypto ticket templates with an
 * attempt history for retry visibility, verification and SLA queues, remediation-effectiveness
 * reporting, and campaigns created from findings with optional bulk assignment. Canonical findings
 * keep owning workflow; nothing here writes suppression or resolution state directly.
 */
@Service
public class CryptoRemediationService {
    public static final int MAX_EFFECTIVENESS_DAYS = 365;
    private static final String SEVERITY = "upper(coalesce(f.severity_override, 'UNKNOWN'))";

    public record TicketAttempt(UUID id, String provider, String template, String outcome, String ticketKey,
            String errorMessage, String attemptedBy, Instant attemptedAt) { }

    public record QueueItem(UUID findingId, String displayId, String title, String severity, String status, String assignedTo,
            String ownerGroup, Instant dueAt, String workflowSubstate, String verificationStatus, String targetState,
            Instant verificationRequestedAt, boolean overdue) { }

    public record SeveritySla(String severity, int open, int overdue, int dueWithin7Days, int unassigned) { }

    public record RemediationQueue(Instant observedAt, List<QueueItem> verificationQueue, List<QueueItem> overdue,
            List<SeveritySla> slaBySeverity) { }

    public record SeverityEffectiveness(String severity, int closed, BigDecimal meanDaysToClose, BigDecimal closedWithinSla) { }

    public record Effectiveness(int days, LocalDate from, LocalDate to, int opened, int closed, int verifiedClosures,
            int reopened, int verificationsAccepted, int verificationsRejected, BigDecimal verificationAcceptanceRate,
            Map<String, Integer> closuresByReason, List<SeverityEffectiveness> bySeverity) { }

    private final JdbcTemplate jdbc;
    private final TicketingService ticketing;
    private final CampaignService campaigns;
    private final FindingWorkflowService workflow;
    private final ObjectMapper mapper;
    private final TransactionTemplate independent;

    public CryptoRemediationService(JdbcTemplate jdbc, TicketingService ticketing, CampaignService campaigns,
            FindingWorkflowService workflow, ObjectMapper mapper, PlatformTransactionManager transactions) {
        this.jdbc = jdbc; this.ticketing = ticketing; this.campaigns = campaigns; this.workflow = workflow; this.mapper = mapper;
        this.independent = new TransactionTemplate(transactions);
        this.independent.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    // ------------------------------------------------------------------ tickets

    /** Raises a ticket (crypto template for CRYPTO findings) and records the attempt, including failures. */
    public TicketRef createTicket(Tenant tenant, UUID findingId, TicketRequest request, String actor) {
        String kind = findingKind(findingId);
        boolean crypto = "CRYPTO".equals(kind);
        TicketRequest effective = crypto ? merge(template(findingId), request) : request;
        String provider = ticketing.status(tenant).active() == null ? null : ticketing.status(tenant).active().key();
        try {
            TicketRef ref = ticketing.createTicketForFinding(tenant, findingId, effective);
            record(findingId, ref.system().key(), crypto ? "CRYPTO" : "DEFAULT", "SUCCEEDED", ref.externalKey(), null, actor);
            return ref;
        } catch (RuntimeException failure) {
            String message = failure instanceof ResponseStatusException status ? status.getReason() : failure.getMessage();
            record(findingId, provider, crypto ? "CRYPTO" : "DEFAULT", "FAILED", null, message, actor);
            throw failure;
        }
    }

    public List<TicketAttempt> attempts(UUID findingId) {
        findingKind(findingId);
        return jdbc.query("""
                SELECT id, provider, template, outcome, ticket_key, error_message, attempted_by, attempted_at
                  FROM finding_ticket_attempts WHERE finding_id = ? ORDER BY attempted_at DESC LIMIT 50
                """, (rs, row) -> new TicketAttempt(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getString(6), rs.getString(7), rs.getTimestamp(8).toInstant()), findingId);
    }

    /** The provider-neutral ticket a CRYPTO finding produces: exact evidence, rule reasoning, target and verification steps. */
    public TicketRequest template(UUID findingId) {
        Map<String, Object> finding = jdbc.queryForMap("""
                SELECT f.display_id, f.title, f.severity_override, f.due_at, f.assigned_to, f.owner_group, f.target_state,
                       f.evidence::text AS evidence, f.finding_kind, a.name AS asset_name, a.environment
                  FROM findings f LEFT JOIN assets a ON a.id = f.asset_id WHERE f.id = ?
                """, findingId);
        if (!"CRYPTO".equals(finding.get("finding_kind"))) {
            throw new IllegalArgumentException("Crypto ticket templates are only available for CRYPTO findings");
        }
        JsonNode evidence = readTree((String) finding.get("evidence"));
        Map<String, Object> source = cbomSource(evidence.path("cbomFindingId").asText(null));
        String component = text(source.get("component_name"), evidence.path("assetName").asText(null));
        String asset = (String) finding.get("asset_name");
        String severity = (String) finding.get("severity_override");
        StringBuilder notes = new StringBuilder();
        notes.append("Cryptographic finding ").append(finding.get("display_id")).append('\n');
        line(notes, "Service / asset", asset == null ? null : asset + (finding.get("environment") == null ? "" : " (" + finding.get("environment") + ")"));
        line(notes, "Component", component);
        line(notes, "Asset type", text(source.get("asset_type"), evidence.path("assetType").asText(null)));
        line(notes, "Algorithm / parameters", join(source.get("primitive"), source.get("key_size") == null ? null : source.get("key_size") + "-bit",
                source.get("curve"), source.get("protocol_version")));
        line(notes, "Custody", (String) source.get("storage_location"));
        line(notes, "Rule", text(source.get("rule_id"), evidence.path("ruleId").asText(null))
                + (source.get("rule_version") == null ? "" : " v" + source.get("rule_version")));
        line(notes, "Rule package", (String) source.get("rule_package"));
        line(notes, "Why", text(source.get("detail"), evidence.path("detail").asText(null)));
        line(notes, "Source CBOM", join(source.get("document_name"), source.get("checksum_sha256") == null ? null : "sha256 " + source.get("checksum_sha256")));
        StringBuilder solution = new StringBuilder();
        line(solution, "Recommendation", (String) source.get("recommendation"));
        line(solution, "Target state", text(finding.get("target_state"), "The rule above no longer fires for this component."));
        solution.append("Verification steps:\n")
                .append("1. Deploy the change and publish an updated CBOM for this application.\n")
                .append("2. Confirm the next CBOM assessment no longer reports ").append(text(source.get("rule_id"), "this rule")).append(" for this component.\n")
                .append("3. Request verification on the ScoutGrid finding with the assessment run ID as evidence.\n");
        Object due = finding.get("due_at");
        String dueDate = due instanceof Timestamp t ? LocalDate.ofInstant(t.toInstant(), ZoneOffset.UTC).toString() : null;
        String title = "[Crypto][" + (severity == null ? "UNKNOWN" : severity) + "] " + finding.get("title")
                + (component == null ? "" : " — " + component) + (asset == null ? "" : " (" + asset + ")");
        // Assignee and assignment group are provider-native identifiers, so they stay with the provider's own derivation.
        line(notes, "ScoutGrid owner", join(finding.get("assigned_to"), finding.get("owner_group")));
        return new TicketRequest(truncate(title, 240), severity, null, dueDate, null, null,
                truncate(notes.toString(), 8000), truncate(solution.toString(), 8000));
    }

    private Map<String, Object> cbomSource(String cbomFindingId) {
        if (cbomFindingId == null) return Map.of();
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT r.rule_id, r.rule_version, r.detail, r.recommendation, c.name AS component_name, c.asset_type, c.primitive,
                       c.key_size, c.curve, c.protocol_version, c.storage_location, b.document_name, b.checksum_sha256,
                       (SELECT x.rule_package_id || '@' || x.rule_package_version FROM cbom_assessment_runs x
                         WHERE x.bom_id = b.id AND x.status = 'SUCCEEDED' ORDER BY x.completed_at DESC NULLS LAST LIMIT 1) AS rule_package
                  FROM cbom_risk_findings r JOIN cbom_components c ON c.id = r.cbom_component_id
                  LEFT JOIN bom_ingestion_records b ON b.id = c.source_bom_id
                 WHERE r.id = ?::uuid
                """, cbomFindingId);
        return rows.isEmpty() ? Map.of() : rows.get(0);
    }

    /** Caller-supplied fields win; the template fills only what the caller left blank. */
    static TicketRequest merge(TicketRequest template, TicketRequest request) {
        if (request == null) return template;
        return new TicketRequest(pick(request.title(), template.title()), pick(request.severity(), template.severity()),
                pick(request.priority(), template.priority()), pick(request.dueDate(), template.dueDate()),
                pick(request.assignee(), template.assignee()), pick(request.assignmentGroup(), template.assignmentGroup()),
                pick(request.notes(), template.notes()), pick(request.solutionInfo(), template.solutionInfo()));
    }

    /** Recorded in its own transaction so a failed ticket push still leaves a visible attempt. */
    private void record(UUID findingId, String provider, String template, String outcome, String key, String error, String actor) {
        independent.executeWithoutResult(tx -> jdbc.update("""
                INSERT INTO finding_ticket_attempts (id, finding_id, provider, template, outcome, ticket_key, error_message, attempted_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, UUID.randomUUID(), findingId, provider, template, outcome, key, truncate(error, 500), actor == null ? "api" : actor));
    }

    // ------------------------------------------------------------------ queues and SLA

    public RemediationQueue queue() {
        List<QueueItem> verification = jdbc.query(QUEUE_SELECT + """
                 WHERE f.finding_kind = 'CRYPTO' AND f.status = 'OPEN' AND f.verification_status = 'REQUESTED'
                 ORDER BY f.verification_requested_at NULLS LAST, f.display_id LIMIT 200
                """, (rs, row) -> item(rs));
        List<QueueItem> overdue = jdbc.query(QUEUE_SELECT + """
                 WHERE f.finding_kind = 'CRYPTO' AND f.status = 'OPEN' AND f.due_at < now()
                 ORDER BY f.due_at, f.display_id LIMIT 200
                """, (rs, row) -> item(rs));
        List<SeveritySla> sla = jdbc.query("SELECT " + SEVERITY + """
                , count(*), count(*) FILTER (WHERE f.due_at < now()),
                       count(*) FILTER (WHERE f.due_at >= now() AND f.due_at < now() + interval '7 days'),
                       count(*) FILTER (WHERE f.assigned_to IS NULL AND f.owner_group IS NULL)
                  FROM findings f WHERE f.finding_kind = 'CRYPTO' AND f.status = 'OPEN'
                 GROUP BY 1
                """, (rs, row) -> new SeveritySla(rs.getString(1), rs.getInt(2), rs.getInt(3), rs.getInt(4), rs.getInt(5)));
        List<SeveritySla> ordered = new ArrayList<>(sla);
        ordered.sort(java.util.Comparator.comparingInt(s -> rank(s.severity())));
        return new RemediationQueue(Instant.now(), verification, overdue, ordered);
    }

    private static final String QUEUE_SELECT = """
            SELECT f.id, f.display_id, f.title, f.severity_override, f.status, f.assigned_to, f.owner_group, f.due_at,
                   f.workflow_substate, f.verification_status, f.target_state, f.verification_requested_at,
                   f.due_at IS NOT NULL AND f.due_at < now()
              FROM findings f""";

    private static QueueItem item(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new QueueItem(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5),
                rs.getString(6), rs.getString(7), instant(rs.getTimestamp(8)), rs.getString(9), rs.getString(10), rs.getString(11),
                instant(rs.getTimestamp(12)), rs.getBoolean(13));
    }

    // ------------------------------------------------------------------ effectiveness

    public Effectiveness effectiveness(int days) {
        int window = Math.max(1, Math.min(MAX_EFFECTIVENESS_DAYS, days));
        Timestamp since = Timestamp.from(Instant.now().minusSeconds(window * 86_400L));
        Integer opened = jdbc.queryForObject("SELECT count(*) FROM findings WHERE finding_kind = 'CRYPTO' AND created_at >= ?", Integer.class, since);
        Map<String, Integer> reasons = new LinkedHashMap<>();
        jdbc.query("""
                SELECT coalesce(closed_reason, status), count(*) FROM findings
                 WHERE finding_kind = 'CRYPTO' AND status IN ('RESOLVED', 'AUTO_CLOSED') AND closed_at >= ?
                 GROUP BY 1 ORDER BY 2 DESC, 1
                """, rs -> { reasons.put(rs.getString(1), rs.getInt(2)); }, since);
        int closed = reasons.values().stream().mapToInt(Integer::intValue).sum();
        Map<String, Integer> events = new LinkedHashMap<>();
        jdbc.query("""
                SELECT e.event_type, count(*) FROM finding_events e JOIN findings f ON f.id = e.finding_id
                 WHERE f.finding_kind = 'CRYPTO' AND e.created_at >= ?
                   AND (e.event_type LIKE '%REOPEN%' OR e.event_type IN ('VERIFICATION_ACCEPTED', 'VERIFICATION_REJECTED'))
                 GROUP BY e.event_type
                """, rs -> { events.put(rs.getString(1), rs.getInt(2)); }, since);
        int reopened = events.entrySet().stream().filter(e -> e.getKey().contains("REOPEN")).mapToInt(Map.Entry::getValue).sum();
        int accepted = events.getOrDefault("VERIFICATION_ACCEPTED", 0);
        int rejected = events.getOrDefault("VERIFICATION_REJECTED", 0);
        List<SeverityEffectiveness> bySeverity = new ArrayList<>(jdbc.query("SELECT " + SEVERITY + """
                , count(*), avg(extract(epoch FROM (f.closed_at - coalesce(f.first_observed_at, f.created_at))) / 86400.0),
                       count(*) FILTER (WHERE f.due_at IS NOT NULL AND f.closed_at <= f.due_at),
                       count(*) FILTER (WHERE f.due_at IS NOT NULL)
                  FROM findings f WHERE f.finding_kind = 'CRYPTO' AND f.status IN ('RESOLVED', 'AUTO_CLOSED') AND f.closed_at >= ?
                 GROUP BY 1
                """, (rs, row) -> new SeverityEffectiveness(rs.getString(1), rs.getInt(2),
                        rs.getBigDecimal(3) == null ? null : rs.getBigDecimal(3).setScale(2, RoundingMode.HALF_UP),
                        rs.getInt(5) == 0 ? null : BigDecimal.valueOf(rs.getInt(4)).divide(BigDecimal.valueOf(rs.getInt(5)), 5, RoundingMode.HALF_UP)),
                since));
        bySeverity.sort(java.util.Comparator.comparingInt(s -> rank(s.severity())));
        int verified = reasons.entrySet().stream().filter(e -> e.getKey() != null && e.getKey().toUpperCase().contains("VERIF"))
                .mapToInt(Map.Entry::getValue).sum();
        LocalDate to = LocalDate.now(ZoneOffset.UTC);
        return new Effectiveness(window, to.minusDays(window), to, opened == null ? 0 : opened, closed, verified, reopened, accepted, rejected,
                accepted + rejected == 0 ? null : BigDecimal.valueOf(accepted).divide(BigDecimal.valueOf(accepted + rejected), 5, RoundingMode.HALF_UP),
                reasons, bySeverity);
    }

    // ------------------------------------------------------------------ campaigns

    /** Creates a campaign from findings and, when an owner is given, assigns them with the campaign due date. */
    public CampaignDetailResponse createCampaign(Tenant tenant, CampaignFromFindingsRequest request, String actor) {
        boolean assigning = request != null && (notBlank(request.assignedTo()) || notBlank(request.ownerGroup()));
        if (assigning && request.dueAt() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "dueAt is required when assigning the campaign's findings");
        }
        CampaignDetailResponse created = campaigns.createFromFindings(tenant, request, actor);
        if (assigning) {
            workflow.updateWorkflowBulkByIds(request.findingIds().stream().distinct().toList(), new FindingWorkflowUpdateRequest(
                    null, notBlank(request.assignedTo()) ? request.assignedTo() : null,
                    notBlank(request.ownerGroup()) ? request.ownerGroup() : null, request.dueAt(), null, null, actor));
        }
        return created;
    }

    // ------------------------------------------------------------------ helpers

    private String findingKind(UUID findingId) {
        List<String> kinds = jdbc.queryForList("SELECT finding_kind FROM findings WHERE id = ?", String.class, findingId);
        if (kinds.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Finding not found");
        return kinds.get(0);
    }

    private JsonNode readTree(String json) {
        try { return json == null ? mapper.createObjectNode() : mapper.readTree(json); }
        catch (Exception invalid) { return mapper.createObjectNode(); }
    }

    private static int rank(String severity) {
        return switch (severity == null ? "" : severity) {
            case "CRITICAL" -> 0; case "HIGH" -> 1; case "MEDIUM" -> 2; case "LOW" -> 3; default -> 4;
        };
    }

    private static void line(StringBuilder out, String label, String value) {
        if (value != null && !value.isBlank() && !"null".equals(value)) out.append(label).append(": ").append(value).append('\n');
    }

    private static String join(Object... parts) {
        List<String> values = new ArrayList<>();
        for (Object part : parts) if (part != null && !part.toString().isBlank()) values.add(part.toString());
        return values.isEmpty() ? null : String.join(" · ", values);
    }

    private static String text(Object value, String fallback) {
        return value == null || value.toString().isBlank() ? fallback : value.toString();
    }

    private static String pick(String requested, String fallback) { return requested == null || requested.isBlank() ? fallback : requested; }
    private static boolean notBlank(String value) { return value != null && !value.isBlank(); }
    private static String truncate(String value, int max) { return value == null || value.length() <= max ? value : value.substring(0, max); }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }
}
