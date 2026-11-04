package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomGovernanceDtos.GateRequest;
import com.prototype.vulnwatch.dto.CbomGovernanceDtos.GateResult;
import com.prototype.vulnwatch.service.AuditEventService;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * CI gate workflow (plan Milestone 5). A CBOM pushed by a pipeline receives a single-job gate token
 * bound to that one document and environment; polling the document's status with the token returns
 * the gate outcome under the environment's policy. The tenant-wide ingest key alone never sees a
 * gate result, findings or reports, and a token cannot read any other document.
 */
@Service
public class CbomGateService {
    public static final String TOKEN_PREFIX = "sgg_";
    public static final Duration TOKEN_TTL = Duration.ofHours(24);
    public static final String DEFAULT_ENVIRONMENT = "default";
    private static final Set<String> SEVERITIES = Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");
    private static final SecureRandom RANDOM = new SecureRandom();

    public record GatePolicy(String environment, List<String> failOnSeverities, BigDecimal minimumCompleteness,
            boolean blockOnInvalid, String updatedBy, Instant updatedAt, long version, boolean configured) { }

    public record GatePolicyRequest(List<String> failOnSeverities, BigDecimal minimumCompleteness, Boolean blockOnInvalid,
            Long version) { }

    /** state is PENDING until an assessment exists; then PASS, FAIL or INDETERMINATE. */
    public record GateStatus(String state, String environment, UUID bomId, UUID assessmentRunId, List<String> reasons,
            String rulePackageDigest, String artifactChecksum, Integer pollAfterSeconds, Instant tokenExpiresAt) { }

    private final JdbcTemplate jdbc;
    private final CbomGovernanceService governance;
    private final AuditEventService audit;

    public CbomGateService(JdbcTemplate jdbc, CbomGovernanceService governance, AuditEventService audit) {
        this.jdbc = jdbc; this.governance = governance; this.audit = audit;
    }

    /** Issues a token for one pushed CBOM. The raw token is returned once and never stored. */
    @Transactional
    public String issue(UUID bomId, String environment, String issuedBy) {
        String env = environment(environment);
        byte[] secret = new byte[32];
        RANDOM.nextBytes(secret);
        String token = TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        jdbc.update("INSERT INTO cbom_gate_tokens (token_hash, bom_id, environment, issued_by, expires_at) VALUES (?, ?, ?, ?, ?)",
                hash(token), bomId, env, issuedBy, Timestamp.from(Instant.now().plus(TOKEN_TTL)));
        jdbc.update("DELETE FROM cbom_gate_tokens WHERE expires_at < now() - interval '7 days'");
        return token;
    }

    /** Gate outcome for the token's own document; any mismatch is indistinguishable from an unknown token. */
    @Transactional
    public GateStatus result(Tenant tenant, UUID bomId, String token) {
        if (token == null || !token.startsWith(TOKEN_PREFIX)) throw invalidToken();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT bom_id, environment, expires_at FROM cbom_gate_tokens WHERE token_hash = ? FOR UPDATE", hash(token));
        if (rows.isEmpty() || !bomId.equals(rows.get(0).get("bom_id"))) throw invalidToken();
        Instant expires = ((Timestamp) rows.get(0).get("expires_at")).toInstant();
        if (expires.isBefore(Instant.now())) throw invalidToken();
        String env = (String) rows.get(0).get("environment");
        jdbc.update("UPDATE cbom_gate_tokens SET last_polled_at = now(), poll_count = poll_count + 1 WHERE token_hash = ?", hash(token));
        List<Map<String, Object>> runs = jdbc.queryForList("""
                SELECT id, status FROM cbom_assessment_runs WHERE bom_id = ? ORDER BY
                  CASE status WHEN 'SUCCEEDED' THEN 0 ELSE 1 END, completed_at DESC NULLS LAST, created_at DESC LIMIT 1
                """, bomId);
        if (runs.isEmpty() || !"SUCCEEDED".equals(runs.get(0).get("status"))) {
            boolean failed = !runs.isEmpty() && "FAILED".equals(runs.get(0).get("status"));
            return new GateStatus(failed ? "INDETERMINATE" : "PENDING", env, bomId, null,
                    failed ? List.of("The CBOM assessment failed; retry the assessment or contact the workspace administrator") : List.of(),
                    null, null, failed ? null : 10, expires);
        }
        GatePolicy policy = policy(env);
        GateResult gate = governance.gate(tenant, new GateRequest((UUID) runs.get(0).get("id"),
                new LinkedHashSet<>(policy.failOnSeverities()), policy.minimumCompleteness()));
        String outcome = gate.outcome();
        List<String> reasons = gate.reasons();
        if (!policy.blockOnInvalid() && "INDETERMINATE".equals(outcome)) {
            // The environment accepts invalid documents: decide on the remaining reasons only.
            reasons = reasons.stream().filter(reason -> !"CBOM validation failed".equals(reason)).toList();
            outcome = reasons.isEmpty() ? "PASS" : "FAIL";
        }
        return new GateStatus(outcome, env, bomId, gate.assessmentRunId(), reasons, gate.rulePackageDigest(),
                gate.artifactChecksum(), null, expires);
    }

    @Transactional(readOnly = true)
    public List<GatePolicy> policies() {
        return jdbc.query("SELECT environment, fail_on_severities, minimum_completeness, block_on_invalid, updated_by, updated_at, version"
                + " FROM cbom_gate_policies ORDER BY environment", (rs, row) -> new GatePolicy(rs.getString(1),
                Arrays.asList(rs.getString(2).split(",")), rs.getBigDecimal(3), rs.getBoolean(4), rs.getString(5),
                rs.getTimestamp(6).toInstant(), rs.getLong(7), true));
    }

    /** Effective policy: the environment row, else the 'default' row, else the application default. */
    @Transactional(readOnly = true)
    public GatePolicy policy(String environment) {
        String env = environment(environment);
        for (GatePolicy policy : policies()) if (policy.environment().equals(env)) return policy;
        for (GatePolicy policy : policies()) if (policy.environment().equals(DEFAULT_ENVIRONMENT)) return policy;
        return new GatePolicy(env, List.of("CRITICAL", "HIGH"), new BigDecimal("0.80000"), true, "application", null, 0, false);
    }

    /** Creates or updates one environment's policy with optimistic concurrency and an audit record. */
    @Transactional
    public GatePolicy save(String environment, GatePolicyRequest request, String actor) {
        String env = environment(environment);
        if (request == null) throw new IllegalArgumentException("A gate policy is required");
        List<String> severities = request.failOnSeverities() == null || request.failOnSeverities().isEmpty() ? List.of("CRITICAL", "HIGH")
                : request.failOnSeverities().stream().map(v -> v.trim().toUpperCase(Locale.ROOT)).distinct().toList();
        if (!SEVERITIES.containsAll(severities)) throw new IllegalArgumentException("failOnSeverities may contain only " + SEVERITIES);
        BigDecimal minimum = request.minimumCompleteness() == null ? new BigDecimal("0.80") : request.minimumCompleteness();
        if (minimum.compareTo(BigDecimal.ZERO) < 0 || minimum.compareTo(BigDecimal.ONE) > 0) throw new IllegalArgumentException("minimumCompleteness must be between 0 and 1");
        boolean block = request.blockOnInvalid() == null || request.blockOnInvalid();
        int changed;
        if (request.version() == null) {
            changed = jdbc.update("""
                    INSERT INTO cbom_gate_policies (environment, fail_on_severities, minimum_completeness, block_on_invalid, updated_by)
                    VALUES (?, ?, ?, ?, ?) ON CONFLICT (tenant_id, environment) DO NOTHING
                    """, env, String.join(",", severities), minimum, block, actor);
        } else {
            changed = jdbc.update("""
                    UPDATE cbom_gate_policies SET fail_on_severities = ?, minimum_completeness = ?, block_on_invalid = ?,
                           updated_by = ?, updated_at = now(), version = version + 1
                     WHERE environment = ? AND version = ?
                    """, String.join(",", severities), minimum, block, actor, env, request.version());
        }
        if (changed != 1) throw new ResponseStatusException(HttpStatus.CONFLICT, "The gate policy changed since it was loaded; reload and try again");
        audit.record("cbom.gate_policy.updated", "cbom_gate_policy", env,
                "{\"failOnSeverities\":\"" + String.join(",", severities) + "\",\"minimumCompleteness\":" + minimum + ",\"blockOnInvalid\":" + block + "}");
        return policy(env);
    }

    public static String environment(String value) {
        String env = value == null || value.isBlank() ? DEFAULT_ENVIRONMENT : value.trim().toLowerCase(Locale.ROOT);
        if (!env.matches("^[a-z0-9][a-z0-9-]{0,39}$")) throw new IllegalArgumentException("environment must be 1-40 lowercase letters, digits or hyphens");
        return env;
    }

    private static String hash(String token) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static ResponseStatusException invalidToken() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "The gate token is invalid, expired or issued for another document");
    }
}
