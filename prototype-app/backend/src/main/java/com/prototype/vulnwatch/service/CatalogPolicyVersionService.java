package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CatalogPolicy;
import com.prototype.vulnwatch.dto.CatalogPolicy.Rule;
import com.prototype.vulnwatch.dto.CatalogPolicyVersionResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CatalogPolicyVersionService {
    private final WorkspaceService workspace;
    private final CatalogPolicyEvaluator evaluator;
    private final ObjectMapper mapper;
    private final NamedParameterJdbcTemplate jdbc;
    private final AuditEventService audit;

    public CatalogPolicyVersionService(WorkspaceService workspace, CatalogPolicyEvaluator evaluator, ObjectMapper mapper,
            NamedParameterJdbcTemplate jdbc, AuditEventService audit) {
        this.workspace = workspace; this.evaluator = evaluator; this.mapper = mapper; this.jdbc = jdbc; this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<CatalogPolicyVersionResponse> list() {
        Tenant tenant = requireTenant();
        return jdbc.query("""
                select version, policy_json::text as policy_json, policy_sha256, created_at
                from intelligence_catalog_policy_versions where tenant_id=:tenant order by version desc limit 100
                """, Map.of("tenant", tenant.getId()), (rs, row) -> new CatalogPolicyVersionResponse(
                    rs.getLong("version"), rs.getString("policy_sha256"), rs.getTimestamp("created_at").toInstant(),
                    readPolicy(rs.getString("policy_json"))));
    }

    @Transactional
    public CatalogPolicyVersionResponse save(Long expectedVersion, CatalogPolicy policy) {
        Tenant tenant = requireTenant();
        evaluator.validate(policy);
        // Serialize per tenant so first-version creation and concurrent saves are race-safe.
        jdbc.getJdbcTemplate().query("select pg_advisory_xact_lock(hashtext(?))", rs -> null,
                "catalog-policy:" + tenant.getId());
        long current = Optional.ofNullable(jdbc.queryForObject("select max(version) from intelligence_catalog_policy_versions where tenant_id=:tenant",
                Map.of("tenant", tenant.getId()), Long.class)).orElse(0L);
        if (expectedVersion == null || expectedVersion != current)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Policy version changed; reload the latest version before saving");

        CatalogPolicy canonical = new CatalogPolicy(policy.version(), new TreeSet<>(policy.sources()), policy.includeNonCve(),
                policy.scoreResolution(), canonicalize(policy.rule()));
        final String json;
        try { json = mapper.writeValueAsString(canonical); }
        catch (Exception error) { throw new IllegalArgumentException("Could not serialize catalog policy", error); }
        String digest = sha256(json);
        long next = current + 1;
        jdbc.update("""
                insert into intelligence_catalog_policy_versions(tenant_id,version,policy_json,policy_sha256)
                values(:tenant,:version,cast(:policy as jsonb),:digest)
                """, new MapSqlParameterSource().addValue("tenant", tenant.getId()).addValue("version", next)
                    .addValue("policy", json).addValue("digest", digest));
        // Same transaction/schema: an audit write failure rolls back the version insert.
        audit.record("tenant.intelligence_catalog_policy.saved", "intelligence_catalog_policy_version",
                Long.toString(next), "{\"version\":" + next + ",\"sha256\":\"" + digest + "\"}");
        java.sql.Timestamp createdAt = jdbc.queryForObject(
                "select created_at from intelligence_catalog_policy_versions where tenant_id=:tenant and version=:version",
                Map.of("tenant", tenant.getId(), "version", next), java.sql.Timestamp.class);
        return new CatalogPolicyVersionResponse(next, digest, Objects.requireNonNull(createdAt).toInstant(), canonical);
    }

    private Tenant requireTenant() {
        UUID tenantId = TenantContext.getCurrentTenantId();
        if (tenantId == null || TenantContext.isPlatformContext())
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "An active tenant context is required");
        Tenant tenant = workspace.getWorkspace();
        if (!tenantId.equals(tenant.getId())) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant context mismatch");
        return tenant;
    }

    private CatalogPolicy readPolicy(String json) {
        try { return mapper.readValue(json, CatalogPolicy.class); }
        catch (Exception error) { throw new IllegalStateException("Stored catalog policy is invalid", error); }
    }
    private static Rule canonicalize(Rule rule) {
        if (rule.children() == null) return rule;
        return new Rule(rule.op(), rule.field(), rule.number(), rule.flag(), rule.children().stream().map(CatalogPolicyVersionService::canonicalize).toList());
    }
    private static String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception impossible) { throw new IllegalStateException("SHA-256 is unavailable", impossible); }
    }
}
