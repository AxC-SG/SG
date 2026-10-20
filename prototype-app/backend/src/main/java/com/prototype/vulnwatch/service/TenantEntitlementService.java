package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import io.micrometer.core.instrument.MeterRegistry;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TenantEntitlementService {

    public static final String PLAN_PRO = "PRO";
    public static final String PLAN_ENTERPRISE = "ENTERPRISE";
    public static final String PLAN_DEMO = "DEMO";
    public static final String PLAN_PILOT = "PILOT";

    public static final String AI_INVESTIGATION_SUMMARY = "ai.investigation_summary";
    public static final String AI_SOLUTION_GENERATION = "ai.solution_generation";
    public static final String AI_REQUIRED_ACTIONS = "ai.required_actions";
    public static final String AI_FIX_GENERATION = "ai.fix_generation";
    public static final String AI_INVESTIGATION_AGENT = "ai.investigation_agent";
    public static final String AI_UPGRADE_RECOMMENDATION = "ai.upgrade_recommendation";
    public static final String AI_SECURITY = "ai.security";

    private static final Set<String> KNOWN_PLANS = Set.of(PLAN_PRO, PLAN_ENTERPRISE, PLAN_DEMO, PLAN_PILOT);
    private static final String SOURCE_DEFAULT = "DEFAULT";
    private static final String SOURCE_PLAN = "PLAN";
    private static final String SOURCE_TENANT_OVERRIDE = "TENANT_OVERRIDE";

    /** Bounded set of entitlement keys allowed as metric labels; anything else buckets to UNKNOWN. */
    private static final Set<String> KNOWN_ENTITLEMENT_KEYS = Set.of(
            AI_INVESTIGATION_SUMMARY,
            AI_SOLUTION_GENERATION,
            AI_REQUIRED_ACTIONS,
            AI_FIX_GENERATION,
            AI_INVESTIGATION_AGENT,
            AI_UPGRADE_RECOMMENDATION,
            AI_SECURITY);

    private static final String METRIC_KEY_UNKNOWN = "UNKNOWN";

    private static final Logger LOG = LoggerFactory.getLogger(TenantEntitlementService.class);

    /**
     * Rollout mode for the corrected resolver.
     * LEGACY  — return the historical always-enabled result; no corrected computation.
     * SHADOW  — enforce the legacy result, compute the corrected result, emit mismatch telemetry.
     * ENFORCE — enforce the corrected result for explicitly named tenant IDs or slugs;
     *           every other tenant behaves as SHADOW. Wildcards are never a pilot cohort.
     */
    public enum ResolutionMode { LEGACY, SHADOW, ENFORCE }

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final MeterRegistry meterRegistry;
    private final ResolutionMode mode;
    private final Set<String> enforceTenantAllowlist;

    public TenantEntitlementService(
            NamedParameterJdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            MeterRegistry meterRegistry,
            @Value("${app.entitlements.mode:LEGACY}") String modeRaw,
            @Value("${app.entitlements.enforce-tenant-allowlist:}") String enforceTenantAllowlistRaw) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.meterRegistry = meterRegistry;
        this.mode = parseMode(modeRaw);
        this.enforceTenantAllowlist = parseEnforcementCohort(enforceTenantAllowlistRaw);
        LOG.info("TenantEntitlementService rollout mode={} enforceAllowlistSize={}",
                this.mode, this.enforceTenantAllowlist.size());
    }

    public Map<String, Boolean> snapshot(Tenant tenant) {
        // Platform/null context is not a tenant: expose no entitlements so the frontend fails closed
        // and null tenants are never reported enabled (even under global enforcement).
        if (tenant == null || tenant.getId() == null) {
            return Map.of();
        }
        LinkedHashMap<String, Boolean> snapshot = new LinkedHashMap<>();
        for (ResolvedEntitlement entitlement : resolveAll(tenant)) {
            snapshot.put(entitlement.key(), entitlement.enabled());
        }
        return snapshot;
    }

    public boolean isEnabled(Tenant tenant, String entitlementKey) {
        return resolve(tenant, entitlementKey).enabled();
    }

    /** True in SHADOW or ENFORCE mode: corrected results are being computed, so the sweep should run. */
    public boolean shadowSweepEnabled() {
        return mode != ResolutionMode.LEGACY;
    }

    public ResolvedEntitlement resolve(Tenant tenant, String entitlementKey) {
        String key = normalizeKey(entitlementKey);
        String commercialPlan = commercialPlanCode(tenant);

        EntitlementDefinition definition = loadDefinitions().stream()
                .filter(candidate -> candidate.key().equals(key))
                .findFirst()
                .orElse(new EntitlementDefinition(key, "UNCATEGORIZED", "BOOLEAN", null));

        Map<String, TenantOverrideRow> overrideRows =
                tenant == null ? Map.of() : loadTenantOverrides(tenant.getId());
        Map<String, PlanEntitlementRow> planRows =
                mode == ResolutionMode.LEGACY ? Map.of() : loadPlanEntitlements(commercialPlan);

        return resolveEffective(tenant, definition, overrideRows, planRows, commercialPlan);
    }

    public List<ResolvedEntitlement> resolveAll(Tenant tenant) {
        String commercialPlan = commercialPlanCode(tenant);
        Map<String, TenantOverrideRow> overrideRows =
                tenant == null ? Map.of() : loadTenantOverrides(tenant.getId());
        Map<String, PlanEntitlementRow> planRows =
                mode == ResolutionMode.LEGACY ? Map.of() : loadPlanEntitlements(commercialPlan);
        List<ResolvedEntitlement> entitlements = new ArrayList<>();
        for (EntitlementDefinition definition : loadDefinitions()) {
            entitlements.add(resolveEffective(tenant, definition, overrideRows, planRows, commercialPlan));
        }
        return entitlements;
    }

    /**
     * Computes the effective entitlement, applying rollout mode and canary allowlist, and emits
     * shadow mismatch telemetry when the corrected result diverges from the legacy result. This is
     * the single authoritative decision used by both enforcement ({@link #isEnabled}) and the
     * auth-context snapshot exposed to the frontend, so the two never disagree.
     */
    private ResolvedEntitlement resolveEffective(
            Tenant tenant,
            EntitlementDefinition definition,
            Map<String, TenantOverrideRow> overrideRows,
            Map<String, PlanEntitlementRow> planRows,
            String commercialPlan) {
        String key = definition.key();

        // Legacy behavior: every entitlement resolves enabled.
        boolean legacyEnabled = true;

        if (mode == ResolutionMode.LEGACY) {
            TenantOverrideRow legacyOverride = overrideRows.get(key);
            Map<String, Object> legacyConfig = legacyOverride != null && legacyOverride.config() != null
                    ? legacyOverride.config()
                    : Map.of();
            return new ResolvedEntitlement(key, definition.category(), legacyEnabled, SOURCE_DEFAULT, commercialPlan, legacyConfig);
        }

        // Corrected precedence: active tenant override -> plan value -> disabled default. Config
        // follows the same precedence, so plan-level config is inherited when no override exists.
        // Expired overrides are already filtered out by loadTenantOverrides, so an expired override
        // falls through to the plan value rather than resolving disabled.
        CorrectedResolution corrected = corrected(key, overrideRows.get(key), planRows.get(key));

        if (legacyEnabled != corrected.enabled()) {
            incrementMismatchCounter(key, corrected.source(), corrected.enabled());
        }

        boolean effectiveEnabled;
        String effectiveSource;
        if (mode == ResolutionMode.ENFORCE) {
            if (tenant == null || tenant.getId() == null) {
                // Platform/null context is not a tenant; fail closed under enforcement rather than
                // leaving it legacy-enabled.
                effectiveEnabled = false;
                effectiveSource = SOURCE_DEFAULT;
            } else if (isEnforcedTenant(tenant)) {
                effectiveEnabled = corrected.enabled();
                effectiveSource = corrected.source();
            } else {
                // Outside the canary allowlist: behave as SHADOW (legacy enforced).
                effectiveEnabled = legacyEnabled;
                effectiveSource = SOURCE_DEFAULT;
            }
        } else {
            // SHADOW: legacy enforced, corrected shadowed.
            effectiveEnabled = legacyEnabled;
            effectiveSource = SOURCE_DEFAULT;
        }
        return new ResolvedEntitlement(key, definition.category(), effectiveEnabled, effectiveSource, commercialPlan, corrected.config());
    }

    /** Corrected precedence, independent of rollout mode: active override -> plan -> disabled default. */
    private CorrectedResolution corrected(String key, TenantOverrideRow overrideRow, PlanEntitlementRow planRow) {
        if (overrideRow != null) {
            Map<String, Object> config = overrideRow.config() != null ? overrideRow.config() : Map.of();
            return new CorrectedResolution(overrideRow.enabled(), SOURCE_TENANT_OVERRIDE, config);
        }
        if (planRow != null) {
            Map<String, Object> config = planRow.config() != null ? planRow.config() : Map.of();
            return new CorrectedResolution(planRow.enabled(), SOURCE_PLAN, config);
        }
        return new CorrectedResolution(false, SOURCE_DEFAULT, Map.of());
    }

    /**
     * Returns keys where the corrected result diverges from the legacy (always-enabled) result for
     * the given tenant. Used by the scheduled shadow sweep so coverage does not depend on a feature
     * actually being exercised. Pure: increments no counters and writes no logs.
     */
    public List<ShadowMismatch> detectShadowMismatches(Tenant tenant) {
        String commercialPlan = commercialPlanCode(tenant);
        Map<String, TenantOverrideRow> overrideRows =
                tenant == null ? Map.of() : loadTenantOverrides(tenant.getId());
        Map<String, PlanEntitlementRow> planRows = loadPlanEntitlements(commercialPlan);
        List<ShadowMismatch> mismatches = new ArrayList<>();
        for (String key : KNOWN_ENTITLEMENT_KEYS) {
            CorrectedResolution corrected = corrected(key, overrideRows.get(key), planRows.get(key));
            if (!corrected.enabled()) {
                mismatches.add(new ShadowMismatch(key, corrected.enabled(), corrected.source()));
            }
        }
        return mismatches;
    }

    private boolean isEnforcedTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return false;
        }
        return enforceTenantAllowlist.contains(tenant.getId().toString())
                || (tenant.getSlug() != null && enforceTenantAllowlist.contains("slug:" + tenant.getSlug()));
    }

    /** Increments the mismatch counter with a bounded key label. Logging is handled by the sweep. */
    public void incrementMismatchCounter(String key, String correctedSource, boolean correctedEnabled) {
        String metricKey = KNOWN_ENTITLEMENT_KEYS.contains(key) ? key : METRIC_KEY_UNKNOWN;
        meterRegistry.counter(
                "entitlement.resolution.mismatch",
                "key", metricKey,
                "source", correctedSource,
                "corrected", Boolean.toString(correctedEnabled)).increment();
    }

    private ResolutionMode parseMode(String raw) {
        if (raw == null || raw.isBlank()) {
            return ResolutionMode.LEGACY;
        }
        try {
            return ResolutionMode.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            // Fail fast: a typo in the rollout mode must not silently defeat a planned cutover.
            throw new IllegalStateException(
                    "Invalid app.entitlements.mode='" + raw + "'; expected one of LEGACY, SHADOW, ENFORCE", ex);
        }
    }

    public static Set<String> parseEnforcementCohort(String raw) {
        Set<String> values = new HashSet<>();
        if (raw != null) {
            for (String part : raw.split(",")) {
                String trimmed = part.trim().toLowerCase(Locale.ROOT);
                if (!trimmed.isEmpty()) {
                    if (trimmed.startsWith("slug:")) {
                        String slug = trimmed.substring(5);
                        if (slug.length() > 120 || !slug.matches("[a-z0-9]+(?:-[a-z0-9]+)*")) {
                            throw new IllegalStateException("Entitlement cohort entries must be canonical tenant UUIDs or slug:<tenant-slug>.");
                        }
                    } else {
                        try {
                            if (!UUID.fromString(trimmed).toString().equals(trimmed)) {
                                throw new IllegalArgumentException("Noncanonical UUID");
                            }
                        } catch (IllegalArgumentException ex) {
                            throw new IllegalStateException("Entitlement cohort entries must be canonical tenant UUIDs or slug:<tenant-slug>; wildcards are forbidden.", ex);
                        }
                    }
                    values.add(trimmed);
                }
            }
        }
        return Set.copyOf(values);
    }

    public List<TenantEntitlementOverrideRecord> listOverrides(UUID tenantId) {
        if (tenantId == null) {
            return List.of();
        }
        return jdbcTemplate.query("""
                select id,
                       tenant_id,
                       entitlement_key,
                       enabled,
                       config_json,
                       reason,
                       expires_at,
                       created_by,
                       created_at,
                       updated_at
                  from platform.tenant_entitlement_overrides
                 where tenant_id = :tenantId
                 order by entitlement_key asc
                """, Map.of("tenantId", tenantId), (rs, rowNum) -> toOverrideRecord(rs));
    }

    public TenantEntitlementOverrideRecord upsertOverride(
            UUID tenantId,
            String entitlementKey,
            boolean enabled,
            Map<String, Object> config,
            String reason,
            Instant expiresAt,
            UUID createdBy
    ) {
        UUID overrideId = existingOverrideId(tenantId, entitlementKey);
        Instant now = Instant.now();
        String configJson = writeJson(config);
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("id", overrideId == null ? UUID.randomUUID() : overrideId)
                .addValue("tenantId", tenantId)
                .addValue("entitlementKey", normalizeKey(entitlementKey))
                .addValue("enabled", enabled)
                .addValue("configJson", configJson)
                .addValue("reason", trimToNull(reason))
                .addValue("expiresAt", expiresAt == null ? null : Timestamp.from(expiresAt))
                .addValue("createdBy", createdBy)
                .addValue("createdAt", Timestamp.from(now))
                .addValue("updatedAt", Timestamp.from(now));
        jdbcTemplate.update("""
                insert into platform.tenant_entitlement_overrides (
                    id, tenant_id, entitlement_key, enabled, config_json, reason, expires_at, created_by, created_at, updated_at
                ) values (
                    :id, :tenantId, :entitlementKey, :enabled, cast(:configJson as jsonb), :reason, :expiresAt, :createdBy, :createdAt, :updatedAt
                )
                on conflict (tenant_id, entitlement_key) do update
                    set enabled = excluded.enabled,
                        config_json = excluded.config_json,
                        reason = excluded.reason,
                        expires_at = excluded.expires_at,
                        created_by = excluded.created_by,
                        updated_at = excluded.updated_at
                """, params);
        return listOverrides(tenantId).stream()
                .filter(override -> override.entitlementKey().equals(normalizeKey(entitlementKey)))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Failed to load saved entitlement override"));
    }

    public void deleteOverride(UUID tenantId, String entitlementKey) {
        jdbcTemplate.update("""
                delete from platform.tenant_entitlement_overrides
                 where tenant_id = :tenantId
                   and entitlement_key = :entitlementKey
                """, Map.of("tenantId", tenantId, "entitlementKey", normalizeKey(entitlementKey)));
    }

    public String commercialPlanCode(Tenant tenant) {
        if (tenant == null) {
            return PLAN_PRO;
        }
        String raw = normalizePlanCode(tenant.getPlanCode());
        return raw == null ? PLAN_PRO : raw;
    }

    public String effectivePlanCode(String commercialPlanCode) {
        String normalized = normalizePlanCode(commercialPlanCode);
        if (normalized == null) {
            return PLAN_PRO;
        }
        return switch (normalized) {
            case PLAN_ENTERPRISE -> PLAN_ENTERPRISE;
            case PLAN_DEMO -> PLAN_DEMO;
            case PLAN_PRO -> PLAN_PRO;
            case PLAN_PILOT -> PLAN_PRO;
            default -> PLAN_PRO;
        };
    }

    private List<EntitlementDefinition> loadDefinitions() {
        return jdbcTemplate.query("""
                select key, category, value_type, description
                  from platform.entitlement_definitions
                 order by category asc, key asc
                """, (rs, rowNum) -> new EntitlementDefinition(
                rs.getString("key"),
                rs.getString("category"),
                rs.getString("value_type"),
                rs.getString("description")
        ));
    }

    private Map<String, PlanEntitlementRow> loadPlanEntitlements(String planCode) {
        LinkedHashMap<String, PlanEntitlementRow> rows = new LinkedHashMap<>();
        jdbcTemplate.query("""
                select entitlement_key, enabled, config_json
                  from platform.plan_entitlements
                 where plan_code = :planCode
                """, Map.of("planCode", effectivePlanCode(planCode)), (rs) -> {
            rows.put(rs.getString("entitlement_key"), new PlanEntitlementRow(
                    rs.getBoolean("enabled"),
                    readJsonMap(rs.getString("config_json"))
            ));
        });
        return rows;
    }

    private Map<String, TenantOverrideRow> loadTenantOverrides(UUID tenantId) {
        LinkedHashMap<String, TenantOverrideRow> rows = new LinkedHashMap<>();
        jdbcTemplate.query("""
                select entitlement_key, enabled, config_json
                  from platform.tenant_entitlement_overrides
                 where tenant_id = :tenantId
                   and (expires_at is null or expires_at > :now)
                """, Map.of("tenantId", tenantId, "now", Timestamp.from(Instant.now())), (rs) -> {
            rows.put(rs.getString("entitlement_key"), new TenantOverrideRow(
                    rs.getBoolean("enabled"),
                    readJsonMap(rs.getString("config_json"))
            ));
        });
        return rows;
    }

    private UUID existingOverrideId(UUID tenantId, String entitlementKey) {
        List<UUID> ids = jdbcTemplate.query("""
                select id
                  from platform.tenant_entitlement_overrides
                 where tenant_id = :tenantId
                   and entitlement_key = :entitlementKey
                """, Map.of("tenantId", tenantId, "entitlementKey", normalizeKey(entitlementKey)),
                (rs, rowNum) -> rs.getObject("id", UUID.class));
        return ids.isEmpty() ? null : ids.get(0);
    }

    private TenantEntitlementOverrideRecord toOverrideRecord(ResultSet rs) throws SQLException {
        return new TenantEntitlementOverrideRecord(
                rs.getObject("id", UUID.class),
                rs.getObject("tenant_id", UUID.class),
                rs.getString("entitlement_key"),
                rs.getBoolean("enabled"),
                readJsonMap(rs.getString("config_json")),
                rs.getString("reason"),
                rs.getTimestamp("expires_at") == null ? null : rs.getTimestamp("expires_at").toInstant(),
                rs.getObject("created_by", UUID.class),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant()
        );
    }

    private String normalizePlanCode(String planCode) {
        if (planCode == null || planCode.isBlank()) {
            return null;
        }
        String normalized = planCode.trim().toUpperCase();
        return KNOWN_PLANS.contains(normalized) ? normalized : normalized;
    }

    private String normalizeKey(String entitlementKey) {
        if (entitlementKey == null || entitlementKey.isBlank()) {
            throw new IllegalArgumentException("entitlementKey is required");
        }
        return entitlementKey.trim();
    }

    private String writeJson(Map<String, Object> config) {
        try {
            return config == null || config.isEmpty() ? null : objectMapper.writeValueAsString(config);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to serialize entitlement config", ex);
        }
    }

    private Map<String, Object> readJsonMap(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception ex) {
            return Map.of();
        }
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private record EntitlementDefinition(
            String key,
            String category,
            String valueType,
            String description
    ) {}

    private record PlanEntitlementRow(
            boolean enabled,
            Map<String, Object> config
    ) {}

    private record CorrectedResolution(boolean enabled, String source, Map<String, Object> config) {}

    public record ShadowMismatch(String key, boolean correctedEnabled, String source) {}

    private record TenantOverrideRow(
            boolean enabled,
            Map<String, Object> config
    ) {}

    public record ResolvedEntitlement(
            String key,
            String category,
            boolean enabled,
            String source,
            String planCode,
            Map<String, Object> config
    ) {}

    public record TenantEntitlementOverrideRecord(
            UUID id,
            UUID tenantId,
            String entitlementKey,
            boolean enabled,
            Map<String, Object> config,
            String reason,
            Instant expiresAt,
            UUID createdBy,
            Instant createdAt,
            Instant updatedAt
    ) {}
}
