package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Provider;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Settings;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * Admin side of the AWS/GCP ownership producers (Phase 0B §2.1, §2.2): per-tenant key and account-input settings
 * ({@code CONFIGURE_OWNERSHIP_PRODUCER}), the tenant kill switch ({@code PAUSE_SOURCE}) and its anomaly approval, and
 * the status the hub's Sources view shows. Settings live on the discovery config rows (tenant V24); the producer reads
 * them through {@link #settings}. Every change is audited and re-resolves the affected subjects through the queue.
 */
@Service
public class CloudOwnershipSourceService {

    public record Status(String provider, boolean deploymentEnabled, boolean configured, String domainState, boolean paused,
                         String pauseReason, boolean intervalValid, Integer intervalMinutes, Settings settings,
                         boolean accountTagsConfigured, long activeClaims, long openAnomalies) { }

    public record SettingsRequest(Boolean ownerKeyEnabled, Boolean teamKeyEnabled, Boolean accountInputEnabled) { }

    static final String ANOMALY_APPROVED = "ANOMALY_APPROVED";
    private static final long MIN_INTERVAL_MINUTES = 15;
    private static final long MAX_INTERVAL_MINUTES = 7 * 24 * 60;

    private final JdbcTemplate jdbc;
    private final OwnershipClaimService claims;
    private final OwnershipResolutionService resolution;
    private final OwnershipAuthorityService authority;
    private final OwnershipReviewService reviews;
    private final AuditEventService audit;
    private final boolean deploymentEnabled;

    public CloudOwnershipSourceService(JdbcTemplate jdbc, OwnershipClaimService claims, OwnershipResolutionService resolution,
                                       OwnershipAuthorityService authority,
                                       OwnershipReviewService reviews, AuditEventService audit,
                                       @Value("${app.ownership.cloud.producer-enabled:false}") boolean deploymentEnabled) {
        this.jdbc = jdbc;
        this.claims = claims;
        this.resolution = resolution;
        this.authority = authority;
        this.reviews = reviews;
        this.audit = audit;
        this.deploymentEnabled = deploymentEnabled;
    }

    /** The tenant's settings for {@code provider}, or empty when the connector is not configured. */
    @Transactional(readOnly = true)
    public Optional<Settings> settings(Provider provider) {
        return jdbc.query("SELECT ownership_owner_key_enabled, ownership_team_key_enabled, ownership_account_input_enabled, interval_minutes FROM "
                        + provider.configTable + " ORDER BY created_at LIMIT 1",
                (rs, n) -> new Settings(rs.getBoolean(1), rs.getBoolean(2), rs.getBoolean(3), (Integer) rs.getObject(4))).stream().findFirst();
    }

    @Transactional(readOnly = true)
    public Status status(Provider provider) {
        Optional<Settings> settings = settings(provider);
        Optional<String> pause = killSwitch(provider).filter(row -> "PAUSED".equals(row.get("state"))).map(row -> (String) row.get("reason"));
        boolean platformPaused = Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM platform.ownership_kill_switches WHERE source_kind = ? AND tenant_id IS NULL AND state = 'PAUSED')
                """, Boolean.class, provider.kind()));
        Integer interval = settings.map(Settings::intervalMinutes).orElse(null);
        boolean accountTags = provider == Provider.GCP || Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM aws_discovery_configs WHERE organizations_role_arn IS NOT NULL AND btrim(organizations_role_arn) <> '')",
                Boolean.class));
        long active = jdbc.queryForObject("SELECT count(*) FROM ownership_claim WHERE source_kind = ? AND status = 'ACTIVE'", Long.class, provider.kind());
        long anomalies = jdbc.queryForObject("""
                SELECT count(*) FROM ownership_review_item WHERE item_type = 'PRODUCER_ANOMALY' AND state = 'OPEN' AND source_kind = ?
                """, Long.class, provider.kind());
        return new Status(provider.kind(), deploymentEnabled, settings.isPresent(),
                authority.stateFor(OwnershipAuthorityService.Domain.CLOUD_BOM).name(), pause.isPresent() || platformPaused,
                platformPaused ? "PLATFORM" : pause.orElse(null), interval != null && validInterval(interval), interval,
                settings.orElse(null), accountTags, active, anomalies);
    }

    /** Changes the key and account-input switches. A switch turned off ends that input's active claims (§2.2). */
    @Transactional
    public Status updateSettings(Provider provider, SettingsRequest request, String actor) {
        Settings current = settings(provider).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                "Configure the " + provider.kind() + " connector first"));
        boolean owner = request.ownerKeyEnabled() == null ? current.ownerKey() : request.ownerKeyEnabled();
        boolean team = request.teamKeyEnabled() == null ? current.teamKey() : request.teamKeyEnabled();
        boolean account = request.accountInputEnabled() == null ? current.accountInput() : request.accountInputEnabled();
        jdbc.update("UPDATE " + provider.configTable + " SET ownership_owner_key_enabled = ?, ownership_team_key_enabled = ?,"
                + " ownership_account_input_enabled = ?, updated_at = now()", owner, team, account);
        int ended = 0;
        if (current.ownerKey() && !owner) ended += claims.endBySourceRef(provider.kind(), "%:" + provider.keyWord + ":owner", actor);
        if (current.teamKey() && !team) ended += claims.endBySourceRef(provider.kind(), "%:" + provider.keyWord + ":team", actor);
        if (current.accountInput() && !account) {
            ended += claims.endBySourceRef(provider.kind(), provider.assetProvider + ":" + provider.accountWord + ":%", actor);
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("provider", provider.kind());
        details.put("ownerKeyEnabled", owner);
        details.put("teamKeyEnabled", team);
        details.put("accountInputEnabled", account);
        details.put("claimsEnded", ended);
        audit.record("ownership.cloud_producer.settings_updated", "ownership_source", provider.kind(), OwnershipEvents.json(details));
        return status(provider);
    }

    /** Pauses the tenant's producer for {@code provider}; its claims stop counting at once (they are re-resolved). */
    @Transactional
    public Status pause(Provider provider, String reason, String actor) {
        setKillSwitch(provider, "PAUSED", reason == null || reason.isBlank() ? "Paused by an administrator" : reason.strip(), actor);
        int queued = enqueueSubjects(provider);
        audit.record("ownership.cloud_producer.paused", "ownership_source", provider.kind(),
                OwnershipEvents.json(Map.of("provider", provider.kind(), "queuedSubjects", queued)));
        return status(provider);
    }

    /**
     * Resumes the producer. After an anomaly pause, resuming is the admin's approval (§2.8): the next run applies the
     * reviewed changes once, without the anomaly gate, and the open anomaly items are closed.
     */
    @Transactional
    public Status resume(Provider provider, String actor) {
        boolean anomaly = killSwitch(provider).map(row -> "PAUSED".equals(row.get("state"))
                && String.valueOf(row.get("reason")).startsWith("ANOMALY")).orElse(false);
        setKillSwitch(provider, "ACTIVE", anomaly ? ANOMALY_APPROVED : "Resumed by an administrator", actor);
        if (anomaly) {
            for (String priorityClass : List.of("CLOUD_TAG", "CLOUD_STRUCTURED")) {
                reviews.closeOpen("PRODUCER_ANOMALY|" + provider.kind() + "|" + priorityClass, "RESOLVED", "Approved by resuming the source", actor);
            }
        }
        int queued = enqueueSubjects(provider);
        audit.record("ownership.cloud_producer.resumed", "ownership_source", provider.kind(),
                OwnershipEvents.json(Map.of("provider", provider.kind(), "anomalyApproved", anomaly, "queuedSubjects", queued)));
        return status(provider);
    }

    /** Called by the producer when a run tripped the anomaly gate (§2.8). */
    @Transactional
    public void pauseForAnomaly(Provider provider, List<String> priorityClasses) {
        setKillSwitch(provider, "PAUSED", "ANOMALY " + String.join(",", priorityClasses), CloudOwnershipProducer.ACTOR);
        enqueueSubjects(provider);
        audit.record("ownership.cloud_producer.anomaly_paused", "ownership_source", provider.kind(),
                OwnershipEvents.json(Map.of("provider", provider.kind(), "priorityClasses", priorityClasses)));
    }

    /** True once after an admin approved an anomaly by resuming; the approval is consumed by the run that reads it. */
    @Transactional
    public boolean consumeAnomalyApproval(Provider provider) {
        UUID tenant = requireTenant();
        return TenantContext.runAsPlatform(() -> jdbc.update("""
                UPDATE platform.ownership_kill_switches SET reason = 'Resumed by an administrator', updated_at = now()
                 WHERE source_kind = ? AND tenant_id = ? AND state = 'ACTIVE' AND reason = ?
                """, provider.kind(), tenant, ANOMALY_APPROVED)) > 0;
    }

    /** §2.1: while the producer is enabled, a connector interval outside 15 minutes to 7 days is rejected. */
    public void requireValidConnectorInterval(Integer intervalMinutes) {
        if (deploymentEnabled && intervalMinutes != null && !validInterval(intervalMinutes)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "While cloud ownership is enabled the sync interval must be between 15 minutes and 7 days");
        }
    }

    static boolean validInterval(long minutes) {
        return minutes >= MIN_INTERVAL_MINUTES && minutes <= MAX_INTERVAL_MINUTES;
    }

    private Optional<Map<String, Object>> killSwitch(Provider provider) {
        UUID tenant = requireTenant();
        return TenantContext.runAsPlatform(() -> jdbc.queryForList(
                "SELECT state, reason FROM platform.ownership_kill_switches WHERE source_kind = ? AND tenant_id = ?", provider.kind(), tenant))
                .stream().findFirst();
    }

    private void setKillSwitch(Provider provider, String state, String reason, String actor) {
        UUID tenant = requireTenant();
        String clipped = reason.length() > 500 ? reason.substring(0, 500) : reason;
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_kill_switches (id, source_kind, tenant_id, state, reason, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, now())
                ON CONFLICT (source_kind, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
                DO UPDATE SET state = EXCLUDED.state, reason = EXCLUDED.reason, updated_by = EXCLUDED.updated_by, updated_at = now()
                """, UUID.randomUUID(), provider.kind(), tenant, state, clipped, actor));
    }

    /** §2.6: a pause or resume changes which claims are eligible, so every subject with one of them is re-resolved. */
    private int enqueueSubjects(Provider provider) {
        return resolution.enqueueSubjectsOfSource(provider.kind());
    }

    private static UUID requireTenant() {
        UUID tenant = TenantContext.getCurrentTenantId();
        if (tenant == null) throw new IllegalStateException("Cloud ownership settings require a tenant context");
        return tenant;
    }
}
