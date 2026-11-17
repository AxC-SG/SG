package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.PlatformIntelligenceProgressResponse;
import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/** Read-only platform progress. Counts describe separate stages and never imply asset coverage. */
@Service
public class PlatformIntelligenceProgressService {
    private final JdbcTemplate jdbc;
    public PlatformIntelligenceProgressService(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ, timeout = 15)
    public PlatformIntelligenceProgressResponse progress() {
        var runs = jdbc.queryForList("""
                select id,sync_type,status,records_fetched,records_failed,started_at,completed_at
                from platform.sync_runs where run_scope='PLATFORM_VULNERABILITY' and tenant_id is null
                  and sync_type not like 'EOL_%'
                order by started_at desc,id desc limit 1
                """);
        PlatformIntelligenceProgressResponse.Acquisition acquisition = null;
        if (!runs.isEmpty()) {
            var run = runs.get(0);
            acquisition = new PlatformIntelligenceProgressResponse.Acquisition((UUID)run.get("id"),
                    (String)run.get("sync_type"), (String)run.get("status"),
                    ((Number)run.get("records_fetched")).longValue(), ((Number)run.get("records_failed")).longValue(),
                    instant(run.get("started_at")), instant(run.get("completed_at")));
        }
        var publication = jdbc.queryForMap("""
                select s.generation,s.release_id,r.published_at,
                  (select count(*) from platform.intelligence_candidates where status='READY') ready_candidates,
                  (select count(*) from platform.intelligence_publication_outbox where kind in ('PUBLISH','WITHDRAW')
                    and status in ('PENDING','RUNNING')) pending_jobs
                from platform.intelligence_active_state s
                left join platform.intelligence_releases r on r.id=s.release_id where s.singleton=true
                """);
        long generation = ((Number)publication.get("generation")).longValue();
        var delivery = jdbc.queryForMap("""
                select count(*) active,
                  count(*) filter (where p.status='COMPLETED' and p.completed_generation>=?
                    and p.completed_revision>=p.required_revision) current_count,
                  count(*) filter (where p.status='FAILED') failed_count,
                  count(*) filter (where p.status in ('PENDING','FAILED') and p.after_component_id is not null
                    and (p.evaluating_generation is distinct from ?
                      or p.evaluating_revision is distinct from p.required_revision)) stale_checkpoints
                from platform.tenants t left join platform.tenant_intelligence_processing p on p.tenant_id=t.id
                where t.status='ACTIVE'
                """, generation, generation);
        long active = ((Number)delivery.get("active")).longValue();
        long current = ((Number)delivery.get("current_count")).longValue();
        long failed = ((Number)delivery.get("failed_count")).longValue();
        var inventory = jdbc.queryForMap("""
                select count(*) canonical_records,
                       count(*) filter (where not intelligence_withdrawn) active_records,
                       count(*) filter (where intelligence_withdrawn) withdrawn_records
                from platform.vulnerabilities
                """);
        long observationRows = jdbc.queryForObject(
                "select count(*) from platform.vulnerability_intel_observations", Long.class);
        List<PlatformIntelligenceProgressResponse.SourceCoverage> sources = jdbc.query("""
                with source_names(name) as (values
                  ('NVD'),('EUVD'),('JVN'),('GHSA'),('KEV'),('OSV'),('EPSS'),
                  ('CSAF_MICROSOFT'),('CSAF_REDHAT'),('ADVISORY')),
                observations as (
                  select source_system,count(*) observed_windows,
                         count(distinct feed_key) filter_scopes,max(interval_end) latest_end
                  from platform.feed_coverage_observations o
                  join platform.sync_runs runs on runs.id=o.run_id and lower(runs.status)='completed'
                  where o.source_system <> 'nvd' or o.ids_recorded_at is not null
                  group by source_system
                )
                select s.name,r.id,r.status,r.records_fetched,r.completed_at,
                       coalesce(o.observed_windows,0),coalesce(o.filter_scopes,0),o.latest_end
                from source_names s left join lateral (
                  select id,status,records_fetched,completed_at
                  from platform.sync_runs
                  where run_scope='PLATFORM_VULNERABILITY' and tenant_id is null
                    and (sync_type=s.name or (s.name='NVD' and sync_type='NVD_FULL'))
                  order by started_at desc,id desc limit 1
                ) r on true left join observations o on o.source_system=lower(s.name)
                order by s.name
                """, (rs, index) -> {
            var capability = IntelligenceSourceCapabilities.require(rs.getString(1));
            return new PlatformIntelligenceProgressResponse.SourceCoverage(
                rs.getString(1), rs.getObject(2, UUID.class), rs.getString(3),
                rs.getObject(4) == null ? 0 : rs.getLong(4),
                rs.getTimestamp(5) == null ? null : rs.getTimestamp(5).toInstant(), "UNKNOWN",
                rs.getLong(6), rs.getLong(7),
                rs.getTimestamp(8) == null ? null : rs.getTimestamp(8).toInstant(),
                capability.evidenceRole(), capability.acquisitionScope(), capability.tenantPolicySelectable());
        });
        return new PlatformIntelligenceProgressResponse(acquisition,
                new PlatformIntelligenceProgressResponse.Publication(generation,
                        (UUID)publication.get("release_id"), instant(publication.get("published_at")),
                        ((Number)publication.get("ready_candidates")).longValue(),
                        ((Number)publication.get("pending_jobs")).longValue()),
                new PlatformIntelligenceProgressResponse.TenantDelivery(active,current,active-current-failed,failed,
                        ((Number)delivery.get("stale_checkpoints")).longValue()),
                new PlatformIntelligenceProgressResponse.CatalogInventory(
                        ((Number)inventory.get("canonical_records")).longValue(),
                        ((Number)inventory.get("active_records")).longValue(),
                        ((Number)inventory.get("withdrawn_records")).longValue(), observationRows),
                sources,
                "NOT_SEPARATELY_TRACKED");
    }

    private static java.time.Instant instant(Object value) {
        return value == null ? null : ((Timestamp)value).toInstant();
    }
}
