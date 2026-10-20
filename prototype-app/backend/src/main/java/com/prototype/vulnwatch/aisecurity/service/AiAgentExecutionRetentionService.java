package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/** Deletes metadata-only runtime records after the configured retention period, tenant by tenant. */
@Service
public class AiAgentExecutionRetentionService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AiAgentExecutionRetentionService.class);
    private static final int MAX_BATCHES_PER_SWEEP = 100;
    private static final long MAX_SWEEP_MILLIS = 30_000;
    private final TenantService tenants; private final TenantSchemaExecutionService tenantExecution;
    private final NamedParameterJdbcTemplate jdbc; private final int retentionDays; private final int batchSize;
    public AiAgentExecutionRetentionService(TenantService tenants, TenantSchemaExecutionService tenantExecution,
                                            NamedParameterJdbcTemplate jdbc,
                                            @Value("${app.ai-security.runtime.retention-days:90}") int retentionDays,
                                            @Value("${app.ai-security.runtime.retention-batch-size:1000}") int batchSize) {
        this.tenants = tenants; this.tenantExecution = tenantExecution; this.jdbc = jdbc;
        this.retentionDays = Math.max(1, retentionDays); this.batchSize = Math.max(1, batchSize);
    }
    @Scheduled(zone = "UTC", cron = "${app.ai-security.runtime.retention-cron:0 17 2 * * *}")
    public void purgeExpired() {
        if (AiRuntimeScope.excluded()) return;
        TenantContext.runAsPlatform(() -> tenants.listActiveTenants().forEach(tenant -> {
            PurgeResult result = purge(tenant);
            if (result.remainingEligible() > 0) {
                LOG.warn("AI runtime retention sweep reached its budget tenantId={} deleted={} remainingEligible={} batches={}",
                        tenant.getId(), result.deleted(), result.remainingEligible(), result.batches());
            }
        }));
    }
    public PurgeResult purge(Tenant tenant) {
        Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
        return tenantExecution.run(tenant, () -> {
            var parameters = new org.springframework.jdbc.core.namedparam.MapSqlParameterSource()
                    .addValue("cutoff", java.sql.Timestamp.from(cutoff))
                    .addValue("batchSize", batchSize);
            long started = System.nanoTime();
            int deleted = 0;
            int batches = 0;
            int batchDeleted;
            do {
                batchDeleted = jdbc.update("""
                        delete from ai_agent_executions
                         where id in (
                               select id from ai_agent_executions
                                where evidence_time < :cutoff
                                order by evidence_time, id
                                limit :batchSize
                         )
                        """, parameters);
                deleted += batchDeleted;
                batches++;
            } while (batchDeleted == batchSize
                    && batches < MAX_BATCHES_PER_SWEEP
                    && (System.nanoTime() - started) / 1_000_000 < MAX_SWEEP_MILLIS);
            Long remaining = jdbc.queryForObject("""
                    select count(*) from ai_agent_executions where evidence_time < :cutoff
                    """, parameters, Long.class);
            return new PurgeResult(deleted, remaining == null ? 0 : remaining, batches);
        });
    }

    public record PurgeResult(int deleted, long remainingEligible, int batches) {}
}
