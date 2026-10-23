package com.prototype.vulnwatch.service;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class IntelligenceOperationalMetrics {
    private final JdbcTemplate jdbc;
    private final BackgroundTaskExecutionPolicy background;
    private final Map<String,AtomicLong> values=new LinkedHashMap<>();
    public IntelligenceOperationalMetrics(JdbcTemplate jdbc,BackgroundTaskExecutionPolicy background,MeterRegistry registry) {
        this.jdbc=jdbc;this.background=background;
        for(String name:List.of("ingestion_failures","candidate_age_seconds","publication_failures","queue_age_seconds","tenant_processing_failures","invitation_delivery_unknown")) {
            AtomicLong value=new AtomicLong();values.put(name,value);Gauge.builder("intelligence."+name,value,AtomicLong::get).register(registry);
        }
    }
    @org.springframework.security.access.prepost.PreAuthorize("hasRole('PLATFORM_OWNER')")
    @org.springframework.transaction.annotation.Transactional(readOnly=true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public Map<String,Object> health() { return queryHealth(); }
    private Map<String,Object> queryHealth() {
        return jdbc.queryForMap("""
                select
                 (select count(*) from platform.sync_runs where run_scope='PLATFORM_VULNERABILITY' and lower(status)='failed' and started_at>now()-interval '1 day') ingestion_failures,
                 (select coalesce(extract(epoch from now()-min(created_at)),0)::bigint from platform.intelligence_candidates where status in ('READY','BUILDING')) candidate_age_seconds,
                 (select count(*) from platform.intelligence_publication_outbox where status='FAILED' and kind in ('PUBLISH','WITHDRAW')) publication_failures,
                 (select coalesce(extract(epoch from now()-min(created_at)),0)::bigint from platform.intelligence_publication_outbox where status='PENDING') queue_age_seconds,
                 (select count(*) from platform.tenant_intelligence_processing where status='FAILED') tenant_processing_failures,
                 (select count(*) from platform.invitation_email_outbox where status='UNKNOWN') invitation_delivery_unknown
                """);
    }
    @Scheduled(fixedDelayString="${app.intelligence.metrics-poll-ms:30000}")
    public void refresh() {
        if(!background.allowsBackgroundTask("intelligence.metrics")) return;
        TenantContext.runAsPlatform(() -> queryHealth().forEach((key,value) -> values.get(key).set(((Number)value).longValue())));
    }
}
