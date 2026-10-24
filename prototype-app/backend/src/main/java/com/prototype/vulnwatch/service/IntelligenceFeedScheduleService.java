package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IntelligenceFeedScheduleService {
    private final JdbcTemplate jdbc;
    private final VulnerabilitySyncRunService runs;
    private final BackgroundTaskExecutionPolicy background;
    public IntelligenceFeedScheduleService(JdbcTemplate jdbc,VulnerabilitySyncRunService runs,BackgroundTaskExecutionPolicy background) { this.jdbc=jdbc;this.runs=runs;this.background=background; }
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<Map<String,Object>> list() { return jdbc.queryForList("select * from platform.intelligence_feed_schedules order by sync_type"); }
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional
    public Map<String,Object> save(String type,boolean enabled,int interval,String actor) {
        if(interval<1 || interval>8760) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Interval must be between 1 and 8760 hours");
        if(jdbc.update("update platform.intelligence_feed_schedules set enabled=?,interval_hours=?,updated_at=now(),updated_by=?,next_due_at=now()+make_interval(hours=>?) where sync_type=?",enabled,interval,actor,interval,type)!=1)
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND,"Unknown feed schedule");
        jdbc.update("insert into platform.intelligence_audit_events(id,action,actor,detail) values(?,'SCHEDULE_UPDATED',?,jsonb_build_object('source',?::text,'enabled',?::boolean,'intervalHours',?::integer))",UUID.randomUUID(),actor,type,enabled,interval);
        return jdbc.queryForMap("select * from platform.intelligence_feed_schedules where sync_type=?",type);
    }
    @Scheduled(fixedDelayString="${app.intelligence.schedule-poll-ms:60000}")
    public void poll() {
        if(!background.allowsBackgroundTask("intelligence.feed-schedules")) return;
        TenantContext.runAsPlatform(() -> jdbc.queryForList("select sync_type from platform.intelligence_feed_schedules where enabled and next_due_at<=now() order by next_due_at limit 20",String.class)
                .forEach(type -> runs.prepareScheduledRun(type,Instant.now())));
    }
}
