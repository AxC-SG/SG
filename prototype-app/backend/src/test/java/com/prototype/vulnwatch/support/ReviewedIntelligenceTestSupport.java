package com.prototype.vulnwatch.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.*;
import jakarta.persistence.EntityManager;
import java.util.*;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.test.util.ReflectionTestUtils;

/** Approves deterministic offline fixtures through the same immutable review contract as an owner. */
public final class ReviewedIntelligenceTestSupport {
    private ReviewedIntelligenceTestSupport() { }
    private static IntelligencePublicationService worker(ApplicationContext context) {
        var worker=new IntelligencePublicationService(context.getBean(JdbcTemplate.class),context.getBean(ObjectMapper.class),context.getBean(ObservationIngestionService.class),context.getBean(VexAssertionService.class),context.getBean(EntityManager.class),BackgroundTaskExecutionPolicy.allowAll(),context.getBean(PlatformTransactionManager.class));
        ReflectionTestUtils.setField(worker,"summaries",context.getBean(VulnerabilityIntelSummaryService.class));
        return worker;
    }
    public static void withdrawActive(ApplicationContext context) {
        UUID release=context.getBean(JdbcTemplate.class).queryForObject("select release_id from platform.intelligence_active_state",UUID.class);
        context.getBean(IntelligencePublicationService.class).withdraw(release,UUID.randomUUID().toString(),"offline-test-owner");
        worker(context).poll();
    }
    public static void publishAll(ApplicationContext context) {
        var previous=SecurityContextHolder.getContext();
        var security=SecurityContextHolder.createEmptyContext();
        security.setAuthentication(new UsernamePasswordAuthenticationToken("offline-test-owner","",List.of(new SimpleGrantedAuthority("ROLE_PLATFORM_OWNER"))));
        SecurityContextHolder.setContext(security);
        try {
            var jdbc=context.getBean(JdbcTemplate.class);
            List<UUID> runs=jdbc.queryForList("select id from platform.sync_runs where lower(status) in ('completed','success') and sync_type not like 'EOL_%' and run_scope='PLATFORM_VULNERABILITY' and id not in (select sync_run_id from platform.intelligence_published_runs)",UUID.class);
            if(runs.isEmpty()) return;
            var service=context.getBean(IntelligencePublicationService.class);
            var worker=worker(context);
            UUID candidate=(UUID)service.createCandidate(runs,"offline-test-owner").get("id");
            worker.poll();
            var reviewed=service.candidate(candidate);
            if(!"READY".equals(reviewed.get("status"))) throw new AssertionError("Offline fixture candidate: "+reviewed);
            service.publish(candidate,(String)reviewed.get("digest"),(UUID)reviewed.get("base_release_id"),UUID.randomUUID().toString(),"offline-test-owner");
            worker.poll();
            if(!"PUBLISHED".equals(service.candidate(candidate).get("status"))) throw new AssertionError("Offline fixture did not publish");
        } finally {SecurityContextHolder.setContext(previous);}
    }
}
