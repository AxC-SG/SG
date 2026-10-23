package com.prototype.vulnwatch.service;

import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Resumable publication fanout and bounded tenant evaluation on the existing PostgreSQL worker runtime. */
@Service
public class TenantIntelligenceProcessingService {
    @org.springframework.beans.factory.annotation.Autowired
    private FindingDeltaQueueService findingQueue;
    private final JdbcTemplate jdbc;
    private final TenantSchemaExecutionService schemas;
    private final FindingComponentRecomputeService recompute;
    private final BackgroundTaskExecutionPolicy background;
    private final TransactionTemplate transactions;
    public TenantIntelligenceProcessingService(JdbcTemplate jdbc,TenantSchemaExecutionService schemas,
            FindingComponentRecomputeService recompute,BackgroundTaskExecutionPolicy background,PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.schemas=schemas;this.recompute=recompute;this.background=background;
        transactions=new TransactionTemplate(manager);transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transactions.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }
    @Scheduled(fixedDelayString="${app.intelligence.tenant-poll-ms:3000}")
    public void poll() {
        if(!background.allowsBackgroundTask("intelligence.tenant-processing")) return;
        TenantContext.runAsPlatform(() -> {
            transactions.executeWithoutResult(status -> fanoutBatch());
            var tenants=jdbc.queryForList("select p.tenant_id from platform.tenant_intelligence_processing p join platform.tenants t on t.id=p.tenant_id where p.status in ('PENDING','FAILED') and t.status='ACTIVE' and (p.last_error is null or p.updated_at<now()-interval '30 seconds') order by p.updated_at,p.tenant_id limit 10",UUID.class);
            for(UUID tenant:tenants) {
                if(!background.allowsBackgroundTask("intelligence.tenant-batch")) break;
                try { schemas.run(tenant,() -> transactions.execute(status -> evaluate(tenant))); }
                catch(RuntimeException failure) {
                    transactions.executeWithoutResult(status -> jdbc.update("update platform.tenant_intelligence_processing set status='FAILED',last_error='EVALUATION_RETRY_REQUIRED',updated_at=now() where tenant_id=?",tenant));
                }
            }
        });
    }
    private void fanoutBatch() {
        var jobs=jdbc.queryForList("select * from platform.intelligence_publication_outbox where kind='FANOUT' and status='PENDING' order by created_at,id for update skip locked limit 1");
        if(jobs.isEmpty()) return;
        var job=jobs.get(0);
        var tenants=jdbc.queryForList("select id from platform.tenants where (?::uuid is null or id>?::uuid) and status not in ('DELETED','PURGED') order by id limit 50",UUID.class,job.get("after_tenant_id"),job.get("after_tenant_id"));
        for(UUID tenant:tenants) jdbc.update("insert into platform.tenant_intelligence_processing(tenant_id) values(?) on conflict(tenant_id) do update set required_revision=tenant_intelligence_processing.required_revision+1,status='PENDING',last_error=null,updated_at=now()",tenant);
        if(tenants.size()<50) jdbc.update("update platform.intelligence_publication_outbox set status='COMPLETED',completed_at=now() where id=?",job.get("id"));
        else jdbc.update("update platform.intelligence_publication_outbox set after_tenant_id=? where id=?",tenants.get(tenants.size()-1),job.get("id"));
    }
    private int evaluate(UUID tenant) {
        // Consistent lock order with synchronous/delta evaluations.
        var release=jdbc.queryForMap("select release_id,generation from platform.intelligence_active_state where singleton=true for share");
        var rows=jdbc.queryForList("select * from platform.tenant_intelligence_processing where tenant_id=? for update skip locked",tenant);
        if(rows.isEmpty()) return 0;
        var row=rows.get(0);
        long revision=((Number)row.get("required_revision")).longValue();
        long generation=((Number)release.get("generation")).longValue();
        UUID after=(UUID)row.get("after_component_id");
        if(!Objects.equals(row.get("evaluating_revision"),revision) || !Objects.equals(row.get("evaluating_generation"),generation)) after=null;
        var components=jdbc.queryForList("select id from inventory_components where (?::uuid is null or id>?::uuid) order by id limit 100",UUID.class,after,after);
        if(!components.isEmpty()) recompute.recomputeOnSoftwareDeltaBatch(tenant,components);
        if(components.size()<100) {
            findingQueue.enqueueNoiseReductionRefresh(tenant,"intelligence-evaluation");
            jdbc.update("update platform.tenant_intelligence_processing set completed_revision=?,completed_generation=?,evaluating_revision=null,evaluating_generation=null,after_component_id=null,status='COMPLETED',last_completed_at=now(),last_error=null,updated_at=now() where tenant_id=?",revision,generation,tenant);
        } else jdbc.update("update platform.tenant_intelligence_processing set evaluating_revision=?,evaluating_generation=?,after_component_id=?,status='PENDING',last_error=null,updated_at=now() where tenant_id=?",revision,generation,components.get(components.size()-1),tenant);
        return components.size();
    }
    @org.springframework.transaction.annotation.Transactional(readOnly=true)
    public Map<String,Object> status(UUID tenant) {
        return jdbc.queryForMap("select p.*,s.release_id current_release_id,s.generation current_generation from platform.tenant_intelligence_processing p cross join platform.intelligence_active_state s where p.tenant_id=?",tenant);
    }
    @org.springframework.security.access.prepost.PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<Map<String,Object>> processing(UUID release,int page,int size) {
        int bounded=Math.max(1,Math.min(size,200));
        return jdbc.queryForList("select p.*,r.id release_id,r.generation release_generation from platform.tenant_intelligence_processing p join platform.intelligence_releases r on r.id=? order by p.tenant_id limit ? offset ?",release,bounded,(long)Math.max(page,0)*bounded);
    }
}
