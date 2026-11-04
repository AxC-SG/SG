package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.*;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Claims CBOM_ASSESSMENT jobs per tenant and runs them on the dedicated executor.
 *
 * <p>Fairness: each poll claims at most {@code per-tenant-claim-limit} jobs per tenant and
 * rotates the tenant start position, so a saturated executor does not always starve the same
 * tail of the tenant list. Claims stop while the executor has no free queue slot, so capacity
 * pressure does not burn job attempts. Transient failures retry with exponential backoff up to
 * {@code max-attempts}; a missing or non-CBOM artifact fails immediately.
 */
@Service
public class CbomAssessmentWorkerService {
    private static final Logger LOG=LoggerFactory.getLogger(CbomAssessmentWorkerService.class);
    private final IngestionJobService jobs; private final TenantService tenants; private final TenantSchemaExecutionService schemas;
    private final CbomAssessmentService assessments; private final TaskExecutor executor; private final TransactionTemplate transactions;
    private CbomOperationsMetrics metrics;
    private CbomReportService reports;
    private BackgroundTaskExecutionPolicy policy=BackgroundTaskExecutionPolicy.allowAll();
    private boolean enabled=true;
    private int perTenantClaimLimit=1;
    private int maxConcurrentPerTenant=1;
    private int maxAttempts=3;
    private long retryBaseSeconds=30;
    private long backlogSampleIntervalMs=30_000;
    private volatile long lastBacklogSampleAt;
    private final AtomicInteger rotation=new AtomicInteger();

    public CbomAssessmentWorkerService(IngestionJobService jobs,TenantService tenants,TenantSchemaExecutionService schemas,
            CbomAssessmentService assessments,@Qualifier("cbomAssessmentExecutor") TaskExecutor executor,TransactionTemplate transactions){
        this.jobs=jobs;this.tenants=tenants;this.schemas=schemas;this.assessments=assessments;this.executor=executor;this.transactions=transactions;
    }
    @org.springframework.beans.factory.annotation.Autowired public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy value){policy=value==null?BackgroundTaskExecutionPolicy.allowAll():value;}
    @org.springframework.beans.factory.annotation.Autowired(required=false) public void setMetrics(CbomOperationsMetrics value){metrics=value;}
    /** Report generation shares the dedicated CBOM executor and per-tenant claim limits. */
    @org.springframework.beans.factory.annotation.Autowired(required=false) public void setReports(CbomReportService value){reports=value;}
    @org.springframework.beans.factory.annotation.Value("${app.cbom.assessment.enabled:true}") public void setEnabled(boolean value){enabled=value;}
    @org.springframework.beans.factory.annotation.Value("${app.cbom.assessment.per-tenant-claim-limit:1}") public void setPerTenantClaimLimit(int value){perTenantClaimLimit=Math.max(1,value);}
    @org.springframework.beans.factory.annotation.Value("${app.cbom.assessment.max-concurrent-per-tenant:1}") public void setMaxConcurrentPerTenant(int value){maxConcurrentPerTenant=Math.max(1,value);}
    @org.springframework.beans.factory.annotation.Value("${app.cbom.assessment.max-attempts:3}") public void setMaxAttempts(int value){maxAttempts=Math.max(1,value);}
    @org.springframework.beans.factory.annotation.Value("${app.cbom.assessment.retry-base-seconds:30}") public void setRetryBaseSeconds(long value){retryBaseSeconds=Math.max(1,value);}
    @org.springframework.beans.factory.annotation.Value("${app.cbom.assessment.backlog-sample-interval-ms:30000}") public void setBacklogSampleIntervalMs(long value){backlogSampleIntervalMs=Math.max(0,value);}

    @Scheduled(fixedDelayString="${app.cbom.assessment.poll-interval-ms:2000}")
    public void poll(){
        if(!enabled||!policy.allowsBackgroundTask("cbom-assessment.poll"))return;
        try{TenantContext.runAsPlatform(()->{
            List<Tenant> active=tenants.listActiveTenants();
            int size=active.size();
            if(size==0)return null;
            int start=Math.floorMod(rotation.getAndIncrement(),size);
            for(int offset=0;offset<size;offset++){
                Tenant tenant=active.get((start+offset)%size);
                if(!hasCapacity()){metrics(m->m.recordExecutorRejection());break;}
                for(String type:reports==null?List.of(IngestionJobService.JOB_TYPE_CBOM_ASSESSMENT)
                        :List.of(IngestionJobService.JOB_TYPE_CBOM_ASSESSMENT,IngestionJobService.JOB_TYPE_CBOM_REPORT)){
                    try{
                        List<IngestionJobService.ClaimedJobRef> claimed=jobs.claimPendingJobsByType(tenant,type,perTenantClaimLimit,maxConcurrentPerTenant);
                        if(!claimed.isEmpty())metrics(m->m.recordClaims(claimed.size()));
                        for(IngestionJobService.ClaimedJobRef ref:claimed){
                            Runnable work=IngestionJobService.JOB_TYPE_CBOM_REPORT.equals(type)?()->executeReport(ref):()->execute(ref);
                            try{executor.execute(work);}catch(RejectedExecutionException busy){
                                metrics(m->m.recordExecutorRejection());
                                jobs.retryRejectedClaim(ref,"EXECUTOR_BUSY","CBOM executor is at capacity",Instant.now().plusSeconds(5));
                            }
                        }
                    }catch(Exception failure){LOG.warn("CBOM {} claim failed for tenant {}: {}",type,tenant.getId(),failure.getMessage());}
                }
            }
            sampleBacklog(active);
            return null;});}catch(Exception failure){LOG.warn("CBOM assessment poll failed: {}",failure.getMessage(),failure);}
    }

    void execute(IngestionJobService.ClaimedJobRef ref){
        Tenant tenant=tenants.resolveTenantUuid(ref.tenantId());
        Instant started=Instant.now();
        try(var ignored=jobs.openAttempt(ref.tenantId(),ref.jobId(),ref.claimToken())){
            try{
                schemas.run(tenant,()->transactions.execute(status->{
                    IngestionJob job=jobs.loadJob(ref.tenantId(),ref.jobId());jobs.recordStarted(job);
                    IngestionJobPayloads.CbomAssessmentPayload payload=jobs.readPayload(job,IngestionJobPayloads.CbomAssessmentPayload.class);
                    var result=assessments.assess(tenant,payload.bomId());
                    jobs.markSucceeded(ref.tenantId(),ref.jobId(),null,jobs.toJson(java.util.Map.of("assessmentRunId",result.id(),"bomId",result.bomId(),"status",result.status())));
                    return null;
                }));
                schemas.run(tenant,()->{jobs.recordCompleted(jobs.loadJob(ref.tenantId(),ref.jobId()));return null;});
                metrics(m->m.recordJobOutcome("succeeded"));
            }catch(Exception failure){
                handleFailure(tenant,ref,failure);
            }
        }finally{
            metrics(m->m.recordDuration(Duration.between(started,Instant.now())));
        }
    }

    void executeReport(IngestionJobService.ClaimedJobRef ref){
        Tenant tenant=tenants.resolveTenantUuid(ref.tenantId());
        try(var ignored=jobs.openAttempt(ref.tenantId(),ref.jobId(),ref.claimToken())){
            try{
                schemas.run(tenant,()->transactions.execute(status->{
                    IngestionJob job=jobs.loadJob(ref.tenantId(),ref.jobId());jobs.recordStarted(job);
                    IngestionJobPayloads.CbomReportPayload payload=jobs.readPayload(job,IngestionJobPayloads.CbomReportPayload.class);
                    reports.generate(tenant,payload.reportId());
                    jobs.markSucceeded(ref.tenantId(),ref.jobId(),null,jobs.toJson(java.util.Map.of("reportId",payload.reportId())));
                    return null;
                }));
                schemas.run(tenant,()->{jobs.recordCompleted(jobs.loadJob(ref.tenantId(),ref.jobId()));return null;});
            }catch(Exception failure){
                handleFailure(tenant,ref,failure);
                schemas.run(tenant,()->transactions.execute(status->{
                    IngestionJob job=jobs.loadJob(ref.tenantId(),ref.jobId());
                    if(IngestionJobService.STATUS_FAILED.equals(job.getStatus())){
                        reports.markFailed(jobs.readPayload(job,IngestionJobPayloads.CbomReportPayload.class).reportId(),failure.getMessage());
                    }
                    return null;
                }));
            }
        }
    }

    private void handleFailure(Tenant tenant,IngestionJobService.ClaimedJobRef ref,Exception failure){
        String message=failure.getMessage()==null?"CBOM assessment failed":failure.getMessage();
        schemas.run(tenant,()->{
            IngestionJob job=jobs.loadJob(ref.tenantId(),ref.jobId());
            boolean permanent=failure instanceof IllegalArgumentException;
            if(!permanent&&job.getAttemptCount()<maxAttempts){
                long backoff=retryBaseSeconds*(1L<<Math.min(10,Math.max(0,job.getAttemptCount()-1)));
                jobs.markQueuedForRetry(ref.tenantId(),ref.jobId(),"CBOM_ASSESSMENT_RETRY",message,Instant.now().plusSeconds(backoff));
                metrics(m->m.recordJobOutcome("retried"));
                LOG.warn("CBOM assessment job {} retry {}/{} in {}s: {}",ref.jobId(),job.getAttemptCount(),maxAttempts,backoff,message);
            }else{
                jobs.markFailed(ref.tenantId(),ref.jobId(),"CBOM_ASSESSMENT_FAILED",message);
                jobs.recordFailed(jobs.loadJob(ref.tenantId(),ref.jobId()));
                metrics(m->m.recordJobOutcome("failed"));
            }
            return null;
        });
    }

    private boolean hasCapacity(){
        if(executor instanceof ThreadPoolTaskExecutor pool&&pool.getThreadPoolExecutor()!=null){
            var threads=pool.getThreadPoolExecutor();
            return threads.getActiveCount()<threads.getMaximumPoolSize()||threads.getQueue().remainingCapacity()>0;
        }
        return true;
    }

    /** Queue depth/age gauges, sampled at most every backlog-sample-interval-ms. */
    void sampleBacklog(List<Tenant> active){
        if(metrics==null)return;
        long now=System.currentTimeMillis();
        if(now-lastBacklogSampleAt<backlogSampleIntervalMs)return;
        lastBacklogSampleAt=now;
        long queued=0,backlogged=0;Instant oldest=null;
        for(Tenant tenant:active){
            try{
                IngestionJobService.JobTypeBacklog backlog=jobs.backlogByType(tenant,IngestionJobService.JOB_TYPE_CBOM_ASSESSMENT);
                if(backlog==null)continue;
                queued+=backlog.queued();
                if(backlog.queued()>0)backlogged++;
                if(backlog.oldestVisibleQueuedAt()!=null&&(oldest==null||backlog.oldestVisibleQueuedAt().isBefore(oldest)))oldest=backlog.oldestVisibleQueuedAt();
            }catch(Exception failure){LOG.debug("CBOM backlog sample failed for tenant {}: {}",tenant.getId(),failure.getMessage());}
        }
        long age=oldest==null?0:Duration.between(oldest,Instant.now()).toSeconds();
        metrics.publishBacklog(queued,age,backlogged);
    }

    private void metrics(java.util.function.Consumer<CbomOperationsMetrics> action){if(metrics!=null)action.accept(metrics);}
}
