package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;

class EpssRefreshServiceTest {
    private final OutboundHttpClient transport=mock(OutboundHttpClient.class);
    private final VulnerabilitySyncRunService runs=mock(VulnerabilitySyncRunService.class);
    private final EpssRefreshService service=new EpssRefreshService(mock(VulnerabilityRepository.class),
            mock(FindingDeltaQueueService.class),transport,mock(OutboundPolicyFactory.class),new ObjectMapper());

    @Test void disabledScheduleReportsDisabledWithoutAcceptingOrExecutingWork() {
        service.configureDurableRuns(runs,mock(PlatformTransactionManager.class));
        ReflectionTestUtils.setField(service,"enabled",false);
        service.refreshAll();
        assertEquals("DISABLED",service.lastRefresh().status());
        verifyNoInteractions(runs,transport);
    }

    @Test void eligibleScheduleOnlyPersistsIntentAndApiRoleDoesNothing() {
        service.configureDurableRuns(runs,mock(PlatformTransactionManager.class));
        ReflectionTestUtils.setField(service,"enabled",true);
        ReflectionTestUtils.setField(service,"refreshCron","* * * * * *");
        service.setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy.forRole("api"));
        service.refreshAll();
        verifyNoInteractions(runs,transport);
        service.setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy.forRole("worker"));
        service.refreshAll();
        verify(runs).prepareScheduledRun(eq("EPSS"),any(java.time.Instant.class));
        verifyNoInteractions(transport);
    }
}
