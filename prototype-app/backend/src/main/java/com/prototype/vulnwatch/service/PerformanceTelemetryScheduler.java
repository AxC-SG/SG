package com.prototype.vulnwatch.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class PerformanceTelemetryScheduler {

    private static final Logger LOG = LoggerFactory.getLogger(PerformanceTelemetryScheduler.class);

    private final PerformanceTelemetryService performanceTelemetryService;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public PerformanceTelemetryScheduler(PerformanceTelemetryService performanceTelemetryService) {
        this.performanceTelemetryService = performanceTelemetryService;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @Scheduled(fixedDelayString = "${app.performance.telemetry-refresh-ms:30000}")
    public void refreshSnapshot() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("performance-telemetry.refresh-snapshot")) {
            return;
        }
        try {
            performanceTelemetryService.refreshFreshnessSnapshot();
        } catch (Exception ex) {
            LOG.warn("Performance telemetry refresh failed; inspect refresh validity and error gauges.");
        }
    }
}
