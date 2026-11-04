package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.client.http.CheckedOutboundRequestFactory;
import org.springframework.core.task.TaskDecorator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.client.RestTemplate;

@Configuration
public class HttpClientConfig {
    @Value("${app.executors.shutdown-wait-seconds:20}")
    private int shutdownWaitSeconds = 20;

    private void configureShutdown(ThreadPoolTaskExecutor executor) {
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(Math.max(1, shutdownWaitSeconds));
    }

    @Bean
    public CheckedOutboundRequestFactory checkedOutboundRequestFactory(OutboundHostPolicy policy,
            @Value("${app.http.connect-timeout-ms:5000}") long connectTimeoutMs,
            @Value("${app.http.read-timeout-ms:30000}") long readTimeoutMs) {
        return new CheckedOutboundRequestFactory(policy, connectTimeoutMs, readTimeoutMs);
    }

    @Bean
    public RestTemplate restTemplate(
            RestTemplateBuilder builder,
            OutboundHostPolicy outboundHostPolicy,
            CheckedOutboundRequestFactory requestFactory,
            @Value("${app.http.connect-timeout-ms:5000}") long connectTimeoutMs,
            @Value("${app.http.read-timeout-ms:30000}") long readTimeoutMs,
            @Value("${app.http.max-response-bytes:104857600}") long maxResponseBytes,
            @Value("${app.http.max-response-duration-ms:120000}") long maxResponseDurationMs
    ) {
        if (connectTimeoutMs <= 0 || readTimeoutMs <= 0 || maxResponseBytes <= 0 || maxResponseDurationMs <= 0) {
            throw new IllegalArgumentException("Outbound HTTP budgets must be positive");
        }
        return builder
                .requestFactory(() -> requestFactory)
                .additionalInterceptors((request, body, execution) -> {
                    outboundHostPolicy.validateAny(request.getURI());
                    long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(maxResponseDurationMs);
                    return CheckedOutboundRequestFactory.bounded(execution.execute(request, body), maxResponseBytes, deadline);
                })
                .build();
    }

    @Bean
    public OutboundPolicyDefaults outboundPolicyDefaults(
            @Value("${app.http.outbound.min-request-interval-ms:0}") long minRequestIntervalMs,
            @Value("${app.http.outbound.max-retries:3}") int maxRetries,
            @Value("${app.http.outbound.retry-base-backoff-ms:500}") long retryBaseBackoffMs,
            @Value("${app.http.outbound.max-backoff-ms:60000}") long maxBackoffMs,
            @Value("${app.http.outbound.honor-retry-after:true}") boolean honorRetryAfter,
            @Value("${app.http.outbound.retry-on-network-errors:true}") boolean retryOnNetworkErrors
    ) {
        return new OutboundPolicyDefaults(
                minRequestIntervalMs,
                maxRetries,
                retryBaseBackoffMs,
                maxBackoffMs,
                honorRetryAfter,
                retryOnNetworkErrors
        );
    }

    @Bean
    public OutboundPolicyFactory outboundPolicyFactory(OutboundPolicyDefaults outboundPolicyDefaults) {
        return new OutboundPolicyFactory(outboundPolicyDefaults);
    }

    @Bean
    public OutboundHostPolicy outboundHostPolicy(
            @Value("${app.http.outbound.allowed-hosts:}") String allowedHosts
    ) {
        return new OutboundHostPolicy(allowedHosts);
    }

    @Bean
    public OutboundHttpClient outboundHttpClient(RestTemplate restTemplate, OutboundHostPolicy outboundHostPolicy) {
        return new OutboundHttpClient(restTemplate, outboundHostPolicy);
    }

    @Bean(name = {"ingestionExecutor", "sbomJobExecutor"})
    @org.springframework.context.annotation.DependsOn({"dataSource", "ingestionAttemptService"})
    public ThreadPoolTaskExecutor ingestionExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(50);
        executor.setThreadNamePrefix("sbom-job-");
        executor.setTaskDecorator(tenantContextTaskDecorator());
        configureShutdown(executor);
        executor.initialize();
        return executor;
    }

    @Bean(name = {"integrationQueueExecutor", "feedSyncExecutor"})
    @org.springframework.context.annotation.DependsOn({"dataSource", "vulnerabilityAttemptService"})
    public ThreadPoolTaskExecutor integrationQueueExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("integration-queue-");
        executor.setTaskDecorator(tenantContextTaskDecorator());
        configureShutdown(executor);
        executor.initialize();
        return executor;
    }

    @Bean(name = "connectorSyncExecutor")
    @org.springframework.context.annotation.DependsOn({"dataSource", "ingestionAttemptService"})
    public ThreadPoolTaskExecutor connectorSyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("connector-sync-");
        executor.setTaskDecorator(tenantContextTaskDecorator());
        configureShutdown(executor);
        executor.initialize();
        return executor;
    }

    @Bean(name = "aiSecurityJobExecutor")
    @org.springframework.context.annotation.DependsOn({"dataSource", "ingestionAttemptService"})
    public ThreadPoolTaskExecutor aiSecurityJobExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(20);
        executor.setThreadNamePrefix("ai-security-job-");
        executor.setTaskDecorator(tenantContextTaskDecorator());
        configureShutdown(executor);
        executor.initialize();
        return executor;
    }

    @Bean(name = "cbomAssessmentExecutor")
    @org.springframework.context.annotation.DependsOn({"dataSource", "ingestionAttemptService"})
    public ThreadPoolTaskExecutor cbomAssessmentExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(50);
        executor.setThreadNamePrefix("cbom-assessment-");
        executor.setTaskDecorator(tenantContextTaskDecorator());
        configureShutdown(executor);
        executor.initialize();
        return executor;
    }

    static TaskDecorator tenantContextTaskDecorator() {
        return runnable -> {
            TenantContext.Snapshot captured = TenantContext.capture();
            return () -> {
                TenantContext.Snapshot previous = TenantContext.capture();
                try {
                    TenantContext.restore(captured);
                    runnable.run();
                } finally {
                    TenantContext.restore(previous);
                }
            };
        };
    }
}
