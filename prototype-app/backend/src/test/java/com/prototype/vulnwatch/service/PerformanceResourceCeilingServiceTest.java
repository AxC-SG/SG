package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

class PerformanceResourceCeilingServiceTest {

    @Test
    void buildTreatsSingleThreadExecutorWithoutBacklogAsHealthy() {
        ThreadPoolExecutor delegate = mock(ThreadPoolExecutor.class);
        when(delegate.getActiveCount()).thenReturn(1);
        when(delegate.getMaximumPoolSize()).thenReturn(1);
        when(delegate.getQueue()).thenReturn(new LinkedBlockingQueue<>());

        ThreadPoolTaskExecutor integrationExecutor = mock(ThreadPoolTaskExecutor.class);
        when(integrationExecutor.getThreadPoolExecutor()).thenReturn(delegate);

        PerformanceResourceCeilingService service = new PerformanceResourceCeilingService(
                provider(null),
                provider(null),
                provider(integrationExecutor),
                provider(null),
                75.0,
                80.0,
                0.0,
                80.0,
                85.0
        );

        var item = service.build().stream()
                .filter(entry -> "executor-integration-queue-active".equals(entry.key()))
                .findFirst()
                .orElseThrow();

        assertEquals("PASS", item.status());
        assertTrue(item.compliant());
        assertTrue(item.note().contains("no queued backlog"));
    }

    @Test
    void buildReportsNoBacklogForDirectHandoffExecutor() {
        ThreadPoolTaskExecutor ingestionExecutor = new ThreadPoolTaskExecutor();
        ingestionExecutor.setQueueCapacity(0);
        ingestionExecutor.initialize();
        try {
            PerformanceResourceCeilingService service = new PerformanceResourceCeilingService(
                    provider(null), provider(ingestionExecutor), provider(null), provider(null),
                    75.0, 80.0, 0.0, 80.0, 85.0);
            var queue = service.build().stream()
                    .filter(entry -> "executor-ingestion-queue".equals(entry.key()))
                    .findFirst()
                    .orElseThrow();
            assertEquals("PASS", queue.status());
            assertEquals(0.0, queue.currentValue());
            assertTrue(queue.note().contains("no in-memory backlog"));
        } finally {
            ingestionExecutor.shutdown();
        }
    }

    @SuppressWarnings("unchecked")
    private <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }
}
