package com.prototype.vulnwatch.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.service.TenantContext;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskDecorator;

class HttpClientConfigTest {
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"ingestion", "integration", "connector", "ai"})
    void everyExecutorDrainsAcceptedQueuedWork(String name) throws Exception {
        HttpClientConfig config = new HttpClientConfig();
        var executor = switch (name) {
            case "ingestion" -> config.ingestionExecutor();
            case "integration" -> config.integrationQueueExecutor();
            case "connector" -> config.connectorSyncExecutor();
            case "ai" -> config.aiSecurityJobExecutor();
            default -> throw new IllegalArgumentException(name);
        };
        var started = new java.util.concurrent.CountDownLatch(executor.getCorePoolSize());
        var release = new java.util.concurrent.CountDownLatch(1);
        var completed = new java.util.concurrent.CountDownLatch(1);
        try {
            for (int i = 0; i < executor.getCorePoolSize(); i++) executor.execute(() -> {
                started.countDown();
                try { release.await(5, java.util.concurrent.TimeUnit.SECONDS); }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); }
            });
            org.junit.jupiter.api.Assertions.assertTrue(started.await(5, java.util.concurrent.TimeUnit.SECONDS));
            executor.execute(completed::countDown);
            var closed = java.util.concurrent.CompletableFuture.runAsync(executor::shutdown);
            long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
            while(!executor.getThreadPoolExecutor().isShutdown() && System.nanoTime()<deadline) Thread.sleep(1);
            release.countDown();
            closed.get(5, java.util.concurrent.TimeUnit.SECONDS);
            org.junit.jupiter.api.Assertions.assertEquals(0, completed.getCount());
        } finally { release.countDown(); executor.shutdown(); }
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void tenantContextTaskDecoratorCopiesAndRestoresContext() {
        UUID tenantId = UUID.randomUUID();
        TenantContext.setCurrentTenantId(tenantId);
        TenantContext.setCurrentSchemaName("tenant_acme");
        TaskDecorator decorator = HttpClientConfig.tenantContextTaskDecorator();
        Runnable decorated = decorator.decorate(() -> {
            assertThat(TenantContext.getCurrentTenantId()).isEqualTo(tenantId);
            assertThat(TenantContext.getCurrentSchemaName()).isEqualTo("tenant_acme");
        });

        TenantContext.clear();
        decorated.run();

        assertThat(TenantContext.getCurrentTenantId()).isNull();
        assertThat(TenantContext.getCurrentSchemaName()).isNull();
    }

    @Test
    void tenantContextTaskDecoratorCopiesPlatformContext() {
        TaskDecorator decorator = HttpClientConfig.tenantContextTaskDecorator();
        Runnable decorated = TenantContext.runAsPlatform(
                () -> decorator.decorate(() -> assertThat(TenantContext.isPlatformContext()).isTrue())
        );

        decorated.run();

        assertThat(TenantContext.isPlatformContext()).isFalse();
    }
}
