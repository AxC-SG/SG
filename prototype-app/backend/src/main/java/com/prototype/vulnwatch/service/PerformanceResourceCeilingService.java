package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.PerformanceResourceCeilingItemResponse;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;

@Service
public class PerformanceResourceCeilingService {

    private final ObjectProvider<HikariDataSource> hikariDataSourceProvider;
    private final ObjectProvider<ThreadPoolTaskExecutor> ingestionExecutorProvider;
    private final ObjectProvider<ThreadPoolTaskExecutor> integrationQueueExecutorProvider;
    private final ObjectProvider<ThreadPoolTaskExecutor> connectorSyncExecutorProvider;
    private final double heapMaxUtilizationPct;
    private final double dbPoolMaxUtilizationPct;
    private final double dbPoolMaxPendingThreads;
    private final double executorQueueMaxUtilizationPct;
    private final double executorActiveMaxUtilizationPct;

    public PerformanceResourceCeilingService(
            ObjectProvider<HikariDataSource> hikariDataSourceProvider,
            @Qualifier("ingestionExecutor") ObjectProvider<ThreadPoolTaskExecutor> ingestionExecutorProvider,
            @Qualifier("integrationQueueExecutor") ObjectProvider<ThreadPoolTaskExecutor> integrationQueueExecutorProvider,
            @Qualifier("connectorSyncExecutor") ObjectProvider<ThreadPoolTaskExecutor> connectorSyncExecutorProvider,
            @Value("${app.performance.heap-max-utilization-pct:75}") double heapMaxUtilizationPct,
            @Value("${app.performance.db-pool-max-utilization-pct:80}") double dbPoolMaxUtilizationPct,
            @Value("${app.performance.db-pool-max-pending-threads:0}") double dbPoolMaxPendingThreads,
            @Value("${app.performance.executor-queue-max-utilization-pct:80}") double executorQueueMaxUtilizationPct,
            @Value("${app.performance.executor-active-max-utilization-pct:85}") double executorActiveMaxUtilizationPct
    ) {
        this.hikariDataSourceProvider = hikariDataSourceProvider;
        this.ingestionExecutorProvider = ingestionExecutorProvider;
        this.integrationQueueExecutorProvider = integrationQueueExecutorProvider;
        this.connectorSyncExecutorProvider = connectorSyncExecutorProvider;
        this.heapMaxUtilizationPct = heapMaxUtilizationPct;
        this.dbPoolMaxUtilizationPct = dbPoolMaxUtilizationPct;
        this.dbPoolMaxPendingThreads = dbPoolMaxPendingThreads;
        this.executorQueueMaxUtilizationPct = executorQueueMaxUtilizationPct;
        this.executorActiveMaxUtilizationPct = executorActiveMaxUtilizationPct;
    }

    public List<PerformanceResourceCeilingItemResponse> build() {
        List<PerformanceResourceCeilingItemResponse> items = new ArrayList<>();
        items.add(heapUtilizationItem());
        items.add(processCpuItem());
        items.add(dbPoolActiveUtilizationItem());
        items.add(dbPoolPendingThreadsItem());
        items.add(executorActiveUtilizationItem("executor-ingestion-active", "Ingestion Executor Active Utilization", ingestionExecutorProvider));
        items.add(executorQueueUtilizationItem("executor-ingestion-queue", "Ingestion Executor Queue Utilization", ingestionExecutorProvider));
        items.add(executorActiveUtilizationItem("executor-integration-queue-active", "Integration Queue Executor Active Utilization", integrationQueueExecutorProvider));
        items.add(executorQueueUtilizationItem("executor-integration-queue", "Integration Queue Executor Queue Utilization", integrationQueueExecutorProvider));
        items.add(executorActiveUtilizationItem("executor-connector-sync-active", "Connector Sync Executor Active Utilization", connectorSyncExecutorProvider));
        items.add(executorQueueUtilizationItem("executor-connector-sync-queue", "Connector Sync Executor Queue Utilization", connectorSyncExecutorProvider));
        return List.copyOf(items);
    }

    private PerformanceResourceCeilingItemResponse heapUtilizationItem() {
        Runtime runtime = Runtime.getRuntime();
        long maxBytes = runtime.maxMemory();
        if (maxBytes <= 0L) {
            return noData("jvm-heap-utilization", "JVM Heap Utilization", "jvm", "%", heapMaxUtilizationPct,
                    "The JVM did not report a finite heap ceiling.");
        }
        long usedBytes = runtime.totalMemory() - runtime.freeMemory();
        double currentPct = percentage(usedBytes, maxBytes);
        return item(
                "jvm-heap-utilization",
                "JVM Heap Utilization",
                "jvm",
                "%",
                heapMaxUtilizationPct,
                currentPct,
                currentPct <= heapMaxUtilizationPct,
                "Used " + toMegabytes(usedBytes) + " MB of " + toMegabytes(maxBytes) + " MB max heap."
        );
    }

    private PerformanceResourceCeilingItemResponse processCpuItem() {
        OperatingSystemMXBean operatingSystemMXBean = ManagementFactory.getOperatingSystemMXBean();
        if (operatingSystemMXBean instanceof com.sun.management.OperatingSystemMXBean extended) {
            double processCpuLoad = extended.getProcessCpuLoad();
            if (processCpuLoad >= 0.0d) {
                double currentPct = round2(processCpuLoad * 100.0d);
                double targetPct = 80.0d;
                return item(
                        "process-cpu-utilization",
                        "Process CPU Utilization",
                        "process",
                        "%",
                        targetPct,
                        currentPct,
                        currentPct <= targetPct,
                        "Process CPU load sampled from the JVM operating-system bean."
                );
            }
        }
        return noData(
                "process-cpu-utilization",
                "Process CPU Utilization",
                "process",
                "%",
                80.0d,
                "The current JVM could not provide process CPU utilization."
        );
    }

    private PerformanceResourceCeilingItemResponse dbPoolActiveUtilizationItem() {
        HikariDataSource hikariDataSource = hikariDataSourceProvider.getIfAvailable();
        if (hikariDataSource == null || hikariDataSource.getHikariPoolMXBean() == null) {
            return noData("db-pool-active-utilization", "DB Pool Active Utilization", "database", "%",
                    dbPoolMaxUtilizationPct, "Hikari pool metrics are not available in the current runtime.");
        }
        int activeConnections = hikariDataSource.getHikariPoolMXBean().getActiveConnections();
        int maxConnections = hikariDataSource.getMaximumPoolSize();
        if (maxConnections <= 0) {
            return noData("db-pool-active-utilization", "DB Pool Active Utilization", "database", "%",
                    dbPoolMaxUtilizationPct, "The Hikari pool has no configured maximum size.");
        }
        double currentPct = percentage(activeConnections, maxConnections);
        return item(
                "db-pool-active-utilization",
                "DB Pool Active Utilization",
                "database",
                "%",
                dbPoolMaxUtilizationPct,
                currentPct,
                currentPct <= dbPoolMaxUtilizationPct,
                "Active connections " + activeConnections + " of " + maxConnections + "."
        );
    }

    private PerformanceResourceCeilingItemResponse dbPoolPendingThreadsItem() {
        HikariDataSource hikariDataSource = hikariDataSourceProvider.getIfAvailable();
        if (hikariDataSource == null || hikariDataSource.getHikariPoolMXBean() == null) {
            return noData("db-pool-pending-threads", "DB Pool Pending Threads", "database", "threads",
                    dbPoolMaxPendingThreads, "Hikari pool metrics are not available in the current runtime.");
        }
        int pendingThreads = hikariDataSource.getHikariPoolMXBean().getThreadsAwaitingConnection();
        return item(
                "db-pool-pending-threads",
                "DB Pool Pending Threads",
                "database",
                "threads",
                dbPoolMaxPendingThreads,
                pendingThreads,
                pendingThreads <= dbPoolMaxPendingThreads,
                "Threads currently waiting for a database connection from Hikari."
        );
    }

    private PerformanceResourceCeilingItemResponse executorActiveUtilizationItem(
            String key,
            String label,
            ObjectProvider<ThreadPoolTaskExecutor> executorProvider
    ) {
        ThreadPoolExecutor executor = resolveThreadPoolExecutor(executorProvider);
        if (executor == null) {
            return noData(key, label, "executor", "%", executorActiveMaxUtilizationPct,
                    "Thread-pool metrics are not available in the current runtime.");
        }
        int activeCount = executor.getActiveCount();
        int maxPoolSize = executor.getMaximumPoolSize();
        if (maxPoolSize <= 0) {
            return noData(key, label, "executor", "%", executorActiveMaxUtilizationPct,
                    "Thread-pool maximum size is not configured.");
        }
        double currentPct = percentage(activeCount, maxPoolSize);
        int queueSize = executor.getQueue() == null ? 0 : executor.getQueue().size();
        boolean singleThreadBusyWithoutBacklog = maxPoolSize == 1 && activeCount == 1 && queueSize == 0;
        boolean compliant = currentPct <= executorActiveMaxUtilizationPct || singleThreadBusyWithoutBacklog;
        return item(
                key,
                label,
                "executor",
                "%",
                executorActiveMaxUtilizationPct,
                currentPct,
                compliant,
                singleThreadBusyWithoutBacklog
                        ? "Single-thread executor is actively processing work with no queued backlog."
                        : "Active threads " + activeCount + " of " + maxPoolSize + "."
        );
    }

    private PerformanceResourceCeilingItemResponse executorQueueUtilizationItem(
            String key,
            String label,
            ObjectProvider<ThreadPoolTaskExecutor> executorProvider
    ) {
        ThreadPoolExecutor executor = resolveThreadPoolExecutor(executorProvider);
        if (executor == null || executor.getQueue() == null) {
            return noData(key, label, "executor", "%", executorQueueMaxUtilizationPct,
                    "Thread-pool queue metrics are not available in the current runtime.");
        }
        int queueSize = executor.getQueue().size();
        if (executor.getQueue() instanceof SynchronousQueue<?>) {
            return item(key, label, "executor", "%", executorQueueMaxUtilizationPct, 0.0, true,
                    "Direct handoff executor has no in-memory backlog.");
        }
        int queueCapacity = queueSize + executor.getQueue().remainingCapacity();
        if (queueCapacity <= 0) {
            return noData(key, label, "executor", "%", executorQueueMaxUtilizationPct,
                    "Thread-pool queue capacity is not finite.");
        }
        double currentPct = percentage(queueSize, queueCapacity);
        return item(
                key,
                label,
                "executor",
                "%",
                executorQueueMaxUtilizationPct,
                currentPct,
                currentPct <= executorQueueMaxUtilizationPct,
                "Queued tasks " + queueSize + " of " + queueCapacity + "."
        );
    }

    private ThreadPoolExecutor resolveThreadPoolExecutor(ObjectProvider<ThreadPoolTaskExecutor> executorProvider) {
        ThreadPoolTaskExecutor taskExecutor = executorProvider.getIfAvailable();
        if (taskExecutor == null) {
            return null;
        }
        try {
            return taskExecutor.getThreadPoolExecutor();
        } catch (IllegalStateException ignored) {
            return null;
        }
    }

    private PerformanceResourceCeilingItemResponse item(
            String key,
            String label,
            String category,
            String unit,
            double targetValue,
            double currentValue,
            boolean compliant,
            String note
    ) {
        return new PerformanceResourceCeilingItemResponse(
                key,
                label,
                category,
                compliant ? "PASS" : "FAIL",
                unit,
                round2(targetValue),
                round2(currentValue),
                compliant,
                note
        );
    }

    private PerformanceResourceCeilingItemResponse noData(
            String key,
            String label,
            String category,
            String unit,
            double targetValue,
            String note
    ) {
        return new PerformanceResourceCeilingItemResponse(
                key,
                label,
                category,
                "NO_DATA",
                unit,
                round2(targetValue),
                0.0d,
                false,
                note
        );
    }

    private double percentage(long current, long total) {
        if (total <= 0L) {
            return 0.0d;
        }
        return round2((current * 100.0d) / total);
    }

    private long toMegabytes(long bytes) {
        return Math.max(0L, bytes / (1024L * 1024L));
    }

    private double round2(double value) {
        return Math.round(value * 100.0d) / 100.0d;
    }
}
