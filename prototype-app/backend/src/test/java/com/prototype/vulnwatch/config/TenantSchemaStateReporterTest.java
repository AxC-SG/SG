package com.prototype.vulnwatch.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.prototype.vulnwatch.migration.PackagedMigrationCatalog;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantSchemaStatusService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class TenantSchemaStateReporterTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(TenantSchemaStateReporter.class);
    private final ListAppender<ILoggingEvent> lines = new ListAppender<>();
    private final PackagedMigrationCatalog catalog = new PackagedMigrationCatalog();
    private final TenantSchemaStatusService status = mock(TenantSchemaStatusService.class);

    @BeforeEach
    void setUp() {
        lines.start();
        logger.addAppender(lines);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(lines);
    }

    @Test
    void reportsTheControlPlaneViewThatReadinessHides() {
        when(status.readinessFailures(catalog.tenantTarget())).thenReturn(2L);
        when(status.supportedTenantVersions()).thenReturn("23..20");
        when(status.activeTenantVersions()).thenReturn("23..23");

        reporter("worker").report();

        assertThat(messages()).containsExactly("tenant_schema_state unready_tenants=2 supported=23..20 active_versions=23..23 packaged_target="
                + catalog.tenantTarget());
    }

    @Test
    void apiNodesDoNotReport() {
        reporter("api").report();

        assertThat(messages()).isEmpty();
    }

    @Test
    void anUnavailableControlPlaneIsReportedNotThrown() {
        when(status.readinessFailures(catalog.tenantTarget())).thenThrow(new IllegalStateException("control plane down"));

        reporter("worker").report();

        assertThat(messages()).containsExactly("tenant_schema_state unavailable: control plane down");
    }

    private TenantSchemaStateReporter reporter(String role) {
        return new TenantSchemaStateReporter(status, catalog, BackgroundTaskExecutionPolicy.forRole(role));
    }

    private java.util.List<String> messages() {
        return lines.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }
}
