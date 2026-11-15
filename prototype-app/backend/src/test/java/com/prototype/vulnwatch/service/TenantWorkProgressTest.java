package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class TenantWorkProgressTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(TenantWorkProgress.class);
    private final ListAppender<ILoggingEvent> lines = new ListAppender<>();
    private TenantWorkProgress progress;

    @BeforeEach
    void setUp() {
        lines.start();
        logger.addAppender(lines);
        progress = new TenantWorkProgress(BackgroundTaskExecutionPolicy.forRole("worker"));
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(lines);
        RequestContextHolder.resetRequestAttributes();
        TenantContext.clear();
    }

    @Test
    void reportsEachOutcomeAndResetsBetweenReports() {
        progress.report();
        progress.track(() -> "ok");
        progress.track(() -> "ok");
        progress.report();
        progress.track(() -> "ok");
        fail();
        progress.report();
        fail();
        progress.report();

        assertThat(messages()).containsExactly(
                "tenant_work_progress outcome=idle succeeded=0 failed=0",
                "tenant_work_progress outcome=healthy succeeded=2 failed=0",
                "tenant_work_progress outcome=degraded succeeded=1 failed=1",
                "tenant_work_progress outcome=failing succeeded=0 failed=1");
    }

    @Test
    void countsOnlyTheOutermostBackgroundCall() {
        progress.track(() -> progress.track(() -> progress.track(() -> "nested")));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        progress.track(() -> "request thread");
        RequestContextHolder.resetRequestAttributes();
        progress.report();

        assertThat(messages()).containsExactly("tenant_work_progress outcome=healthy succeeded=1 failed=0");
    }

    @Test
    void apiNodesDoNotReport() {
        TenantWorkProgress api = new TenantWorkProgress(BackgroundTaskExecutionPolicy.forRole("api"));
        api.track(() -> "ok");
        api.report();

        assertThat(messages()).isEmpty();
    }

    @Test
    void aSchemaOutsideTheSupportedRangeCountsAsFailedTenantWork() {
        TenantService tenants = mock(TenantService.class);
        TenantSchemaService schemas = mock(TenantSchemaService.class);
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setSchemaName("tenant_acme");
        when(schemas.schemaNameForTenant(tenant)).thenReturn("tenant_acme");
        doThrow(new IllegalStateException("Tenant schema is outside this release's supported range V23..V20"))
                .when(schemas).assertSchemaReady("tenant_acme");
        TenantSchemaExecutionService execution = new TenantSchemaExecutionService(tenants, schemas, progress, "FAIL");

        assertThatThrownBy(() -> execution.run(tenant, () -> "never")).isInstanceOf(IllegalStateException.class);
        progress.report();

        assertThat(messages()).containsExactly("tenant_work_progress outcome=failing succeeded=0 failed=1");
    }

    private void fail() {
        assertThatThrownBy(() -> progress.track(() -> {
            throw new IllegalStateException("tenant job failed");
        })).isInstanceOf(IllegalStateException.class);
    }

    private List<String> messages() {
        return lines.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }
}
