package com.prototype.vulnwatch.service;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer;
import java.util.Arrays;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

/** Exercises Spring injection, since manually setting the policy misses a lost @Autowired annotation. */
class CloudDiscoveryRuntimeRoleTest {

    @ParameterizedTest
    @ValueSource(strings = {"api", "schema-migrator", "worker"})
    void awsDiscoveryHonorsTheInjectedRuntimeRole(String role) throws Exception {
        verifyRuntimeRole(AwsDiscoverySyncService.class, role);
    }

    @ParameterizedTest
    @ValueSource(strings = {"api", "schema-migrator", "worker"})
    void gcpDiscoveryHonorsTheInjectedRuntimeRole(String role) throws Exception {
        verifyRuntimeRole(GcpDiscoverySyncService.class, role);
    }

    private <T> void verifyRuntimeRole(Class<T> type, String role) throws Exception {
        var constructor = type.getConstructors()[0];
        Object[] dependencies = Arrays.stream(constructor.getParameterTypes()).map(org.mockito.Mockito::mock).toArray();
        TenantService tenants = Arrays.stream(dependencies).filter(TenantService.class::isInstance)
                .map(TenantService.class::cast).findFirst().orElseThrow();
        T service = type.cast(constructor.newInstance(dependencies));
        try (var context = new AnnotationConfigApplicationContext()) {
            context.registerBean(BackgroundTaskExecutionPolicy.class, () -> BackgroundTaskExecutionPolicy.forRole(role));
            context.registerBean(CloudOwnershipProducer.class, () -> org.mockito.Mockito.mock(CloudOwnershipProducer.class));
            context.registerBean(type, () -> service);
            context.refresh();
            type.getMethod("runScheduledSyncs").invoke(context.getBean(type));
            if ("worker".equals(role)) {
                verify(tenants).listActiveTenants();
            } else {
                verifyNoInteractions(tenants);
            }
        }
    }
}
