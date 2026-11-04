package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;

class IngestionAttemptStartupTest {

    @Test
    void registersCommitGuardAfterJpaBootstrap() {
        try (var context = new AnnotationConfigApplicationContext(JpaBootstrapConfiguration.class)) {
            var transactionManager = context.getBean(JpaTransactionManager.class);
            assertEquals(1, transactionManager.getTransactionExecutionListeners().size());
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    @Import(IngestionAttemptService.class)
    static class JpaBootstrapConfiguration {
        @Bean
        EntityManagerFactory entityManagerFactory(IngestionAttemptService attempts) {
            // Reproduce the dependency on the service during JPA bootstrap.
            return mock(EntityManagerFactory.class);
        }

        @Bean
        JpaTransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
            return new JpaTransactionManager(entityManagerFactory);
        }

        @Bean
        JdbcTemplate jdbcTemplate() {
            return mock(JdbcTemplate.class);
        }

        @Bean
        TenantSchemaExecutionService tenantSchemaExecutionService() {
            return mock(TenantSchemaExecutionService.class);
        }
    }
}
