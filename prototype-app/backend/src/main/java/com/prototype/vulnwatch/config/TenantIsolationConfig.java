package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.servlet.Filter;
import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * BLG-007: Replaces Spring Boot's auto-configured DataSource with a
 * TenantAwareDataSource wrapper that sets app.current_tenant_id on every
 * connection, enabling PostgreSQL Row-Level Security policies.
 *
 * Spring Boot's DataSourceAutoConfiguration backs off when a DataSource bean
 * named "dataSource" is defined here. HikariCP settings from
 * spring.datasource.hikari.* are still applied via @ConfigurationProperties.
 */
@Configuration
public class TenantIsolationConfig {

    /**
     * Raw HikariCP pool — not exposed to the application directly.
     * Receives all spring.datasource.hikari.* bindings.
     */
    @Bean(name = "hikariDataSource")
    @ConfigurationProperties(prefix = "spring.datasource.hikari")
    public HikariDataSource hikariDataSource(DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build();
    }

    /**
     * Primary DataSource bean — wraps the HikariCP pool with tenant context injection.
     * All JPA, Flyway, and JdbcTemplate beans will use this bean.
     */
    @Bean
    @Primary
    public DataSource dataSource(
            HikariDataSource hikariDataSource,
            @org.springframework.beans.factory.annotation.Value("${app.tenancy.require-tenant-context:true}") boolean requireTenantContext,
            @org.springframework.beans.factory.annotation.Value("${app.tenancy.default-schema:tenant_default}") String defaultSchemaName,
            ObjectProvider<MeterRegistry> meterRegistryProvider,
            ApplicationLifecycleState applicationLifecycleState
    ) {
        return new TenantAwareDataSource(
                hikariDataSource,
                requireTenantContext,
                defaultSchemaName,
                meterRegistryProvider.getIfAvailable(),
                applicationLifecycleState::isApplicationReady
        );
    }

    /**
     * Default tenant-aware JdbcTemplate for the application's ordinary read/write
     * flows. Platform-plane jobs use the explicitly qualified templates below.
     */
    @Bean
    @Primary
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    /**
     * Unscoped JdbcTemplate for platform-plane flows that must operate outside
     * tenant RLS, including global ingestion jobs and irreversible purge/reset operations.
     */
    @Bean(name = "prototypeResetJdbcTemplate")
    public JdbcTemplate prototypeResetJdbcTemplate(HikariDataSource hikariDataSource) {
        return new JdbcTemplate(hikariDataSource);
    }

    @Bean(name = "platformJdbcTemplate")
    public JdbcTemplate platformJdbcTemplate(HikariDataSource hikariDataSource) {
        return new JdbcTemplate(hikariDataSource);
    }

    /**
     * Spring Boot normally auto-configures this, but that backs off once we
     * provide our own DataSource/JdbcTemplate stack for tenant isolation.
     */
    @Bean
    public NamedParameterJdbcTemplate namedParameterJdbcTemplate(DataSource dataSource) {
        return new NamedParameterJdbcTemplate(dataSource);
    }

    /**
     * Dedicated transaction manager for platform-plane operations that should
     * bypass the tenant-aware datasource wrapper.
     */
    @Bean(name = "prototypeResetTransactionManager")
    public PlatformTransactionManager prototypeResetTransactionManager(HikariDataSource hikariDataSource) {
        return new DataSourceTransactionManager(hikariDataSource);
    }

    @Bean(name = "platformTransactionManager")
    public PlatformTransactionManager platformTransactionManager(HikariDataSource hikariDataSource) {
        return new DataSourceTransactionManager(hikariDataSource);
    }

    /**
     * Keep the application's default JPA transaction manager available under the
     * conventional bean name expected by the rest of the service layer.
     */
    @Bean(name = "transactionManager")
    @Primary
    public PlatformTransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory);
    }

    /**
     * Registers TenantResolutionFilter explicitly (not via @Component) so that
     * @WebMvcTest slice tests do not try to load it without JPA context available.
     */
    @Bean
    public FilterRegistrationBean<Filter> tenantResolutionFilter(
            WorkspaceService workspaceService,
            TenantService tenantService,
            @org.springframework.beans.factory.annotation.Value("${app.tenancy.allow-header-tenant-selection:false}") boolean allowHeaderTenantSelection,
            @org.springframework.beans.factory.annotation.Value("${app.tenancy.require-tenant-context:true}") boolean requireTenantContext
    ) {
        FilterRegistrationBean<Filter> reg = new FilterRegistrationBean<>(
                new TenantResolutionFilter(workspaceService, tenantService, allowHeaderTenantSelection, requireTenantContext));
        reg.addUrlPatterns("/*");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        reg.setName("tenantResolutionFilter");
        return reg;
    }
}
