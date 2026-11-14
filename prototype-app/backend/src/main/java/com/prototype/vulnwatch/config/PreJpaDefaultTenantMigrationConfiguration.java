package com.prototype.vulnwatch.config;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import com.prototype.vulnwatch.migration.TenantSearchPathFlywayCallback;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.flyway.autoconfigure.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/** Test-harness equivalent of the production platform-then-tenant bootstrap, executed before JPA. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "app.schema-migration.pre-jpa-default-tenant-enabled", havingValue = "true")
public class PreJpaDefaultTenantMigrationConfiguration {
    private static final String DEFAULT_SCHEMA = "tenant_default";
    private static final UUID DEFAULT_TENANT_ID = UUID.nameUUIDFromBytes(
            "scout-default-tenant".getBytes(StandardCharsets.UTF_8));

    @Bean
    FlywayMigrationStrategy platformThenDefaultTenantMigrationStrategy() {
        return platformFlyway -> {
            platformFlyway.migrate();
            DataSource dataSource = platformFlyway.getConfiguration().getDataSource();
            JdbcTemplate jdbc = new JdbcTemplate(dataSource);
            UUID tenantId = jdbc.query("""
                    select id from platform.tenants
                     where schema_name = ? or id = ?
                     order by case when id = ? then 0 else 1 end
                     limit 1
                    """, ps -> {
                        ps.setString(1, DEFAULT_SCHEMA);
                        ps.setObject(2, DEFAULT_TENANT_ID);
                        ps.setObject(3, DEFAULT_TENANT_ID);
                    }, rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
            if (tenantId == null) {
                tenantId = DEFAULT_TENANT_ID;
                jdbc.update("""
                        insert into platform.tenants (
                            id,name,slug,schema_name,status,plan_code,created_at,updated_at,
                            max_connector_count,max_service_account_count,max_daily_sbom_uploads,
                            max_export_rows,max_daily_exposure_refreshes)
                        values (?, 'Default Workspace', 'default-workspace', ?, 'ACTIVE', 'ENTERPRISE',
                                now(), now(), 10, 25, 100, 50000, 25)
                        """, tenantId, DEFAULT_SCHEMA);
            }
            Flyway.configure().dataSource(dataSource).schemas(DEFAULT_SCHEMA).defaultSchema(DEFAULT_SCHEMA)
                    .table("tenant_schema_history").locations("classpath:db/migration/tenant")
                    .placeholders(Map.of("tenantId", tenantId.toString(), "tenantSchema", DEFAULT_SCHEMA))
                    .callbacks(new TenantSearchPathFlywayCallback(DEFAULT_SCHEMA))
                    .validateOnMigrate(true).outOfOrder(false)
                    .initSql("SET search_path TO \"tenant_default\", public; SET statement_timeout = '5min'")
                    .load().migrate();
        };
    }
}
