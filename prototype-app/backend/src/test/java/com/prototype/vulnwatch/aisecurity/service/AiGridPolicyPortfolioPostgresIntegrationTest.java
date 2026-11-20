package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.migration.PackagedMigrationCatalog;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiGridPolicyPortfolioPostgresIntegrationTest {

    private static final UUID TENANT_ID = UUID.fromString("e5fe0d29-1d64-4175-8ce6-c34f42b214cc");
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_policy_portfolio");

    @Test
    @SuppressWarnings("unchecked")
    void executesCoverageSqlAndDerivesNoEpochEffectivePartialAndPreview() throws Exception {
        migrate();
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password())) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("set search_path to tenant_default,platform,public");
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    "select set_config('app.current_tenant_id', ?, false)")) {
                statement.setString(1, TENANT_ID.toString());
                statement.execute();
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                        insert into platform.tenant_schema_versions
                            (tenant_id,schema_name,current_version,target_version,status,last_successful_version)
                        values (?,'tenant_default',2,2,'CURRENT',2)
                        on conflict (tenant_id) do update set current_version=2,target_version=2,status='CURRENT',last_successful_version=2
                        """)) {
                statement.setObject(1, TENANT_ID);
                statement.executeUpdate();
            }
            NamedParameterJdbcTemplate jdbc = new NamedParameterJdbcTemplate(new SingleConnectionDataSource(connection, true));
            TenantSchemaExecutionService execution = mock(TenantSchemaExecutionService.class);
            when(execution.run(any(Tenant.class), any(Supplier.class)))
                    .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
            AiGridPolicyPortfolioService service = new AiGridPolicyPortfolioService(
                    jdbc, new ObjectMapper(), mock(AuditEventService.class), execution);
            Tenant tenant = new Tenant(); tenant.setId(TENANT_ID); tenant.setSchemaName("tenant_default");

            assertEquals(3, service.frameworks().size());
            var withoutEpoch = service.frameworkCoverage(tenant, "OWASP_GENAI_LLM_TOP_10", "2026", null);
            assertEquals(java.util.List.of("NO_COVERAGE_EPOCH"), withoutEpoch.blockers());
            assertTrue(withoutEpoch.controls().stream().filter(control -> control.mappedPolicies() > 0)
                    .allMatch(control -> control.blockers().contains("NO_COVERAGE_EPOCH")));

            Mapping mapping = firstVisibleMapping(connection);
            UUID epoch = UUID.randomUUID(); UUID run = UUID.randomUUID();
            insertReadiness(connection, mapping, epoch, run, "ENABLED", "READY", 2);
            assertEquals("EFFECTIVE", control(service, tenant, mapping, epoch).coverageStatus());
            updateReadiness(connection, epoch, "ENABLED", "PARTIAL", 0);
            assertEquals("PARTIAL", control(service, tenant, mapping, epoch).coverageStatus());
            updateReadiness(connection, epoch, "PREVIEW", "READY", 1);
            assertEquals("PREVIEW", control(service, tenant, mapping, epoch).coverageStatus());
        }
    }

    private AiGridPolicyPortfolioService.ControlCoverage control(AiGridPolicyPortfolioService service, Tenant tenant,
                                                                  Mapping mapping, UUID epoch) {
        return service.frameworkCoverage(tenant, mapping.framework(), mapping.version(), epoch).controls().stream()
                .filter(control -> control.controlId().equals(mapping.control())).findFirst().orElseThrow();
    }

    private Mapping firstVisibleMapping(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement(); ResultSet rs = statement.executeQuery("""
                select p.policy_id,p.version,m->>'framework',m->>'frameworkVersion',m->>'controlId'
                  from platform.ai_grid_policy_versions p
                  join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id
                  cross join lateral jsonb_array_elements(p.framework_mappings_json) m
                 where p.release_family in ('AGCF_PHASE_1','AGCF_PHASE_2') and d.available=true
                   and d.rollout_stage='GENERAL_AVAILABILITY'
                   and m->>'framework'='OWASP_GENAI_LLM_TOP_10'
                 order by p.policy_id limit 1
                """)) {
            rs.next(); return new Mapping(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5));
        }
    }

    private void insertReadiness(Connection connection, Mapping mapping, UUID epoch, UUID run,
                                 String selection, String readiness, int ready) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "insert into ai_grid_current_coverage_state (tenant_id,epoch_id,trigger_run_id) values (?, ?, ?)")) {
            statement.setObject(1, TENANT_ID);
            statement.setObject(2, epoch);
            statement.setObject(3, run);
            statement.executeUpdate();
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                    insert into ai_grid_policy_readiness
                        (id,tenant_id,run_id,policy_id,policy_version,selection,readiness,
                         applicable_count,decision_ready_count,coverage_epoch_id)
                    values (?, ?, ?, ?, ?, ?, ?, 2, ?, ?)
                    """)) {
            statement.setObject(1, UUID.randomUUID());
            statement.setObject(2, TENANT_ID);
            statement.setObject(3, run);
            statement.setString(4, mapping.policyId());
            statement.setString(5, mapping.policyVersion());
            statement.setString(6, selection);
            statement.setString(7, readiness);
            statement.setInt(8, ready);
            statement.setObject(9, epoch);
            statement.executeUpdate();
        }
    }

    private void updateReadiness(Connection connection, UUID epoch, String selection, String readiness, int ready) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement("""
                update ai_grid_policy_readiness
                   set selection = ?, readiness = ?, decision_ready_count = ?
                 where coverage_epoch_id = ?
                """)) {
            statement.setString(1, selection);
            statement.setString(2, readiness);
            statement.setInt(3, ready);
            statement.setObject(4, epoch);
            statement.executeUpdate();
        }
    }

    private void migrate() {
        Flyway.configure().configuration(java.util.Map.of("flyway.postgresql.transactional.lock", "false")).dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public").locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .validateOnMigrate(true).load().migrate();
        Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas("tenant_default").defaultSchema("tenant_default").table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(Map.of("tenantSchema", "tenant_default", "tenantId", TENANT_ID.toString()))
                .target(Integer.toString(PackagedMigrationCatalog.resolve().tenantTarget()))
                .validateOnMigrate(true).load().migrate();
    }

    private record Mapping(String policyId, String policyVersion, String framework, String version, String control) {}
}
