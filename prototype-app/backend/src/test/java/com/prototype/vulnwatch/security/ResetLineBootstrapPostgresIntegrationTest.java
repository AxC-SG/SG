package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
class ResetLineBootstrapPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("reset_line_bootstrap");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    @Qualifier("platformJdbcTemplate")
    private JdbcTemplate platformJdbcTemplate;

    @MockBean
    private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void freshDatabaseBootstrapsPlatformAndDefaultTenantSchemas() {
        Tenant defaultTenant = tenantRepository.findBySchemaName("tenant_default").orElseThrow();
        assertNotNull(defaultTenant.getId());
        assertEquals("tenant_default", defaultTenant.getSchemaName());

        assertSchemaExists("platform");
        assertSchemaExists("tenant_default");

        assertTablesExist("platform",
                "tenants",
                "app_users",
                "tenant_memberships",
                "tenant_support_grants",
                "software_identities",
                "software_identifiers",
                "cpe_dim",
                "identity_links",
                "vulnerability_intel_summary",
                "vulnerability_intel_observations",
                "vulnerability_intel_summary_sources",
                "vulnerability_intel_relations",
                "vulnerability_targets",
                "vex_assertions",
                "vulnerability_rules",
                "vulnerability_config_expr",
                "software_eol_mapping",
                "eol_product_catalog",
                "eol_release",
                "sync_runs",
                "vulnerabilities");

        assertTablesExist("tenant_default",
                "assets",
                "inventory_components",
                "discovery_models",
                "demo_requests",
                "demo_invites",
                "audit_events",
                "applicability_assessments",
                "investigations",
                "investigation_activities",
                "investigation_attachments",
                "cis",
                "ci_aliases",
                "software_instances",
                "software_inventory_items",
                "findings",
                "finding_events",
                "finding_comments",
                "finding_delta_queue",
                "risk_policies",
                "org_cve_records",
                "org_cve_ai_artifacts",
                "component_vulnerability_states",
                "inventory_component_cpe_map",
                "suppression_rules",
                "ownership_rules",
                "fix_records",
                "sbom_uploads",
                "service_accounts",
                "github_sbom_sources",
                "aws_discovery_configs",
                "aws_discovery_targets",
                "sccm_cmdb_configs",
                "servicenow_cmdb_configs",
                "vulnerability_source_filter_configs");

        assertIndexExists("tenant_default", "uk_findings_component_vulnerability");
        assertIndexExists("tenant_default", "idx_findings_tenant_status_updated");
        assertIndexExists("tenant_default", "idx_findings_tenant_component_vuln");
        assertIndexExists("tenant_default", "idx_findings_vulnerability_status");
        assertIndexExists("tenant_default", "uk_component_vuln_state_tenant_component_vulnerability");
        assertIndexExists("tenant_default", "idx_software_inventory_tenant_component");
        assertIndexExists("tenant_default", "idx_github_sbom_sources_tenant");
        assertIndexExists("platform", "idx_cpe_dim_normalized");
        assertIndexExists("platform", "idx_vex_assertions_vulnerability");
        assertIndexExists("platform", "uk_identity_links_pair_type_source");
        assertIndexExists("platform", "uk_vuln_intel_relations_pair_type_source");
        assertIndexExists("platform", "idx_vulnerabilities_external_cvss_lastmod_updated");
        assertIndexExists("platform", "idx_sync_runs_run_scope_started");
        assertIndexExists("platform", "idx_sync_runs_tenant_started");
    }

    private void assertSchemaExists(String schemaName) {
        Integer count = platformJdbcTemplate.queryForObject("""
                SELECT count(*)
                FROM information_schema.schemata
                WHERE schema_name = ?
                """, Integer.class, schemaName);
        assertEquals(1, count);
    }

    private void assertTablesExist(String schemaName, String... tableNames) {
        for (String tableName : tableNames) {
            Integer count = platformJdbcTemplate.queryForObject("""
                    SELECT count(*)
                    FROM information_schema.tables
                    WHERE table_schema = ?
                      AND table_name = ?
                    """, Integer.class, schemaName, tableName);
            assertEquals(1, count, () -> "Missing table " + schemaName + "." + tableName);
        }
    }

    private void assertIndexExists(String schemaName, String indexName) {
        Integer count = platformJdbcTemplate.queryForObject("""
                SELECT count(*)
                FROM pg_indexes
                WHERE schemaname = ?
                  AND indexname = ?
                """, Integer.class, schemaName, indexName);
        assertEquals(1, count, () -> "Missing index " + schemaName + "." + indexName);
    }
}
