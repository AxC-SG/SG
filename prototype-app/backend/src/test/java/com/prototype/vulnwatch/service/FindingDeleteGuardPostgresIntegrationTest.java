package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/**
 * Phase 0B §4.12, §4.13: campaign membership is never cascaded away, so deleting a finding that belongs to a campaign is
 * refused with 409 and deletes nothing, while tenant purge (which drops the tenant schema) is not blocked by the
 * {@code RESTRICT} key.
 */
@PostgresIntegrationTest
class FindingDeleteGuardPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("finding_delete_guard");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private FindingWorkflowService workflow;
    @Autowired private CampaignService campaigns;
    @Autowired private TenantSchemaService schemas;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID asset;

    @BeforeEach
    void setUp() {
        String slug = "delg-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        enter();
        asset = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')",
                asset, "host-" + asset, "host-" + asset);
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    void aCampaignMemberCannotBeDeletedAndNothingInTheRequestIsDeleted() {
        UUID member = finding();
        UUID free = finding();
        campaigns.createFromFindings(tenant, new CampaignFromFindingsRequest("Guard", null, List.of(member), null, null, null), "analyst");
        enter();

        assertThatThrownBy(() -> workflow.bulkDelete(List.of(member, free)))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> {
                    assertThat(e.getStatusCode().value()).isEqualTo(409);
                    assertThat(e.getReason()).contains("campaign members");
                });
        assertThat(count("findings")).as("the non-member was not deleted either").isEqualTo(2);
        assertThat(count("campaign_findings")).isEqualTo(1);

        assertThat(workflow.bulkDelete(List.of(free))).isEqualTo(1);
        assertThat(count("findings")).isEqualTo(1);
    }

    @Test
    void tenantPurgeIsNotBlockedByCampaignMembership() {
        UUID member = finding();
        campaigns.createFromFindings(tenant, new CampaignFromFindingsRequest("Purge", null, List.of(member), null, null, null), "analyst");
        enter();
        assertThat(count("campaign_findings")).isEqualTo(1);

        // DemoTenantPurgeService removes a tenant by dropping its schema, so the RESTRICT key has nothing to block.
        schemas.dropTenantSchema(tenant.getSchemaName());
        TenantContext.clear();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM information_schema.schemata WHERE schema_name = ?", Integer.class,
                tenant.getSchemaName())).isZero();
    }

    private UUID finding() {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, confidence_score,
                    status, finding_kind, asset_id)
                VALUES (?, ?, now(), now(), 'AI_SECURITY', ?, 'AI_SECURITY', 5.0, 0.9, 'OPEN', 'AI_POSTURE', ?)""",
                id, tenant.getId(), "F-" + id.toString().substring(0, 8), asset);
        return id;
    }

    private int count(String table) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM " + table, Integer.class);
        return n == null ? 0 : n;
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
