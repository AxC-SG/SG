package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.DirectoryImportService.Kind;
import com.prototype.vulnwatch.service.ownership.DirectoryImportService.Outcome;
import com.prototype.vulnwatch.service.ownership.DirectoryImportService.Report;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.nio.charset.StandardCharsets;
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

/** Real-PostgreSQL proof for manual directory administration and CSV import (plan §6.2, §6.3). */
@PostgresIntegrationTest
class DirectoryPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_directory");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private DirectoryService directory;
    @Autowired private DirectoryImportService imports;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenant = newTenant(true);
        enter(tenant);
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    void writesFailClosedUntilTheTenantKeyIsProvisioned() {
        enter(newTenant(false));
        assertThatThrownBy(() -> directory.createUser("Ada Lovelace", null, null, null, directory.manualSource("admin"), "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(503));
    }

    @Test
    void manualPeopleAreEncryptedSearchableAndNeverDuplicatedByEmail() {
        UUID manual = directory.manualSource("admin");
        assertThat(directory.manualSource("admin")).isEqualTo(manual);
        var ada = directory.createUser("Ada Lovelace", "Ada@Example.com", "E-1", null, manual, "admin");
        var grace = directory.createUser("Grace Hopper", null, null, ada.id(), manual, "admin");
        assertThat(ada.email()).isEqualTo("ada@example.com");

        String stored = jdbc.queryForObject("SELECT display_name_enc || coalesce(email_enc, '') FROM directory_user WHERE id = ?", String.class, ada.id());
        assertThat(stored).startsWith("enc:t1:").doesNotContain("Ada").doesNotContain("example.com");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE details_json::text ILIKE '%lovelace%' OR details_json::text ILIKE '%example.com%'",
                Integer.class)).isZero();

        assertThat(directory.searchUsers("lov", 10)).extracting(DirectoryService.DirectoryUser::id).containsExactly(ada.id());
        assertThat(directory.searchUsers("gr hop", 10)).extracting(DirectoryService.DirectoryUser::id).containsExactly(grace.id());
        assertThat(directory.searchUsers("a", 10)).isEmpty();
        assertThat(directory.userIdByEmail("ADA@example.com")).contains(ada.id());

        assertThatThrownBy(() -> directory.createUser("Other Ada", "ada@example.com", null, null, manual, "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));
        assertThatThrownBy(() -> directory.updateUser(ada.id(), null, null, null, grace.id(), false, ada.version(), "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(400));

        var inactive = directory.setUserStatus(ada.id(), "INACTIVE", ada.version(), "admin");
        assertThat(directory.setUserStatus(ada.id(), "ACTIVE", inactive.version(), "admin").id()).isEqualTo(ada.id());
    }

    @Test
    void membershipsAreIdempotentAndRemovalKeepsHistory() {
        UUID manual = directory.manualSource("admin");
        var user = directory.createUser("Linus", null, null, null, manual, "admin");
        var group = directory.createGroup("Platform SRE", manual, "admin");
        assertThat(directory.addMember(group.id(), user.id(), manual, "admin")).isTrue();
        assertThat(directory.addMember(group.id(), user.id(), manual, "admin")).isFalse();
        assertThat(directory.removeMember(group.id(), user.id(), manual, "admin")).isTrue();
        assertThat(directory.members(group.id())).isEmpty();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM directory_group_member", Integer.class)).isEqualTo(1);
        assertThat(directory.addMember(group.id(), user.id(), manual, "admin")).isTrue();
        assertThat(directory.searchGroups("platform", 10)).extracting(DirectoryService.DirectoryGroup::id).containsExactly(group.id());
    }

    @Test
    void csvPreviewChangesNothingAndCommitIsBoundToTheSameFileAndImporter() {
        byte[] users = csv("""
                external_id,display_name,email,manager_external_id,status
                u1,Ada Lovelace,ada@example.com,,ACTIVE
                u2,Grace Hopper,grace@example.com,u1,
                u2,Grace Again,,,
                u3,=SUM(A1),,,
                u4,No Status,,,RETIRED
                """);
        Report preview = imports.preview(Kind.USERS, users, "admin");
        assertThat(preview.counts()).containsEntry(Outcome.CREATE, 2).containsEntry(Outcome.DUPLICATE, 1).containsEntry(Outcome.REJECTED, 2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM directory_user", Integer.class)).isZero();
        assertThat(preview.rows()).allSatisfy(r -> assertThat(String.valueOf(r.message())).doesNotContain("SUM(").doesNotContain("Grace"));

        assertThatThrownBy(() -> imports.commit(preview.runId(), csv("external_id,display_name,email,manager_external_id,status\n"), "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));
        assertThatThrownBy(() -> imports.commit(preview.runId(), users, "someone-else"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));

        Report committed = imports.commit(preview.runId(), users, "admin");
        assertThat(committed.state()).isEqualTo("APPLIED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM directory_user", Integer.class)).isEqualTo(2);
        UUID source = directory.csvSource("admin");
        UUID ada = directory.userIdByExternalId(source, "u1").orElseThrow();
        UUID grace = directory.userIdByExternalId(source, "u2").orElseThrow();
        assertThat(directory.user(grace).orElseThrow().managerUserId()).isEqualTo(ada);
        assertThatThrownBy(() -> imports.commit(preview.runId(), users, "admin")).isInstanceOf(ResponseStatusException.class);

        // Replaying the same file is all UNCHANGED and creates nothing.
        Report again = imports.preview(Kind.USERS, users, "admin");
        assertThat(again.counts()).containsEntry(Outcome.CREATE, 0).containsEntry(Outcome.UNCHANGED, 2);
        imports.commit(again.runId(), users, "admin");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM directory_user", Integer.class)).isEqualTo(2);
    }

    @Test
    void csvEmailCollisionGoesToReviewInsteadOfMerging() {
        directory.createUser("Ada Manual", "ada@example.com", null, null, directory.manualSource("admin"), "admin");
        byte[] users = csv("external_id,display_name,email,manager_external_id,status\nu9,Ada Csv,ada@example.com,,\n");
        Report preview = imports.preview(Kind.USERS, users, "admin");
        assertThat(preview.counts()).containsEntry(Outcome.AMBIGUOUS, 1);
        imports.commit(preview.runId(), users, "admin");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM directory_user", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_review_item WHERE item_type = 'AMBIGUOUS_IDENTITY'", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT details::text FROM ownership_review_item", String.class)).doesNotContain("example.com");
    }

    @Test
    void groupsMembershipsTeamsAndAliasesImportEndToEnd() {
        commit(Kind.USERS, "external_id,display_name,email,manager_external_id,status\nu1,Ada,,,\nu2,Grace,,,\n");
        commit(Kind.GROUPS, "external_id,display_name,status\ng1,Payments Engineers,\n");
        Report members = commit(Kind.MEMBERSHIPS, "group_external_id,user_external_id,operation\ng1,u1,ADD\ng1,u2,ADD\ng1,u404,ADD\n");
        assertThat(members.counts()).containsEntry(Outcome.CREATE, 2).containsEntry(Outcome.REJECTED, 1);
        UUID source = directory.csvSource("admin");
        UUID group = directory.groupIdByExternalId(source, "g1").orElseThrow();
        assertThat(directory.members(group)).hasSize(2);
        commit(Kind.MEMBERSHIPS, "group_external_id,user_external_id,operation\ng1,u2,REMOVE\n");
        assertThat(directory.members(group)).hasSize(1);

        commit(Kind.TEAMS, "name,parent_team,ticket_assignment_group\nEngineering,,\nPayments,Engineering,PAY-OPS\n");
        UUID payments = teams.resolve("payments").orElseThrow();
        assertThat(teams.team(payments).orElseThrow().parentTeamId()).isEqualTo(teams.resolve("engineering").orElseThrow());
        Report aliases = commit(Kind.TEAM_ALIASES, "source_kind,alias,team_name\nSERVICENOW,PAY-SUPPORT,Payments\nSERVICENOW,Engineering,Payments\n");
        assertThat(aliases.counts()).containsEntry(Outcome.CREATE, 1).containsEntry(Outcome.REJECTED, 1);
        assertThat(teams.resolve("pay-support")).contains(payments);
    }

    @Test
    void malformedFilesAreRejectedBeforeAnyRowIsRead() {
        assertBadRequest(() -> imports.preview(Kind.USERS, new byte[] {'P', 'K', 3, 4, 0}, "admin"));
        assertBadRequest(() -> imports.preview(Kind.USERS, new byte[] {(byte) 0xC3, (byte) 0x28}, "admin"));
        assertBadRequest(() -> imports.preview(Kind.USERS, csv("wrong,header\n"), "admin"));
        assertBadRequest(() -> imports.preview(Kind.GROUPS, csv("external_id,display_name,status\n\"g1,unterminated\n"), "admin"));
    }

    private Report commit(Kind kind, String body) {
        byte[] file = csv(body);
        return imports.commit(imports.preview(kind, file, "admin").runId(), file, "admin");
    }

    private static byte[] csv(String body) {
        return body.getBytes(StandardCharsets.UTF_8);
    }

    private Tenant newTenant(boolean withKey) {
        String slug = "own-dir-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        Tenant resolved = tenantService.resolveTenantUuid(created.getId());
        if (withKey) keys.provision(resolved.getId());
        return resolved;
    }

    private void enter(Tenant t) {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(t.getId());
        TenantContext.setCurrentSchemaName(t.getSchemaName());
    }

    private static void assertBadRequest(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(400));
    }
}
