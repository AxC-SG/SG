package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.DirectoryService.DirectoryUser;
import com.prototype.vulnwatch.service.ownership.DirectoryService.IdentityObservation;
import com.prototype.vulnwatch.service.ownership.DirectoryService.IdentityResolution;
import com.prototype.vulnwatch.service.ownership.DirectoryService.LinkOutcome;
import com.prototype.vulnwatch.service.ownership.DirectoryService.ObservedIdentity;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/** Real-PostgreSQL proof for provider identity linking rules 1–6 and admin resolution (Phase 0B contract §1.4). */
@PostgresIntegrationTest
class DirectoryLinkingPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_directory_linking");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private DirectoryService directory;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private UUID source;
    private UUID manual;

    @BeforeEach
    void setUp() {
        String slug = "own-link-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        Tenant tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        source = directory.createProviderSource("SERVICENOW", "ServiceNow", null, "{}", "PT24H", "admin");
        manual = directory.manualSource("admin");
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    void rule4CreatesAPersonForThisSourceAndRule1KeepsTheLinkWhenTheEmailChanges() {
        IdentityObservation first = observe("sys-1", "Ada Lovelace", "Ada@Example.com", "alovelace", "E-1", true);
        assertThat(first.outcome()).isEqualTo(LinkOutcome.CREATED_PERSON);
        DirectoryUser ada = directory.user(first.userId()).orElseThrow();
        assertThat(ada.displayName()).isEqualTo("Ada Lovelace");
        assertThat(ada.email()).isEqualTo("ada@example.com");
        assertThat(ada.employeeId()).isEqualTo("E-1");
        assertThat(jdbc.queryForObject("SELECT created_source_id FROM directory_user WHERE id = ?", UUID.class, ada.id())).isEqualTo(source);

        String stored = jdbc.queryForObject("SELECT external_id_enc || email_enc || username_enc FROM external_identity WHERE id = ?",
                String.class, first.identityId());
        assertThat(stored).startsWith("enc:t1:").doesNotContain("sys-1").doesNotContain("example.com").doesNotContain("alovelace");

        // An unrelated person now holds the new email; the link still does not move (rule 1), and drift is reported (rule 5).
        directory.createUser("Someone Else", "ada.new@example.com", null, null, manual, "admin");
        IdentityObservation again = observe("sys-1", "Ada Lovelace", "ada.new@example.com", "alovelace", "E-1", true);
        assertThat(again.outcome()).isEqualTo(LinkOutcome.KEPT_LINK);
        assertThat(again.identityId()).isEqualTo(first.identityId());
        assertThat(again.userId()).isEqualTo(ada.id());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM external_identity WHERE email_index IS NOT NULL AND id = ? AND user_id = ?",
                Integer.class, first.identityId(), ada.id())).isEqualTo(1);
        assertThat(openReviews(DirectoryService.driftKey(first.identityId()))).isEqualTo(1);
        assertThat(countPeople()).isEqualTo(2);
    }

    @Test
    void rule2LinksToTheOnlyActivePersonWithTheEmail() {
        DirectoryUser grace = directory.createUser("Grace Hopper", "grace@example.com", null, null, manual, "admin");
        IdentityObservation seen = observe("sys-2", "G. Hopper", "GRACE@example.com", null, null, true);
        assertThat(seen.outcome()).isEqualTo(LinkOutcome.LINKED_BY_EMAIL);
        assertThat(seen.userId()).isEqualTo(grace.id());
        assertThat(directory.user(grace.id()).orElseThrow().displayName()).isEqualTo("Grace Hopper");
        assertThat(countPeople()).isEqualTo(1);
    }

    @Test
    void rule3MarksAnIdentityMatchingSeveralPeopleAmbiguousWithOneDeduplicatedReviewItem() {
        DirectoryUser one = directory.createUser("Shared One", "team@example.com", null, null, manual, "admin");
        DirectoryUser two = directory.createUser("Shared Two", null, null, null, manual, "admin");
        shareEmail(one.id(), two.id());

        IdentityObservation seen = observe("sys-3", "Team Mailbox", "team@example.com", null, null, true);
        assertThat(seen.outcome()).isEqualTo(LinkOutcome.AMBIGUOUS);
        assertThat(seen.userId()).isNull();
        assertThat(observe("sys-3", "Team Mailbox", "team@example.com", null, null, true).outcome()).isEqualTo(LinkOutcome.AMBIGUOUS);

        String key = DirectoryService.ambiguousKey(seen.identityId());
        assertThat(openReviews(key)).isEqualTo(1);
        Map<String, Object> item = jdbc.queryForMap(
                "SELECT occurrence_count, source_kind, details::text AS details FROM ownership_review_item WHERE dedupe_key = ?", key);
        assertThat(item.get("occurrence_count")).isEqualTo(2);
        assertThat(item.get("source_kind")).isEqualTo("SERVICENOW");
        assertThat((String) item.get("details")).contains("MULTIPLE_MATCHES", one.id().toString(), two.id().toString())
                .doesNotContain("example.com").doesNotContain("Team Mailbox");
        assertThat(jdbc.queryForObject("SELECT link_status FROM external_identity WHERE id = ?", String.class, seen.identityId()))
                .isEqualTo("AMBIGUOUS");
        assertThat(countPeople()).isEqualTo(2);
    }

    @Test
    void anIdentityMatchingOnlyAnInactivePersonIsAmbiguousRatherThanADuplicate() {
        DirectoryUser former = directory.createUser("Former Person", "former@example.com", null, null, manual, "admin");
        directory.setUserStatus(former.id(), "INACTIVE", former.version(), "admin");

        IdentityObservation seen = observe("sys-4", "Former Person", "former@example.com", null, null, true);
        assertThat(seen.outcome()).isEqualTo(LinkOutcome.AMBIGUOUS);
        assertThat(jdbc.queryForObject("SELECT details::text FROM ownership_review_item WHERE dedupe_key = ?", String.class,
                DirectoryService.ambiguousKey(seen.identityId()))).contains("ONLY_INACTIVE_MATCH", former.id().toString());
        assertThat(countPeople()).isEqualTo(1);
    }

    @Test
    void aNewInactiveIdentityIsRecordedUnlinkedUntilItBecomesActive() {
        IdentityObservation locked = observe("sys-5", "Locked Out", "locked@example.com", null, null, false);
        assertThat(locked.outcome()).isEqualTo(LinkOutcome.UNLINKED_INACTIVE);
        assertThat(jdbc.queryForMap("SELECT link_status, status, user_id FROM external_identity WHERE id = ?", locked.identityId()))
                .containsEntry("link_status", "UNLINKED").containsEntry("status", "INACTIVE").containsEntry("user_id", null);
        assertThat(countPeople()).isZero();

        IdentityObservation active = observe("sys-5", "Locked Out", "locked@example.com", null, null, true);
        assertThat(active.outcome()).isEqualTo(LinkOutcome.CREATED_PERSON);
        assertThat(active.identityId()).isEqualTo(locked.identityId());
        assertThat(countPeople()).isEqualTo(1);
    }

    @Test
    void rule6UserNameAndEmployeeNumberNeverDriveALink() {
        DirectoryUser existing = directory.createUser("Existing Person", null, "E-9", null, manual, "admin");
        IdentityObservation seen = observe("sys-6", "Existing Person", null, "Existing Person", "E-9", true);
        assertThat(seen.outcome()).isEqualTo(LinkOutcome.CREATED_PERSON);
        assertThat(seen.userId()).isNotEqualTo(existing.id());
    }

    @Test
    void anInvalidEmailIsTreatedAsAbsent() {
        directory.createUser("Valid Person", "valid@example.com", null, null, manual, "admin");
        IdentityObservation seen = observe("sys-7", "No Mail", "not an email", null, null, true);
        assertThat(seen.outcome()).isEqualTo(LinkOutcome.CREATED_PERSON);
        assertThat(jdbc.queryForObject("SELECT email_enc FROM external_identity WHERE id = ?", String.class, seen.identityId())).isNull();
        assertThat(directory.user(seen.userId()).orElseThrow().email()).isNull();
    }

    @Test
    void anAdminResolvesAnAmbiguousIdentityByChoosingAPersonAndTheReviewItemCloses() {
        DirectoryUser former = directory.createUser("Former Person", "back@example.com", null, null, manual, "admin");
        directory.setUserStatus(former.id(), "INACTIVE", former.version(), "admin");
        IdentityObservation seen = observe("sys-8", "Former Person", "back@example.com", null, null, true);

        IdentityResolution resolved = directory.resolveAmbiguousIdentity(seen.identityId(), former.id(), null, "admin");
        assertThat(resolved).isEqualTo(new IdentityResolution(seen.identityId(), former.id(), false));
        assertThat(openReviews(DirectoryService.ambiguousKey(seen.identityId()))).isZero();
        assertThat(jdbc.queryForObject("SELECT state FROM ownership_review_item WHERE dedupe_key = ?", String.class,
                DirectoryService.ambiguousKey(seen.identityId()))).isEqualTo("RESOLVED");
        assertThat(observe("sys-8", "Former Person", "back@example.com", null, null, true).outcome()).isEqualTo(LinkOutcome.KEPT_LINK);

        assertConflict(() -> directory.resolveAmbiguousIdentity(seen.identityId(), former.id(), null, "admin"));
    }

    @Test
    void anAdminResolvesAnAmbiguousIdentityByCreatingANewPersonWhoKeepsTheSharedEmail() {
        DirectoryUser one = directory.createUser("Shared One", "shared@example.com", null, null, manual, "admin");
        DirectoryUser two = directory.createUser("Shared Two", null, null, null, manual, "admin");
        shareEmail(one.id(), two.id());
        IdentityObservation seen = observe("sys-9", "Third Person", "shared@example.com", null, null, true);

        assertBadRequest(() -> directory.resolveAmbiguousIdentity(seen.identityId(), null, " ", "admin"));
        assertBadRequest(() -> directory.resolveAmbiguousIdentity(seen.identityId(), one.id(), "Both", "admin"));
        assertThatThrownBy(() -> directory.resolveAmbiguousIdentity(UUID.randomUUID(), one.id(), null, "admin"))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(404));

        IdentityResolution resolved = directory.resolveAmbiguousIdentity(seen.identityId(), null, "Third Person", "admin");
        assertThat(resolved.createdPerson()).isTrue();
        DirectoryUser third = directory.user(resolved.userId()).orElseThrow();
        assertThat(third.email()).isEqualTo("shared@example.com");
        assertThat(jdbc.queryForObject("SELECT created_source_id FROM directory_user WHERE id = ?", UUID.class, third.id())).isEqualTo(source);
        assertThat(openReviews(DirectoryService.ambiguousKey(seen.identityId()))).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE details_json::text ILIKE '%example.com%' OR details_json::text ILIKE '%Third%'",
                Integer.class)).isZero();
    }

    private IdentityObservation observe(String sysId, String name, String email, String username, String employee, boolean active) {
        return directory.observeIdentity(new ObservedIdentity(source, sysId, name, email, username, employee, active), null, "sync");
    }

    /** Test-only setup: the API refuses a second person with the same email, but other paths (and rule 3) assume it can happen. */
    private void shareEmail(UUID from, UUID to) {
        jdbc.update("UPDATE directory_user t SET email_enc = f.email_enc, email_index = f.email_index FROM directory_user f WHERE f.id = ? AND t.id = ?",
                from, to);
    }

    private int countPeople() {
        return jdbc.queryForObject("SELECT count(*) FROM directory_user", Integer.class);
    }

    private int openReviews(String dedupeKey) {
        return jdbc.queryForObject("SELECT count(*) FROM ownership_review_item WHERE dedupe_key = ? AND state = 'OPEN'", Integer.class, dedupeKey);
    }

    private static void assertBadRequest(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(400));
    }

    private static void assertConflict(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));
    }
}
