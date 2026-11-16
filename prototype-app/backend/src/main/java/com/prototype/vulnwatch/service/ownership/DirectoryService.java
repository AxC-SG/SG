package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * The only writer of directory users, groups, memberships, external identities and search tokens (plan §6.2,
 * §7.1). Directory records describe people; they never grant Scoutgrid access. PII is stored only as tenant
 * ciphertext, exact lookups use blind indexes and prefix search uses HMAC tokens. Every write first checks tenant
 * key readiness and fails closed. Audit payloads carry IDs only.
 */
@Service
public class DirectoryService {

    public record DirectoryUser(UUID id, String displayName, String email, String employeeId, UUID managerUserId,
                                String status, long version) { }

    public record DirectoryGroup(UUID id, String displayName, String status, long version) { }

    public record Membership(UUID groupId, UUID userId, UUID sourceId, String status) { }

    static final String P_NAME = "directory.user.display_name";
    static final String P_EMAIL = "directory.user.email";
    static final String P_EMPLOYEE = "directory.user.employee_id";
    static final String P_SEARCH = "directory.search";
    static final String P_EXTERNAL_ID = "directory.external_id";
    static final int MIN_PREFIX = 2;
    static final int MAX_PREFIX = 12;
    private static final Set<String> STATUSES = Set.of("ACTIVE", "INACTIVE");
    private static final Pattern WORD_SPLIT = Pattern.compile("[^\\p{L}\\p{N}]+");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]{1,64}@[^@\\s]{1,255}$");

    private final JdbcTemplate jdbc;
    private final TenantDataCipher cipher;
    private final AuditEventService audit;
    private final OwnershipReviewService reviews;

    public DirectoryService(JdbcTemplate jdbc, TenantDataCipher cipher, AuditEventService audit, OwnershipReviewService reviews) {
        this.jdbc = jdbc;
        this.cipher = cipher;
        this.audit = audit;
        this.reviews = reviews;
    }

    // ----- sources --------------------------------------------------------------------------------------------

    /** The tenant's single MANUAL source, created on first use. */
    @Transactional
    public UUID manualSource(String actor) {
        return source("MANUAL", "Manual entry", actor);
    }

    /** The tenant's CSV import source, created on first use. */
    @Transactional
    public UUID csvSource(String actor) {
        return source("CSV", "CSV import", actor);
    }

    private UUID source(String kind, String name, String actor) {
        jdbc.query("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", rs -> null,
                TenantContext.getCurrentTenantId() + "|ownership.identity-source|" + kind);
        List<UUID> existing = jdbc.queryForList("SELECT id FROM identity_source WHERE kind = ? ORDER BY created_at LIMIT 1", UUID.class, kind);
        if (!existing.isEmpty()) return existing.get(0);
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO identity_source (tenant_id, id, kind, display_name, state, health, created_by) VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, 'ENABLED', 'HEALTHY', ?)",
                id, kind, name, actor);
        audit.record("ownership.identity_source.created", "identity_source", id.toString(), OwnershipEvents.json(Map.of("kind", kind)));
        return id;
    }

    // ----- provider sources (validated, encrypted and audited by IdentitySourceService) -----------------------

    private static final Set<String> PROVIDER_KINDS = Set.of("SERVICENOW", "ENTRA", "OKTA");

    /** Inserts a provider source in state DISABLED. {@code credentialsEnc} must already be tenant ciphertext. */
    @Transactional
    public UUID createProviderSource(String kind, String displayName, String credentialsEnc, String scopeJson, String schedule,
                                     String actor) {
        requireProviderKind(kind);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO identity_source (tenant_id, id, kind, display_name, credentials_enc, scope_config, schedule, created_by)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?::jsonb, ?, ?)
                """, id, kind, displayName, credentialsEnc, scopeJson, schedule, actor);
        return id;
    }

    /**
     * Replaces a provider source's configuration and state at {@code expectedVersion}. {@code resetCursor} clears the
     * sync cursor, for a move to another instance whose timestamps the old cursor does not describe. Returns false on
     * a version conflict.
     */
    @Transactional
    public boolean updateProviderSource(UUID id, String kind, String displayName, String credentialsEnc, String scopeJson,
                                        String schedule, String state, boolean resetCursor, long expectedVersion) {
        requireProviderKind(kind);
        return jdbc.update("""
                UPDATE identity_source SET display_name = ?, credentials_enc = ?, scope_config = ?::jsonb, schedule = ?, state = ?,
                       sync_cursor = CASE WHEN ? THEN NULL ELSE sync_cursor END, updated_at = now(), version = version + 1
                 WHERE id = ? AND kind = ? AND version = ?
                """, displayName, credentialsEnc, scopeJson, schedule, state, resetCursor, id, kind, expectedVersion) == 1;
    }

    /**
     * Stores a provider source's per-table sync cursor (JSON). Called after the page that produced it has committed.
     * Does not bump the version: sync progress must not invalidate an admin's form or preview.
     */
    @Transactional
    public void advanceSyncCursor(UUID id, String cursorJson) {
        jdbc.update("UPDATE identity_source SET sync_cursor = ?, updated_at = now() WHERE id = ? AND kind IN ('SERVICENOW','ENTRA','OKTA')",
                cursorJson, id);
    }

    /** Records a sync run's outcome on its source: health, and on success the last-success time; {@code lastError} holds codes only. */
    @Transactional
    public void recordProviderSyncOutcome(UUID id, String health, boolean succeeded, String lastError) {
        jdbc.update("""
                UPDATE identity_source SET health = ?, last_success_at = CASE WHEN ? THEN now() ELSE last_success_at END,
                       last_error = ?, updated_at = now()
                 WHERE id = ? AND kind IN ('SERVICENOW','ENTRA','OKTA')
                """, health, succeeded, lastError == null ? null : lastError.substring(0, Math.min(lastError.length(), 1000)), id);
    }

    /** Moves a provider source from one of {@code from} to {@code to}. Returns false when it was in none of them. */
    @Transactional
    public boolean setProviderSourceState(UUID id, String kind, List<String> from, String to) {
        return setProviderSourceState(id, kind, from, to, null);
    }

    /** As {@link #setProviderSourceState(UUID, String, List, String)}, and only at {@code expectedVersion} when given. */
    @Transactional
    public boolean setProviderSourceState(UUID id, String kind, List<String> from, String to, Long expectedVersion) {
        requireProviderKind(kind);
        List<Object> args = new ArrayList<>(List.of(to, id, kind));
        args.addAll(from);
        String versionClause = "";
        if (expectedVersion != null) {
            versionClause = " AND version = ?";
            args.add(expectedVersion);
        }
        return jdbc.update("UPDATE identity_source SET state = ?, updated_at = now(), version = version + 1"
                + " WHERE id = ? AND kind = ? AND state IN (" + String.join(", ", java.util.Collections.nCopies(from.size(), "?")) + ")"
                + versionClause, args.toArray()) == 1;
    }

    private static void requireProviderKind(String kind) {
        if (!PROVIDER_KINDS.contains(kind)) throw new IllegalArgumentException("Not a provider identity-source kind: " + kind);
    }

    // ----- users ----------------------------------------------------------------------------------------------

    @Transactional
    public DirectoryUser createUser(String displayName, String email, String employeeId, UUID managerUserId, UUID sourceId, String actor) {
        UUID tenant = requireReady();
        String normalizedEmail = normalizeEmail(email);
        if (normalizedEmail != null && userIdByEmail(normalizedEmail).isPresent()) {
            throw conflict("Another directory user already has this email; link or review instead of creating a duplicate");
        }
        return insertUser(tenant, displayName, normalizedEmail, employeeId, managerUserId, sourceId, actor);
    }

    /** Inserts a person without the duplicate-email check; callers decide whether a shared email is acceptable. */
    private DirectoryUser insertUser(UUID tenant, String displayName, String normalizedEmail, String employeeId, UUID managerUserId,
                                     UUID sourceId, String actor) {
        String name = displayName(displayName);
        String normalizedEmployee = blankToNull(employeeId);
        if (managerUserId != null) requireUser(managerUserId);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO directory_user (tenant_id, id, display_name_enc, email_enc, email_index, employee_id_enc, employee_id_index,
                                            manager_user_id, created_source_id, created_by)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, id, cipher.encrypt(tenant, P_NAME, name),
                normalizedEmail == null ? null : cipher.encrypt(tenant, P_EMAIL, normalizedEmail),
                normalizedEmail == null ? null : cipher.blindIndex(tenant, P_EMAIL, normalizedEmail),
                normalizedEmployee == null ? null : cipher.encrypt(tenant, P_EMPLOYEE, normalizedEmployee),
                normalizedEmployee == null ? null : cipher.blindIndex(tenant, P_EMPLOYEE, normalizedEmployee.toLowerCase(Locale.ROOT)),
                managerUserId, sourceId, actor);
        writeSearchTokens(tenant, "USER", id, name);
        audit.record("ownership.directory_user.created", "directory_user", id.toString(),
                OwnershipEvents.json(Map.of("sourceId", sourceId, "hasEmail", normalizedEmail != null)));
        return user(id).orElseThrow();
    }

    /** Updates only the fields given (null = unchanged; blank email/employee id = clear). */
    @Transactional
    public DirectoryUser updateUser(UUID id, String displayName, String email, String employeeId, UUID managerUserId,
                                    boolean clearManager, long expectedVersion, String actor) {
        UUID tenant = requireReady();
        DirectoryUser current = requireUser(id);
        String name = displayName == null ? current.displayName() : displayName(displayName);
        String newEmail = email == null ? current.email() : normalizeEmail(email);
        String newEmployee = employeeId == null ? current.employeeId() : blankToNull(employeeId);
        if (newEmail != null && !newEmail.equals(current.email())) {
            Optional<UUID> holder = userIdByEmail(newEmail);
            if (holder.isPresent() && !holder.get().equals(id)) throw conflict("Another directory user already has this email");
        }
        UUID manager = clearManager ? null : managerUserId == null ? current.managerUserId() : managerUserId;
        if (manager != null) {
            if (manager.equals(id)) throw bad("A person cannot be their own manager");
            requireUser(manager);
            if (managesTransitively(id, manager)) throw bad("This manager would create a reporting cycle");
        }
        int changed = jdbc.update("""
                UPDATE directory_user SET display_name_enc = ?, email_enc = ?, email_index = ?, employee_id_enc = ?, employee_id_index = ?,
                       manager_user_id = ?, updated_at = now(), version = version + 1
                 WHERE id = ? AND version = ?
                """, cipher.encrypt(tenant, P_NAME, name),
                newEmail == null ? null : cipher.encrypt(tenant, P_EMAIL, newEmail),
                newEmail == null ? null : cipher.blindIndex(tenant, P_EMAIL, newEmail),
                newEmployee == null ? null : cipher.encrypt(tenant, P_EMPLOYEE, newEmployee),
                newEmployee == null ? null : cipher.blindIndex(tenant, P_EMPLOYEE, newEmployee.toLowerCase(Locale.ROOT)),
                manager, id, expectedVersion);
        if (changed != 1) throw conflict("The person changed since it was loaded; reload and try again");
        if (!name.equals(current.displayName())) writeSearchTokens(tenant, "USER", id, name);
        audit.record("ownership.directory_user.updated", "directory_user", id.toString(), OwnershipEvents.json(Map.of(
                "nameChanged", !name.equals(current.displayName()), "emailChanged", !java.util.Objects.equals(newEmail, current.email()),
                "managerUserId", manager == null ? "" : manager.toString())));
        return user(id).orElseThrow();
    }

    /** Deactivation keeps every historical reference; reactivation restores the same canonical identity. */
    @Transactional
    public DirectoryUser setUserStatus(UUID id, String status, long expectedVersion, String actor) {
        requireReady();
        if (!STATUSES.contains(status)) throw bad("Unknown status");
        requireUser(id);
        int changed = jdbc.update("UPDATE directory_user SET status = ?, updated_at = now(), version = version + 1 WHERE id = ? AND version = ?",
                status, id, expectedVersion);
        if (changed != 1) throw conflict("The person changed since it was loaded; reload and try again");
        audit.record("ownership.directory_user.status_changed", "directory_user", id.toString(), OwnershipEvents.json(Map.of("status", status)));
        return user(id).orElseThrow();
    }

    @Transactional(readOnly = true)
    public Optional<DirectoryUser> user(UUID id) {
        UUID tenant = TenantContext.getCurrentTenantId();
        return jdbc.query("""
                SELECT id, display_name_enc, email_enc, employee_id_enc, manager_user_id, status, version FROM directory_user WHERE id = ?
                """, (rs, row) -> new DirectoryUser(rs.getObject(1, UUID.class), cipher.decrypt(tenant, P_NAME, rs.getString(2)),
                decryptOrNull(tenant, P_EMAIL, rs.getString(3)), decryptOrNull(tenant, P_EMPLOYEE, rs.getString(4)),
                rs.getObject(5, UUID.class), rs.getString(6), rs.getLong(7)), id).stream().findFirst();
    }

    @Transactional(readOnly = true)
    public Optional<UUID> userIdByEmail(String email) {
        String normalized = normalizeEmail(email);
        if (normalized == null) return Optional.empty();
        List<UUID> ids = jdbc.queryForList("SELECT id FROM directory_user WHERE email_index = ? AND status <> 'DELETED'", UUID.class,
                cipher.blindIndex(TenantContext.getCurrentTenantId(), P_EMAIL, normalized));
        return ids.size() == 1 ? Optional.of(ids.get(0)) : Optional.empty();
    }

    /**
     * Prefix search over display names. Every query word must prefix some word of the name. Queries shorter than
     * {@value #MIN_PREFIX} characters return nothing; words are matched on at most {@value #MAX_PREFIX} characters.
     */
    @Transactional(readOnly = true)
    public List<DirectoryUser> searchUsers(String query, int limit) {
        UUID tenant = TenantContext.getCurrentTenantId();
        List<String> words = words(query).stream().filter(w -> w.length() >= MIN_PREFIX)
                .map(w -> w.length() > MAX_PREFIX ? w.substring(0, MAX_PREFIX) : w).distinct().toList();
        if (words.isEmpty()) return List.of();
        List<byte[]> tokens = words.stream().map(w -> cipher.blindIndex(tenant, P_SEARCH, w)).toList();
        StringBuilder sql = new StringBuilder("SELECT t0.entity_id FROM directory_search_token t0");
        List<Object> args = new ArrayList<>();
        for (int i = 1; i < tokens.size(); i++) {
            sql.append(" JOIN directory_search_token t").append(i).append(" ON t").append(i).append(".entity_kind = 'USER' AND t")
                    .append(i).append(".entity_id = t0.entity_id AND t").append(i).append(".token = ?");
            args.add(tokens.get(i));
        }
        sql.append(" WHERE t0.entity_kind = 'USER' AND t0.token = ? LIMIT ?");
        args.add(tokens.get(0));
        args.add(Math.max(1, Math.min(limit, 100)));
        List<UUID> ids = jdbc.queryForList(sql.toString(), UUID.class, args.toArray());
        return ids.stream().map(this::user).flatMap(Optional::stream)
                .sorted(java.util.Comparator.comparing(DirectoryUser::displayName, String.CASE_INSENSITIVE_ORDER)).toList();
    }

    // ----- groups and memberships -----------------------------------------------------------------------------

    @Transactional
    public DirectoryGroup createGroup(String displayName, UUID sourceId, String actor) {
        requireReady();
        String name = displayName(displayName);
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO directory_group (tenant_id, id, display_name, name_key, created_source_id, created_by) VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?)",
                id, name, name.toLowerCase(Locale.ROOT), sourceId, actor);
        audit.record("ownership.directory_group.created", "directory_group", id.toString(), OwnershipEvents.json(Map.of("sourceId", sourceId)));
        return group(id).orElseThrow();
    }

    @Transactional
    public DirectoryGroup updateGroup(UUID id, String displayName, String status, long expectedVersion, String actor) {
        requireReady();
        DirectoryGroup current = group(id).orElseThrow(() -> notFound("Group not found"));
        String name = displayName == null ? current.displayName() : displayName(displayName);
        String newStatus = status == null ? current.status() : status;
        if (!STATUSES.contains(newStatus)) throw bad("Unknown status");
        int changed = jdbc.update("""
                UPDATE directory_group SET display_name = ?, name_key = ?, status = ?, updated_at = now(), version = version + 1
                 WHERE id = ? AND version = ?
                """, name, name.toLowerCase(Locale.ROOT), newStatus, id, expectedVersion);
        if (changed != 1) throw conflict("The group changed since it was loaded; reload and try again");
        audit.record("ownership.directory_group.updated", "directory_group", id.toString(), OwnershipEvents.json(Map.of("status", newStatus)));
        return group(id).orElseThrow();
    }

    @Transactional(readOnly = true)
    public Optional<DirectoryGroup> group(UUID id) {
        return jdbc.query("SELECT id, display_name, status, version FROM directory_group WHERE id = ?",
                (rs, row) -> new DirectoryGroup(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getLong(4)), id)
                .stream().findFirst();
    }

    @Transactional(readOnly = true)
    public List<DirectoryGroup> searchGroups(String query, int limit) {
        String prefix = query == null ? "" : query.strip().toLowerCase(Locale.ROOT);
        String escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return jdbc.query("""
                SELECT id, display_name, status, version FROM directory_group WHERE name_key LIKE ? ESCAPE '\\' AND status <> 'DELETED'
                 ORDER BY name_key LIMIT ?
                """, (rs, row) -> new DirectoryGroup(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getLong(4)),
                escaped + "%", Math.max(1, Math.min(limit, 100)));
    }

    /** Adds (or re-activates) a membership observed from {@code sourceId}. Returns true when anything changed. */
    @Transactional
    public boolean addMember(UUID groupId, UUID userId, UUID sourceId, String actor) {
        requireReady();
        group(groupId).orElseThrow(() -> notFound("Group not found"));
        requireUser(userId);
        int changed = jdbc.update("""
                INSERT INTO directory_group_member (tenant_id, id, group_id, user_id, source_id) VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, group_id, user_id, source_id)
                DO UPDATE SET status = 'ACTIVE', observed_at = now(), updated_at = now() WHERE directory_group_member.status <> 'ACTIVE'
                """, UUID.randomUUID(), groupId, userId, sourceId);
        if (changed > 0) {
            audit.record("ownership.directory_membership.added", "directory_group", groupId.toString(),
                    OwnershipEvents.json(Map.of("userId", userId, "sourceId", sourceId)));
        }
        return changed > 0;
    }

    /** Marks a membership REMOVED; history is kept. Returns true when anything changed. */
    @Transactional
    public boolean removeMember(UUID groupId, UUID userId, UUID sourceId, String actor) {
        requireReady();
        int changed = jdbc.update("""
                UPDATE directory_group_member SET status = 'REMOVED', updated_at = now()
                 WHERE group_id = ? AND user_id = ? AND source_id = ? AND status = 'ACTIVE'
                """, groupId, userId, sourceId);
        if (changed > 0) {
            audit.record("ownership.directory_membership.removed", "directory_group", groupId.toString(),
                    OwnershipEvents.json(Map.of("userId", userId, "sourceId", sourceId)));
        }
        return changed > 0;
    }

    @Transactional(readOnly = true)
    public List<Membership> members(UUID groupId) {
        return jdbc.query("SELECT group_id, user_id, source_id, status FROM directory_group_member WHERE group_id = ? AND status = 'ACTIVE'",
                (rs, row) -> new Membership(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getObject(3, UUID.class),
                        rs.getString(4)), groupId);
    }

    // ----- external identities (used by CSV and provider imports) ----------------------------------------------

    /** Canonical identity key (design §3): the user linked to {@code (source, externalId)}, if any. */
    @Transactional(readOnly = true)
    public Optional<UUID> userIdByExternalId(UUID sourceId, String externalId) {
        return jdbc.queryForList("SELECT user_id FROM external_identity WHERE source_id = ? AND external_id_index = ? AND user_id IS NOT NULL",
                UUID.class, sourceId, externalIndex(externalId)).stream().findFirst();
    }

    /** Links {@code (source, externalId)} to {@code userId}; idempotent for the same user. */
    @Transactional
    public void linkExternalIdentity(UUID sourceId, String externalId, UUID userId, UUID runId) {
        UUID tenant = requireReady();
        String key = externalKey(externalId);
        int changed = jdbc.update("""
                INSERT INTO external_identity (tenant_id, id, source_id, external_id_enc, external_id_index, user_id, link_status, last_seen_run_id)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, 'LINKED', ?)
                ON CONFLICT (tenant_id, source_id, external_id_index)
                DO UPDATE SET observed_at = now(), updated_at = now(), last_seen_run_id = EXCLUDED.last_seen_run_id
                 WHERE external_identity.user_id = EXCLUDED.user_id
                """, UUID.randomUUID(), sourceId, cipher.encrypt(tenant, P_EXTERNAL_ID, key), cipher.blindIndex(tenant, P_EXTERNAL_ID, key),
                userId, runId);
        if (changed == 0) throw conflict("This external identity is already linked to another person");
    }

    @Transactional(readOnly = true)
    public Optional<UUID> groupIdByExternalId(UUID sourceId, String externalId) {
        return jdbc.queryForList("SELECT group_id FROM external_group WHERE source_id = ? AND external_id_index = ? AND group_id IS NOT NULL",
                UUID.class, sourceId, externalIndex(externalId)).stream().findFirst();
    }

    @Transactional
    public void linkExternalGroup(UUID sourceId, String externalId, String displayName, UUID groupId, UUID runId) {
        UUID tenant = requireReady();
        String key = externalKey(externalId);
        int changed = jdbc.update("""
                INSERT INTO external_group (tenant_id, id, source_id, external_id_enc, external_id_index, display_name, group_id, last_seen_run_id)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, source_id, external_id_index)
                DO UPDATE SET display_name = EXCLUDED.display_name, observed_at = now(), updated_at = now(),
                              last_seen_run_id = EXCLUDED.last_seen_run_id
                 WHERE external_group.group_id = EXCLUDED.group_id
                """, UUID.randomUUID(), sourceId, cipher.encrypt(tenant, P_EXTERNAL_ID, key), cipher.blindIndex(tenant, P_EXTERNAL_ID, key),
                displayName(displayName), groupId, runId);
        if (changed == 0) throw conflict("This external group is already linked to another group");
    }

    // ----- provider identity linking (Phase 0B §1.4) ----------------------------------------------------------

    /** One user record as a provider sync observed it. Values are plaintext only here; they are stored as tenant ciphertext. */
    public record ObservedIdentity(UUID sourceId, String externalId, String displayName, String email, String username,
                                   String employeeNumber, boolean active) { }

    public enum LinkOutcome {
        /** Rule 1: the identity was already linked and stays linked to the same person. */
        KEPT_LINK,
        /** Rule 2: the email matched exactly one person, who is active. */
        LINKED_BY_EMAIL,
        /** Rule 4: nobody matched, so a person was created for this source. */
        CREATED_PERSON,
        /** Rule 3: more than one person matched, or only inactive people did. Waits for an admin. */
        AMBIGUOUS,
        /** A new identity that is inactive or locked out: recorded as evidence, not linked and no person created. */
        UNLINKED_INACTIVE
    }

    /** What an observation did to the stored rows, for a run's counts. */
    public enum RowChange { CREATED, UPDATED, UNCHANGED }

    /** {@code change} covers the identity row and, for this source's own people, the linked person's fields. */
    public record IdentityObservation(UUID identityId, LinkOutcome outcome, UUID userId, RowChange change) { }

    public record IdentityResolution(UUID identityId, UUID userId, boolean createdPerson) { }

    static final String P_USERNAME = "directory.external.username";
    static final String REVIEW_AMBIGUOUS = "AMBIGUOUS_IDENTITY";
    private static final int MAX_CANDIDATES = 100;
    private static final int MAX_CANDIDATES_IN_REVIEW = 10;

    private record IdentityRow(UUID id, UUID userId, String linkStatus, byte[] emailIndex, String usernameEnc, String status) { }

    private record Candidate(UUID id, String status) { }

    /**
     * Records a provider identity and applies linking rules 1–6. It never merges, deletes or relinks people.
     * {@code user_name} and employee number are stored as evidence only and never drive a link (rule 6).
     * An email that is not a valid address is treated as absent.
     *
     * <p>When the identity is linked (rules 1 and 2) and the person was created by this source, the person's display
     * name, email and employee number follow the provider (§1.3), and an inactive person is reactivated by an active
     * identity. People created manually, by CSV or by another source keep their values. A provider email that
     * another person already holds is not copied to the person; rule 5 reports it instead.
     */
    @Transactional
    public IdentityObservation observeIdentity(ObservedIdentity observed, UUID runId, String actor) {
        UUID tenant = requireReady();
        UUID sourceId = java.util.Objects.requireNonNull(observed.sourceId(), "sourceId");
        String key = externalKey(observed.externalId());
        byte[] externalIndex = cipher.blindIndex(tenant, P_EXTERNAL_ID, key);
        String email = sourceEmail(observed.email());
        byte[] emailIndex = email == null ? null : cipher.blindIndex(tenant, P_EMAIL, email);
        String username = blankToNull(observed.username());
        // Identity first, then email: each call takes at most one of each, so the order cannot deadlock.
        advisoryLock(tenant + "|ownership.external-identity|" + sourceId + "|" + HexFormat.of().formatHex(externalIndex));
        if (emailIndex != null) advisoryLock(tenant + "|ownership.directory-email|" + HexFormat.of().formatHex(emailIndex));

        String emailEnc = email == null ? null : cipher.encrypt(tenant, P_EMAIL, email);
        String usernameEnc = username == null ? null : cipher.encrypt(tenant, P_USERNAME, username);
        String status = observed.active() ? "ACTIVE" : "INACTIVE";
        List<IdentityRow> existing = jdbc.query("""
                SELECT id, user_id, link_status, email_index, username_enc, status FROM external_identity
                 WHERE source_id = ? AND external_id_index = ? FOR UPDATE
                """, (rs, n) -> new IdentityRow(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3), rs.getBytes(4),
                rs.getString(5), rs.getString(6)), sourceId, externalIndex);
        IdentityRow row;
        boolean identityChanged;
        if (existing.isEmpty()) {
            row = new IdentityRow(UUID.randomUUID(), null, "UNLINKED", null, null, null);
            identityChanged = true;
            jdbc.update("""
                    INSERT INTO external_identity (tenant_id, id, source_id, external_id_enc, external_id_index, email_enc, email_index,
                                                   username_enc, status, last_seen_run_id)
                    VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, row.id(), sourceId, cipher.encrypt(tenant, P_EXTERNAL_ID, key), externalIndex, emailEnc, emailIndex, usernameEnc,
                    status, runId);
        } else {
            row = existing.get(0);
            identityChanged = !java.util.Arrays.equals(row.emailIndex(), emailIndex) || !status.equals(row.status())
                    || !java.util.Objects.equals(decryptOrNull(tenant, P_USERNAME, row.usernameEnc()), username);
            // Rule 1: evidence fields follow the provider; the link does not move.
            jdbc.update("""
                    UPDATE external_identity SET email_enc = ?, email_index = ?, username_enc = ?, status = ?, observed_at = now(),
                           updated_at = now(), last_seen_run_id = COALESCE(?, last_seen_run_id)
                     WHERE id = ?
                    """, emailEnc, emailIndex, usernameEnc, status, runId, row.id());
        }
        RowChange created = existing.isEmpty() ? RowChange.CREATED : null;

        List<Candidate> candidates = emailIndex == null ? List.of() : candidates(emailIndex);
        if ("LINKED".equals(row.linkStatus())) {
            // Rule 5: report drift to a different person; change nothing.
            List<UUID> others = candidates.stream().map(Candidate::id).filter(id -> !id.equals(row.userId())).toList();
            if (!others.isEmpty()) {
                raiseAmbiguous(driftKey(row.id()), row.id(), sourceId, "EMAIL_MATCHES_OTHER_PERSON", others, row.userId());
            }
            boolean personChanged = refreshSourcePerson(tenant, row.userId(), sourceId, observed, key, email, actor);
            return new IdentityObservation(row.id(), LinkOutcome.KEPT_LINK, row.userId(),
                    identityChanged || personChanged ? RowChange.UPDATED : RowChange.UNCHANGED);
        }
        RowChange touched = created != null ? created : identityChanged ? RowChange.UPDATED : RowChange.UNCHANGED;
        if ("AMBIGUOUS".equals(row.linkStatus())) {
            raiseAmbiguous(ambiguousKey(row.id()), row.id(), sourceId, ambiguityReason(candidates),
                    candidates.stream().map(Candidate::id).toList(), null);
            return new IdentityObservation(row.id(), LinkOutcome.AMBIGUOUS, null, touched);
        }
        if (!observed.active()) return new IdentityObservation(row.id(), LinkOutcome.UNLINKED_INACTIVE, null, touched);
        RowChange linked = created != null ? created : RowChange.UPDATED;
        if (candidates.isEmpty()) {
            DirectoryUser person = insertUser(tenant, personName(observed, key), email, observed.employeeNumber(), null, sourceId, actor);
            linkIdentity(row.id(), person.id());
            return new IdentityObservation(row.id(), LinkOutcome.CREATED_PERSON, person.id(), linked);
        }
        if (candidates.size() == 1 && "ACTIVE".equals(candidates.get(0).status())) {
            linkIdentity(row.id(), candidates.get(0).id());
            refreshSourcePerson(tenant, candidates.get(0).id(), sourceId, observed, key, email, actor);
            return new IdentityObservation(row.id(), LinkOutcome.LINKED_BY_EMAIL, candidates.get(0).id(), linked);
        }
        jdbc.update("UPDATE external_identity SET link_status = 'AMBIGUOUS', updated_at = now() WHERE id = ?", row.id());
        raiseAmbiguous(ambiguousKey(row.id()), row.id(), sourceId, ambiguityReason(candidates),
                candidates.stream().map(Candidate::id).toList(), null);
        return new IdentityObservation(row.id(), LinkOutcome.AMBIGUOUS, null, linked);
    }

    private record SourcePerson(String nameEnc, String emailEnc, String employeeEnc, String status, UUID createdSourceId, long version) { }

    /**
     * §1.3 field writes for a linked person, only when {@code sourceId} created the person. Returns true when anything
     * changed. A name the directory cannot hold keeps the current name; an email another person holds keeps the current
     * email.
     */
    private boolean refreshSourcePerson(UUID tenant, UUID userId, UUID sourceId, ObservedIdentity observed, String key, String email,
                                        String actor) {
        List<SourcePerson> rows = jdbc.query("""
                SELECT display_name_enc, email_enc, employee_id_enc, status, created_source_id, version FROM directory_user WHERE id = ? FOR UPDATE
                """, (rs, n) -> new SourcePerson(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getObject(5, UUID.class), rs.getLong(6)), userId);
        if (rows.isEmpty()) return false;
        SourcePerson current = rows.get(0);
        if (!sourceId.equals(current.createdSourceId()) || "DELETED".equals(current.status())) return false;
        String currentName = cipher.decrypt(tenant, P_NAME, current.nameEnc());
        String currentEmail = decryptOrNull(tenant, P_EMAIL, current.emailEnc());
        String currentEmployee = decryptOrNull(tenant, P_EMPLOYEE, current.employeeEnc());
        String name;
        try {
            name = OwnershipNames.display(personName(observed, key));
        } catch (IllegalArgumentException unusable) {
            name = currentName;
        }
        String newEmail = email;
        if (newEmail != null && !newEmail.equals(currentEmail)) {
            boolean heldByOther = !jdbc.queryForList("SELECT id FROM directory_user WHERE email_index = ? AND status <> 'DELETED' AND id <> ? LIMIT 1",
                    UUID.class, cipher.blindIndex(tenant, P_EMAIL, newEmail), userId).isEmpty();
            if (heldByOther) newEmail = currentEmail;
        }
        String newEmployee = blankToNull(observed.employeeNumber());
        String newStatus = observed.active() && "INACTIVE".equals(current.status()) ? "ACTIVE" : current.status();
        boolean nameChanged = !name.equals(currentName);
        boolean emailChanged = !java.util.Objects.equals(newEmail, currentEmail);
        boolean employeeChanged = !java.util.Objects.equals(newEmployee, currentEmployee);
        boolean reactivated = !newStatus.equals(current.status());
        if (!nameChanged && !emailChanged && !employeeChanged && !reactivated) return false;
        jdbc.update("""
                UPDATE directory_user SET display_name_enc = ?, email_enc = ?, email_index = ?, employee_id_enc = ?, employee_id_index = ?,
                       status = ?, updated_at = now(), version = version + 1
                 WHERE id = ?
                """, nameChanged ? cipher.encrypt(tenant, P_NAME, name) : current.nameEnc(),
                newEmail == null ? null : emailChanged ? cipher.encrypt(tenant, P_EMAIL, newEmail) : current.emailEnc(),
                newEmail == null ? null : cipher.blindIndex(tenant, P_EMAIL, newEmail),
                newEmployee == null ? null : employeeChanged ? cipher.encrypt(tenant, P_EMPLOYEE, newEmployee) : current.employeeEnc(),
                newEmployee == null ? null : cipher.blindIndex(tenant, P_EMPLOYEE, newEmployee.toLowerCase(Locale.ROOT)),
                newStatus, userId);
        if (nameChanged) writeSearchTokens(tenant, "USER", userId, name);
        audit.record("ownership.directory_user.updated", "directory_user", userId.toString(), OwnershipEvents.json(Map.of(
                "sourceId", sourceId, "nameChanged", nameChanged, "emailChanged", emailChanged, "employeeIdChanged", employeeChanged,
                "reactivated", reactivated)));
        return true;
    }

    /**
     * Sets the manager of a person created by {@code sourceId} from the provider's manager reference (§1.3); null
     * clears it. People created manually, by CSV or by another source keep their manager. A manager that would create
     * a reporting cycle is not set. Returns true when the manager changed.
     */
    @Transactional
    public boolean setSourceManager(UUID userId, UUID managerUserId, UUID sourceId, String actor) {
        requireReady();
        List<Object[]> rows = jdbc.query("SELECT manager_user_id, created_source_id, status FROM directory_user WHERE id = ? FOR UPDATE",
                (rs, n) -> new Object[] {rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3)}, userId);
        if (rows.isEmpty() || !sourceId.equals(rows.get(0)[1]) || "DELETED".equals(rows.get(0)[2])) return false;
        if (java.util.Objects.equals(rows.get(0)[0], managerUserId)) return false;
        if (managerUserId != null && (managerUserId.equals(userId) || user(managerUserId).isEmpty()
                || managesTransitively(userId, managerUserId))) {
            return false;
        }
        jdbc.update("UPDATE directory_user SET manager_user_id = ?, updated_at = now(), version = version + 1 WHERE id = ?", managerUserId, userId);
        audit.record("ownership.directory_user.updated", "directory_user", userId.toString(), OwnershipEvents.json(Map.of(
                "sourceId", sourceId, "managerUserId", managerUserId == null ? "" : managerUserId.toString())));
        return true;
    }

    // ----- provider groups and memberships (Phase 0B §1.3) ----------------------------------------------------

    public record ObservedGroup(UUID sourceId, String externalId, String displayName, boolean active) { }

    public record GroupObservation(UUID externalGroupId, UUID groupId, RowChange change) { }

    /**
     * Records a provider group. A directory group is created for it on first sight and linked; a rename in the
     * provider renames only that directory group. An active group reactivates its directory group; deactivation
     * waits for a complete scan ({@link #deactivateAbsentGroups}).
     */
    @Transactional
    public GroupObservation observeGroup(ObservedGroup observed, UUID runId, String actor) {
        UUID tenant = requireReady();
        UUID sourceId = java.util.Objects.requireNonNull(observed.sourceId(), "sourceId");
        String key = externalKey(observed.externalId());
        byte[] index = cipher.blindIndex(tenant, P_EXTERNAL_ID, key);
        advisoryLock(tenant + "|ownership.external-group|" + sourceId + "|" + HexFormat.of().formatHex(index));
        String name = groupName(observed.displayName(), key);
        String status = observed.active() ? "ACTIVE" : "INACTIVE";
        List<Object[]> existing = jdbc.query("""
                SELECT id, group_id, display_name, status FROM external_group WHERE source_id = ? AND external_id_index = ? FOR UPDATE
                """, (rs, n) -> new Object[] {rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4)},
                sourceId, index);
        if (existing.isEmpty()) {
            UUID groupId = insertSourceGroup(name, status, sourceId, actor);
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    INSERT INTO external_group (tenant_id, id, source_id, external_id_enc, external_id_index, display_name, group_id, status,
                                                last_seen_run_id)
                    VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, id, sourceId, cipher.encrypt(tenant, P_EXTERNAL_ID, key), index, name, groupId, status, runId);
            return new GroupObservation(id, groupId, RowChange.CREATED);
        }
        UUID id = (UUID) existing.get(0)[0];
        UUID groupId = (UUID) existing.get(0)[1];
        boolean changed = !name.equals(existing.get(0)[2]) || !status.equals(existing.get(0)[3]);
        if (groupId == null) {
            groupId = insertSourceGroup(name, status, sourceId, actor);
            changed = true;
        }
        jdbc.update("""
                UPDATE external_group SET display_name = ?, status = ?, group_id = ?, observed_at = now(), updated_at = now(),
                       last_seen_run_id = COALESCE(?, last_seen_run_id)
                 WHERE id = ?
                """, name, status, groupId, runId, id);
        List<Object[]> group = jdbc.query("SELECT display_name, status, created_source_id FROM directory_group WHERE id = ? FOR UPDATE",
                (rs, n) -> new Object[] {rs.getString(1), rs.getString(2), rs.getObject(3, UUID.class)}, groupId);
        if (!group.isEmpty() && sourceId.equals(group.get(0)[2]) && !"DELETED".equals(group.get(0)[1])) {
            boolean renamed = !name.equals(group.get(0)[0]);
            boolean reactivated = observed.active() && "INACTIVE".equals(group.get(0)[1]);
            if (renamed || reactivated) {
                jdbc.update("""
                        UPDATE directory_group SET display_name = ?, name_key = ?, status = ?, updated_at = now(), version = version + 1
                         WHERE id = ?
                        """, name, name.toLowerCase(Locale.ROOT), reactivated ? "ACTIVE" : group.get(0)[1], groupId);
                audit.record("ownership.directory_group.updated", "directory_group", groupId.toString(), OwnershipEvents.json(Map.of(
                        "sourceId", sourceId, "renamed", renamed, "reactivated", reactivated)));
                changed = true;
            }
        }
        return new GroupObservation(id, groupId, changed ? RowChange.UPDATED : RowChange.UNCHANGED);
    }

    private UUID insertSourceGroup(String name, String status, UUID sourceId, String actor) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO directory_group (tenant_id, id, display_name, name_key, status, created_source_id, created_by)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?)
                """, id, name, name.toLowerCase(Locale.ROOT), status, sourceId, actor);
        audit.record("ownership.directory_group.created", "directory_group", id.toString(), OwnershipEvents.json(Map.of("sourceId", sourceId)));
        return id;
    }

    /** Records a provider membership between a linked group and a linked person, re-activating a removed one. */
    @Transactional
    public RowChange observeMembership(UUID groupId, UUID userId, UUID sourceId, UUID runId) {
        requireReady();
        List<String> status = jdbc.queryForList("""
                SELECT status FROM directory_group_member WHERE group_id = ? AND user_id = ? AND source_id = ? FOR UPDATE
                """, String.class, groupId, userId, sourceId);
        jdbc.update("""
                INSERT INTO directory_group_member (tenant_id, id, group_id, user_id, source_id, last_seen_run_id)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, group_id, user_id, source_id)
                DO UPDATE SET status = 'ACTIVE', observed_at = now(), updated_at = now(),
                              last_seen_run_id = COALESCE(EXCLUDED.last_seen_run_id, directory_group_member.last_seen_run_id)
                """, UUID.randomUUID(), groupId, userId, sourceId, runId);
        if (!status.isEmpty() && "ACTIVE".equals(status.get(0))) return RowChange.UNCHANGED;
        audit.record("ownership.directory_membership.added", "directory_group", groupId.toString(),
                OwnershipEvents.json(Map.of("userId", userId, "sourceId", sourceId)));
        return status.isEmpty() ? RowChange.CREATED : RowChange.UPDATED;
    }

    // ----- read-only planning for the anomaly gate (Phase 0B §1.7) ---------------------------------------------
    // Each planner predicts what the matching observe method would do, without writing. Existing ACTIVE rows that the
    // run sees are added to seenActive, so a complete scan can count the absent ones it would deactivate.

    /** What {@link #observeIdentity} would do to this identity and its source-created person (manager excluded). */
    @Transactional(readOnly = true)
    public RowChange planIdentity(ObservedIdentity observed, Set<UUID> seenActive) {
        UUID tenant = TenantContext.getCurrentTenantId();
        String key = externalKey(observed.externalId());
        String email = sourceEmail(observed.email());
        byte[] emailIndex = email == null ? null : cipher.blindIndex(tenant, P_EMAIL, email);
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT e.id, e.status, e.email_index, e.username_enc, e.link_status, e.user_id, u.created_source_id, u.display_name_enc,
                       u.email_enc, u.employee_id_enc, u.status AS person_status
                  FROM external_identity e LEFT JOIN directory_user u ON u.id = e.user_id
                 WHERE e.source_id = ? AND e.external_id_index = ?
                """, observed.sourceId(), cipher.blindIndex(tenant, P_EXTERNAL_ID, key));
        if (rows.isEmpty()) return RowChange.CREATED;
        Map<String, Object> row = rows.get(0);
        if ("ACTIVE".equals(row.get("status"))) seenActive.add((UUID) row.get("id"));
        boolean identityChanged = !java.util.Arrays.equals((byte[]) row.get("email_index"), emailIndex)
                || !(observed.active() ? "ACTIVE" : "INACTIVE").equals(row.get("status"))
                || !java.util.Objects.equals(decryptOrNull(tenant, P_USERNAME, (String) row.get("username_enc")), blankToNull(observed.username()));
        if (identityChanged) return RowChange.UPDATED;
        if ("UNLINKED".equals(row.get("link_status"))) return observed.active() ? RowChange.UPDATED : RowChange.UNCHANGED;
        if (!"LINKED".equals(row.get("link_status")) || !observed.sourceId().equals(row.get("created_source_id"))
                || "DELETED".equals(row.get("person_status"))) {
            return RowChange.UNCHANGED;
        }
        String currentName = cipher.decrypt(tenant, P_NAME, (String) row.get("display_name_enc"));
        String name;
        try {
            name = OwnershipNames.display(personName(observed, key));
        } catch (IllegalArgumentException unusable) {
            name = currentName;
        }
        String currentEmail = decryptOrNull(tenant, P_EMAIL, (String) row.get("email_enc"));
        boolean emailChanges = !java.util.Objects.equals(email, currentEmail) && (email == null || jdbc.queryForList(
                "SELECT id FROM directory_user WHERE email_index = ? AND status <> 'DELETED' AND id <> ? LIMIT 1", UUID.class, emailIndex,
                row.get("user_id")).isEmpty());
        boolean changed = !name.equals(currentName) || emailChanges
                || !java.util.Objects.equals(blankToNull(observed.employeeNumber()), decryptOrNull(tenant, P_EMPLOYEE, (String) row.get("employee_id_enc")))
                || (observed.active() && "INACTIVE".equals(row.get("person_status")));
        return changed ? RowChange.UPDATED : RowChange.UNCHANGED;
    }

    /** What {@link #observeGroup} would do. */
    @Transactional(readOnly = true)
    public RowChange planGroup(ObservedGroup observed, Set<UUID> seenActive) {
        UUID tenant = TenantContext.getCurrentTenantId();
        String key = externalKey(observed.externalId());
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT e.id, e.display_name, e.status, e.group_id, g.display_name AS group_name, g.status AS group_status, g.created_source_id
                  FROM external_group e LEFT JOIN directory_group g ON g.id = e.group_id
                 WHERE e.source_id = ? AND e.external_id_index = ?
                """, observed.sourceId(), cipher.blindIndex(tenant, P_EXTERNAL_ID, key));
        if (rows.isEmpty()) return RowChange.CREATED;
        Map<String, Object> row = rows.get(0);
        if ("ACTIVE".equals(row.get("status"))) seenActive.add((UUID) row.get("id"));
        String name = groupName(observed.displayName(), key);
        boolean ownGroup = observed.sourceId().equals(row.get("created_source_id")) && !"DELETED".equals(row.get("group_status"));
        boolean changed = !name.equals(row.get("display_name")) || !(observed.active() ? "ACTIVE" : "INACTIVE").equals(row.get("status"))
                || row.get("group_id") == null
                || (ownGroup && (!name.equals(row.get("group_name")) || (observed.active() && "INACTIVE".equals(row.get("group_status")))));
        return changed ? RowChange.UPDATED : RowChange.UNCHANGED;
    }

    /** What {@link #observeMembership} would do; null when the person or group is not linked yet (the row is rejected). */
    @Transactional(readOnly = true)
    public RowChange planMembership(UUID sourceId, String groupExternalId, String userExternalId, Set<UUID> seenActive) {
        Optional<UUID> group = groupIdByExternalId(sourceId, groupExternalId);
        Optional<UUID> user = userIdByExternalId(sourceId, userExternalId);
        if (group.isEmpty() || user.isEmpty()) return null;
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, status FROM directory_group_member WHERE group_id = ? AND user_id = ? AND source_id = ?", group.get(), user.get(), sourceId);
        if (rows.isEmpty()) return RowChange.CREATED;
        if (!"ACTIVE".equals(rows.get(0).get("status"))) return RowChange.UPDATED;
        seenActive.add((UUID) rows.get(0).get("id"));
        return RowChange.UNCHANGED;
    }

    /** Active rows this source owns in a directory table, the anomaly gate's denominator. */
    @Transactional(readOnly = true)
    public long activeSourceRows(UUID sourceId, String table) {
        String sql = switch (table) {
            case "sys_user" -> "SELECT count(*) FROM external_identity WHERE source_id = ? AND status = 'ACTIVE'";
            case "sys_user_group" -> "SELECT count(*) FROM external_group WHERE source_id = ? AND status = 'ACTIVE'";
            case "sys_user_grmember" -> "SELECT count(*) FROM directory_group_member WHERE source_id = ? AND status = 'ACTIVE'";
            default -> throw new IllegalArgumentException("Not a directory table: " + table);
        };
        return jdbc.queryForObject(sql, Long.class, sourceId);
    }

    // ----- complete-scan reconciliation (Phase 0B §1.5): only after a complete scan without a page error ---------

    /** Marks this source's identities that {@code runId} did not see INACTIVE. Returns how many changed. */
    @Transactional
    public int deactivateAbsentIdentities(UUID sourceId, UUID runId) {
        requireReady();
        int changed = jdbc.update("""
                UPDATE external_identity SET status = 'INACTIVE', updated_at = now()
                 WHERE source_id = ? AND status = 'ACTIVE' AND last_seen_run_id IS DISTINCT FROM ?
                """, sourceId, runId);
        if (changed > 0) {
            audit.record("ownership.external_identity.deactivated", "identity_source", sourceId.toString(),
                    OwnershipEvents.json(Map.of("runId", runId, "count", changed)));
        }
        return changed;
    }

    /**
     * Deactivates people created by {@code sourceId} whose every linked identity is inactive. People created manually,
     * by CSV or by another source are never deactivated here. Returns how many changed.
     */
    @Transactional
    public int deactivateSourcePeople(UUID sourceId, UUID runId) {
        requireReady();
        int changed = jdbc.update("""
                UPDATE directory_user u SET status = 'INACTIVE', updated_at = now(), version = u.version + 1
                 WHERE u.created_source_id = ? AND u.status = 'ACTIVE'
                   AND EXISTS (SELECT 1 FROM external_identity e WHERE e.user_id = u.id)
                   AND NOT EXISTS (SELECT 1 FROM external_identity e WHERE e.user_id = u.id AND e.status = 'ACTIVE')
                """, sourceId);
        if (changed > 0) {
            audit.record("ownership.directory_user.deactivated", "identity_source", sourceId.toString(),
                    OwnershipEvents.json(Map.of("runId", runId, "count", changed)));
        }
        return changed;
    }

    /**
     * Marks this source's groups that {@code runId} did not see INACTIVE, then deactivates directory groups created by
     * the source whose every external group is inactive. Returns how many external groups changed.
     */
    @Transactional
    public int deactivateAbsentGroups(UUID sourceId, UUID runId) {
        requireReady();
        int changed = jdbc.update("""
                UPDATE external_group SET status = 'INACTIVE', updated_at = now()
                 WHERE source_id = ? AND status = 'ACTIVE' AND last_seen_run_id IS DISTINCT FROM ?
                """, sourceId, runId);
        int groups = jdbc.update("""
                UPDATE directory_group g SET status = 'INACTIVE', updated_at = now(), version = g.version + 1
                 WHERE g.created_source_id = ? AND g.status = 'ACTIVE'
                   AND EXISTS (SELECT 1 FROM external_group e WHERE e.group_id = g.id)
                   AND NOT EXISTS (SELECT 1 FROM external_group e WHERE e.group_id = g.id AND e.status = 'ACTIVE')
                """, sourceId);
        if (changed > 0 || groups > 0) {
            audit.record("ownership.directory_group.deactivated", "identity_source", sourceId.toString(),
                    OwnershipEvents.json(Map.of("runId", runId, "externalGroups", changed, "groups", groups)));
        }
        return changed;
    }

    /** Marks this source's memberships that {@code runId} did not see REMOVED; history is kept. Returns how many changed. */
    @Transactional
    public int removeAbsentMemberships(UUID sourceId, UUID runId) {
        requireReady();
        int changed = jdbc.update("""
                UPDATE directory_group_member SET status = 'REMOVED', updated_at = now()
                 WHERE source_id = ? AND status = 'ACTIVE' AND last_seen_run_id IS DISTINCT FROM ?
                """, sourceId, runId);
        if (changed > 0) {
            audit.record("ownership.directory_membership.removed", "identity_source", sourceId.toString(),
                    OwnershipEvents.json(Map.of("runId", runId, "count", changed)));
        }
        return changed;
    }

    private static String groupName(String displayName, String externalKey) {
        try {
            return OwnershipNames.display(displayName == null || displayName.isBlank() ? externalKey : displayName);
        } catch (IllegalArgumentException unusable) {
            return OwnershipNames.display(externalKey);
        }
    }

    /**
     * An admin's answer to an AMBIGUOUS identity: link it to {@code userId}, or create a new person named
     * {@code newPersonDisplayName} for it. The new person keeps the identity's email even though another person shares
     * it; that shared email is why the identity was ambiguous. Closes the open review item.
     */
    @Transactional
    public IdentityResolution resolveAmbiguousIdentity(UUID identityId, UUID userId, String newPersonDisplayName, String actor) {
        UUID tenant = requireReady();
        boolean createNew = newPersonDisplayName != null && !newPersonDisplayName.isBlank();
        if ((userId == null) == !createNew) throw bad("Choose an existing person or name a new person, not both");
        List<Object[]> rows = jdbc.query("SELECT source_id, link_status, email_enc FROM external_identity WHERE id = ? FOR UPDATE",
                (rs, n) -> new Object[] {rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3)}, identityId);
        if (rows.isEmpty()) throw notFound("External identity not found");
        UUID sourceId = (UUID) rows.get(0)[0];
        if (!"AMBIGUOUS".equals(rows.get(0)[1])) throw conflict("Only an ambiguous identity can be resolved");
        UUID target;
        if (createNew) {
            String email = decryptOrNull(tenant, P_EMAIL, (String) rows.get(0)[2]);
            target = insertUser(tenant, newPersonDisplayName, email, null, null, sourceId, actor).id();
        } else {
            if ("DELETED".equals(requireUser(userId).status())) throw bad("A deleted person cannot be linked");
            target = userId;
        }
        linkIdentity(identityId, target);
        reviews.closeOpen(ambiguousKey(identityId), "RESOLVED", null, actor);
        audit.record("ownership.external_identity.resolved", "external_identity", identityId.toString(),
                OwnershipEvents.json(Map.of("userId", target, "sourceId", sourceId, "createdPerson", createNew)));
        return new IdentityResolution(identityId, target, createNew);
    }

    private void linkIdentity(UUID identityId, UUID userId) {
        jdbc.update("UPDATE external_identity SET user_id = ?, link_status = 'LINKED', updated_at = now() WHERE id = ?", userId, identityId);
    }

    private List<Candidate> candidates(byte[] emailIndex) {
        return jdbc.query("SELECT id, status FROM directory_user WHERE email_index = ? AND status <> 'DELETED' ORDER BY created_at, id LIMIT ?",
                (rs, n) -> new Candidate(rs.getObject(1, UUID.class), rs.getString(2)), emailIndex, MAX_CANDIDATES);
    }

    private static String ambiguityReason(List<Candidate> candidates) {
        if (candidates.isEmpty()) return "NO_CURRENT_MATCH";
        return candidates.stream().anyMatch(c -> "ACTIVE".equals(c.status())) ? "MULTIPLE_MATCHES" : "ONLY_INACTIVE_MATCH";
    }

    /** Review details carry IDs and codes only, never names or emails. */
    private void raiseAmbiguous(String dedupeKey, UUID identityId, UUID sourceId, String reason, List<UUID> candidateIds, UUID linkedUserId) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("identityId", identityId.toString());
        details.put("sourceId", sourceId.toString());
        details.put("reason", reason);
        details.put("candidateCount", candidateIds.size());
        details.put("candidateUserIds", candidateIds.stream().limit(MAX_CANDIDATES_IN_REVIEW).map(UUID::toString).toList());
        if (linkedUserId != null) details.put("linkedUserId", linkedUserId.toString());
        String kind = jdbc.queryForList("SELECT kind FROM identity_source WHERE id = ?", String.class, sourceId).stream().findFirst().orElse(null);
        reviews.raise(REVIEW_AMBIGUOUS, dedupeKey, null, kind, details);
    }

    static String ambiguousKey(UUID identityId) {
        return "AMBIGUOUS_IDENTITY|identity|" + identityId;
    }

    static String driftKey(UUID identityId) {
        return "AMBIGUOUS_IDENTITY|drift|" + identityId;
    }

    /** The name for a person created by rule 4: display name, then user name, then email, then the external id. */
    private static String personName(ObservedIdentity observed, String externalKey) {
        for (String candidate : new String[] {observed.displayName(), observed.username(), observed.email()}) {
            if (candidate != null && !candidate.isBlank()) return candidate;
        }
        return externalKey;
    }

    private static String sourceEmail(String email) {
        try {
            return normalizeEmail(email);
        } catch (ResponseStatusException ex) {
            return null;
        }
    }

    private void advisoryLock(String key) {
        jdbc.query("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", rs -> null, key);
    }

    // ----- helpers --------------------------------------------------------------------------------------------

    private byte[] externalIndex(String externalId) {
        return cipher.blindIndex(TenantContext.getCurrentTenantId(), P_EXTERNAL_ID, externalKey(externalId));
    }

    /** External IDs are opaque and case-sensitive; only surrounding whitespace is trimmed. */
    static String externalKey(String externalId) {
        if (externalId == null || externalId.isBlank()) throw bad("An external id is required");
        String key = externalId.strip();
        if (key.length() > 512) throw bad("External ids are limited to 512 characters");
        return key;
    }

    private void writeSearchTokens(UUID tenant, String kind, UUID id, String name) {
        jdbc.update("DELETE FROM directory_search_token WHERE entity_kind = ? AND entity_id = ?", kind, id);
        Set<String> prefixes = new LinkedHashSet<>();
        for (String word : words(name)) {
            for (int n = MIN_PREFIX; n <= Math.min(word.length(), MAX_PREFIX); n++) prefixes.add(word.substring(0, n));
        }
        for (String prefix : prefixes) {
            jdbc.update("INSERT INTO directory_search_token (tenant_id, entity_kind, entity_id, token) VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?) ON CONFLICT DO NOTHING",
                    kind, id, cipher.blindIndex(tenant, P_SEARCH, prefix));
        }
    }

    static List<String> words(String value) {
        if (value == null) return List.of();
        String folded = Normalizer.normalize(value, Normalizer.Form.NFKD).replaceAll("\\p{M}", "").toLowerCase(Locale.ROOT);
        return java.util.Arrays.stream(WORD_SPLIT.split(folded)).filter(w -> !w.isEmpty()).toList();
    }

    private boolean managesTransitively(UUID userId, UUID newManager) {
        UUID cursor = newManager;
        for (int depth = 0; cursor != null && depth < 64; depth++) {
            if (cursor.equals(userId)) return true;
            List<UUID> next = jdbc.queryForList("SELECT manager_user_id FROM directory_user WHERE id = ?", UUID.class, cursor);
            cursor = next.isEmpty() ? null : next.get(0); // the list holds a null when the person has no manager
        }
        return cursor != null;
    }

    private DirectoryUser requireUser(UUID id) {
        return user(id).orElseThrow(() -> notFound("Person not found"));
    }

    private UUID requireReady() {
        UUID tenant = TenantContext.getCurrentTenantId();
        if (tenant == null) throw new IllegalStateException("Directory writes require a tenant context");
        TenantKeyRegistry.Readiness readiness = cipher.readiness(tenant);
        if (!readiness.ready()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Tenant encryption is not ready (" + readiness.reason() + ")");
        }
        return tenant;
    }

    private String decryptOrNull(UUID tenant, String purpose, String value) {
        return value == null ? null : cipher.decrypt(tenant, purpose, value);
    }

    private static String displayName(String value) {
        try {
            return OwnershipNames.display(value);
        } catch (IllegalArgumentException ex) {
            throw bad(ex.getMessage());
        }
    }

    static String normalizeEmail(String email) {
        if (email == null || email.isBlank()) return null;
        String normalized = email.strip().toLowerCase(Locale.ROOT);
        if (!EMAIL.matcher(normalized).matches()) throw bad("Invalid email address");
        return normalized;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private static ResponseStatusException conflict(String message) {
        return new ResponseStatusException(HttpStatus.CONFLICT, message);
    }

    private static ResponseStatusException notFound(String message) {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, message);
    }
}
