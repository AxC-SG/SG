package com.prototype.vulnwatch.service.ownership;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Connection;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.DirectoryTable;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.ServiceNowDirectoryException;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.TableProbe;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.TableSample;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import java.net.URI;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * Configures ServiceNow identity sources (Phase 0B contract §1.1–§1.2): validation, encryption,
 * connection tests, lifecycle rules and audit. The rows are written by {@link DirectoryService},
 * the single writer of {@code identity_source} (plan §7.6).
 *
 * <p>Credentials are encrypted with the tenant key and never returned. The instance URL is checked
 * against the outbound host policy at save and again by the client on every request. A new source
 * starts {@code DISABLED} and is enabled only with a token from a preview of its current scope.
 * Configuring, testing, previewing, enabling and resuming need {@code app.ownership.servicenow.directory-enabled}; pausing and
 * disabling always work, so a source can be stopped after the switch is turned off.
 */
@Service
public class IdentitySourceService {

    public static final String KIND = "SERVICENOW";
    public static final Duration DEFAULT_SCHEDULE = Duration.ofHours(24);
    static final String P_CREDENTIALS = "identity_source.credentials";
    private static final int MAX_REASON = 500;

    /** What an admin submits. A null secret keeps the stored one, unless the URL, auth type or username changes. */
    public record ServiceNowSourceRequest(String displayName, String instanceUrl, String authType, String username,
                                          String secret, Map<String, String> filters, String schedule, Long version) { }

    /** A source as the API shows it. Credentials are reported only as present or absent. */
    public record SourceView(UUID id, String kind, String displayName, String instanceUrl, String authType,
                             boolean hasCredentials, Map<String, String> filters, String schedule, String state,
                             String health, Instant lastSuccessAt, String lastError, long version) { }

    public record TableCheck(String table, String outcome, Long rowCount) { }

    /** {@code failure} is a {@link ServiceNowDirectoryClient.FailureKind} name when the test could not finish. */
    public record ConnectionTest(boolean succeeded, String failure, String message, List<TableCheck> tables) { }

    /** One table in a preview: its row count and up to {@value #SAMPLE_ROWS} rows with full values. */
    public record TablePreview(String table, String outcome, Long rowCount, List<Map<String, String>> samples) { }

    /**
     * A preview. Sample values are full names and emails (§1.6 decision) and exist only in this response; the token is
     * null unless every table could be read.
     */
    public record Preview(boolean succeeded, String failure, String message, List<TablePreview> tables, String previewToken,
                          Instant expiresAt) { }

    static final int SAMPLE_ROWS = 10;
    static final String P_PREVIEW_TOKEN = "identity_source.preview_token";

    private record Credentials(String username, String secret) { }

    private record Row(UUID id, String kind, String displayName, String credentialsEnc, Map<String, Object> scope,
                       String schedule, String state, String health, Instant lastSuccessAt, String lastError, long version) { }

    private final JdbcTemplate jdbc;
    private final DirectoryService directory;
    private final TenantDataCipher cipher;
    private final AuditEventService audit;
    private final OutboundHostPolicy hostPolicy;
    private final ServiceNowDirectoryClient client;
    private final OwnershipClaimService claims;
    private final ObjectMapper json;
    private final boolean enabled;

    public IdentitySourceService(JdbcTemplate jdbc, DirectoryService directory, TenantDataCipher cipher, AuditEventService audit, OutboundHostPolicy hostPolicy,
                                 ServiceNowDirectoryClient client, OwnershipClaimService claims, ObjectMapper json,
                                 @Value("${app.ownership.servicenow.directory-enabled:false}") boolean enabled) {
        this.jdbc = jdbc;
        this.directory = directory;
        this.cipher = cipher;
        this.audit = audit;
        this.hostPolicy = hostPolicy;
        this.client = client;
        this.claims = claims;
        this.json = json;
        this.enabled = enabled;
    }

    // ----- reads ----------------------------------------------------------------------------------------------

    @Transactional(readOnly = true)
    public List<SourceView> list() {
        return jdbc.query(SELECT + " ORDER BY created_at", this::row).stream().map(IdentitySourceService::view).toList();
    }

    @Transactional(readOnly = true)
    public Optional<SourceView> get(UUID id) {
        return find(id).map(IdentitySourceService::view);
    }

    // ----- configuration --------------------------------------------------------------------------------------

    @Transactional
    public SourceView create(ServiceNowSourceRequest req, String actor) {
        requireEnabled();
        UUID tenant = requireReady();
        String name = displayName(req.displayName());
        String url = instanceUrl(req.instanceUrl());
        ServiceNowAuthType authType = authType(req.authType());
        Credentials credentials = credentials(authType, req.username(), req.secret());
        Map<String, Object> scope = scope(url, authType, filters(req.filters()));
        String schedule = schedule(req.schedule());
        UUID id = directory.createProviderSource(KIND, name, encrypt(tenant, credentials), write(scope), schedule, actor);
        audit.record("ownership.identity_source.created", "identity_source", id.toString(),
                OwnershipEvents.json(Map.of("kind", KIND, "authType", authType.name())));
        return get(id).orElseThrow();
    }

    /**
     * Replaces the configuration. Changing the URL, auth type or username needs the secret again, so stored
     * credentials are never sent to a host or account the admin did not pair them with. Changing the URL or a
     * filter returns an enabled or paused source to DISABLED, because enabling needs a preview of the current scope.
     */
    @Transactional
    public SourceView update(UUID id, ServiceNowSourceRequest req, String actor) {
        requireEnabled();
        UUID tenant = requireReady();
        if (req.version() == null) throw bad("version is required");
        Row current = requireServiceNow(id);
        String name = displayName(req.displayName());
        String url = instanceUrl(req.instanceUrl());
        ServiceNowAuthType authType = authType(req.authType());
        Map<String, String> filters = filters(req.filters());
        String schedule = schedule(req.schedule());

        Credentials stored = decrypt(tenant, current.credentialsEnc());
        boolean pairingChanged = !url.equals(current.scope().get("instanceUrl"))
                || !authType.name().equals(current.scope().get("authType"))
                || (authType == ServiceNowAuthType.BASIC && !Objects.equals(blankToNull(req.username()), stored.username()));
        boolean secretGiven = req.secret() != null && !req.secret().isBlank();
        if (pairingChanged && !secretGiven) {
            throw bad("Enter the password or token again when changing the instance URL, auth type or username");
        }
        Credentials credentials = secretGiven ? credentials(authType, req.username(), req.secret()) : stored;
        Map<String, Object> scope = scope(url, authType, filters);
        boolean scopeChanged = !url.equals(current.scope().get("instanceUrl")) || !filters.equals(storedFilters(current.scope()));
        String state = scopeChanged && !"DISABLED".equals(current.state()) ? "DISABLED" : current.state();

        boolean changed = directory.updateProviderSource(id, KIND, name,
                secretGiven ? encrypt(tenant, credentials) : current.credentialsEnc(), write(scope), schedule, state, req.version());
        if (!changed) throw conflict("The source changed since it was loaded; reload and try again");
        audit.record("ownership.identity_source.updated", "identity_source", id.toString(), OwnershipEvents.json(Map.of(
                "scopeChanged", scopeChanged, "credentialsChanged", secretGiven,
                "scheduleChanged", !schedule.equals(current.schedule()), "state", state)));
        return get(id).orElseThrow();
    }

    /**
     * Reads one row from each directory table with the stored credentials. A denied table is reported, not thrown;
     * rejected credentials, a rejected host or an unreachable instance end the test with that failure. Writes
     * nothing except an audit event without row values. Deliberately not transactional: no transaction is held open
     * across the HTTP calls.
     */
    public ConnectionTest testConnection(UUID id, String actor) {
        requireEnabled();
        requireNotKilled();
        UUID tenant = requireReady();
        Row source = requireServiceNow(id);
        Connection connection = connection(tenant, source);
        Map<String, String> filters = storedFilters(source.scope());
        List<TableCheck> checks = new ArrayList<>();
        ConnectionTest result;
        try {
            for (DirectoryTable table : DirectoryTable.values()) {
                TableProbe probe = client.probe(connection, table, filters.get(table.tableName()));
                checks.add(new TableCheck(table.tableName(), probe.outcome().name(), probe.totalCount()));
            }
            boolean allReadable = checks.stream().allMatch(c -> "READABLE".equals(c.outcome()));
            result = new ConnectionTest(allReadable, allReadable ? null : "PERMISSION_DENIED",
                    allReadable ? "The integration account can read every directory table"
                            : "The integration account cannot read every directory table", List.copyOf(checks));
        } catch (ServiceNowDirectoryException error) {
            result = new ConnectionTest(false, error.kind().name(), error.getMessage(), List.copyOf(checks));
        }
        audit.record("ownership.identity_source.connection_tested", "identity_source", id.toString(), OwnershipEvents.json(Map.of(
                "succeeded", result.succeeded(), "failure", result.failure() == null ? "" : result.failure())),
                result.succeeded() ? "SUCCESS" : "FAILURE");
        return result;
    }

    /**
     * Fetches counts and up to {@value #SAMPLE_ROWS} rows per table and returns a token for {@link #enable}. Writes
     * nothing; the audit event records the actor, the source and the number of sample rows, never their values. Not
     * transactional, so no transaction is held across the HTTP calls.
     */
    public Preview preview(UUID id, String actor) {
        requireEnabled();
        requireNotKilled();
        UUID tenant = requireReady();
        Row source = requireServiceNow(id);
        Connection connection = connection(tenant, source);
        Map<String, String> filters = storedFilters(source.scope());
        List<TablePreview> tables = new ArrayList<>();
        Preview result;
        try {
            for (DirectoryTable table : DirectoryTable.values()) {
                TableSample sample = client.sample(connection, table, filters.get(table.tableName()), SAMPLE_ROWS);
                tables.add(new TablePreview(table.tableName(), sample.outcome().name(), sample.totalCount(), sample.rows()));
            }
            if (tables.stream().allMatch(t -> "READABLE".equals(t.outcome()))) {
                Instant expiresAt = Instant.now().plus(IdentitySourcePreviewToken.TTL);
                String token = IdentitySourcePreviewToken.issue(mac(tenant), id, source.version(), scopeHash(source), actor, expiresAt);
                result = new Preview(true, null, "Preview complete", List.copyOf(tables), token, expiresAt);
            } else {
                result = new Preview(false, "PERMISSION_DENIED", "The integration account cannot read every directory table",
                        List.copyOf(tables), null, null);
            }
        } catch (ServiceNowDirectoryException error) {
            result = new Preview(false, error.kind().name(), error.getMessage(), List.copyOf(tables), null, null);
        }
        int sampleRows = result.tables().stream().mapToInt(t -> t.samples().size()).sum();
        audit.record("ownership.identity_source.previewed", "identity_source", id.toString(), OwnershipEvents.json(Map.of(
                "sampleRows", sampleRows, "succeeded", result.succeeded(), "failure", result.failure() == null ? "" : result.failure())),
                result.succeeded() ? "SUCCESS" : "FAILURE");
        return result;
    }

    /**
     * Enables a disabled source. Needs a preview token issued to this actor for the source's current version and
     * scope; any update since the preview, including a credential rotation, invalidates it, and enabling itself
     * bumps the version, so a token enables at most once. The first complete run after this is the baseline load.
     */
    @Transactional
    public SourceView enable(UUID id, String previewToken, String actor) {
        requireEnabled();
        requireNotKilled();
        UUID tenant = requireReady();
        Row source = requireServiceNow(id);
        if (!"DISABLED".equals(source.state())) throw conflict("Only a disabled source can be enabled");
        if (!IdentitySourcePreviewToken.valid(mac(tenant), previewToken, id, source.version(), scopeHash(source), actor, Instant.now())) {
            throw conflict("Preview the source again before enabling it: the preview is missing, expired or out of date");
        }
        if (!directory.setProviderSourceState(id, KIND, List.of("DISABLED"), "ENABLED", source.version())) {
            throw conflict("The source changed since it was previewed; preview it again");
        }
        audit.record("ownership.identity_source.enabled", "identity_source", id.toString(), OwnershipEvents.json(Map.of()));
        return get(id).orElseThrow();
    }

    private Function<String, byte[]> mac(UUID tenant) {
        return payload -> cipher.blindIndex(tenant, P_PREVIEW_TOKEN, payload);
    }

    private String scopeHash(Row source) {
        return IdentitySourcePreviewToken.scopeHash(write(source.scope()));
    }

    // ----- lifecycle ------------------------------------------------------------------------------------------

    /** Pauses an enabled or failing source (PAUSE_SOURCE). Works with the feature switch off. */
    @Transactional
    public SourceView pause(UUID id, String reason, String actor) {
        String note = reason == null || reason.isBlank() ? null : reason.strip();
        if (note != null && note.length() > MAX_REASON) throw bad("The reason is limited to " + MAX_REASON + " characters");
        transition(id, List.of("ENABLED", "ERROR"), "PAUSED", "Only an enabled or failing source can be paused");
        audit.record("ownership.identity_source.paused", "identity_source", id.toString(),
                OwnershipEvents.json(Map.of("hasReason", note != null)));
        return get(id).orElseThrow();
    }

    /** Resumes a paused source, which is also how an admin approves a run held by an anomaly pause. */
    @Transactional
    public SourceView resume(UUID id, String actor) {
        requireEnabled();
        requireNotKilled();
        requireReady();
        transition(id, List.of("PAUSED"), "ENABLED", "Only a paused source can be resumed");
        audit.record("ownership.identity_source.resumed", "identity_source", id.toString(), OwnershipEvents.json(Map.of()));
        return get(id).orElseThrow();
    }

    /** Turns a source off. Works with the feature switch off. Re-enabling needs a new preview. */
    @Transactional
    public SourceView disable(UUID id, String actor) {
        transition(id, List.of("ENABLED", "PAUSED", "ERROR"), "DISABLED", "The source is already disabled");
        audit.record("ownership.identity_source.disabled", "identity_source", id.toString(), OwnershipEvents.json(Map.of()));
        return get(id).orElseThrow();
    }

    private void transition(UUID id, List<String> from, String to, String refusal) {
        requireServiceNow(id);
        if (!directory.setProviderSourceState(id, KIND, from, to)) throw conflict(refusal);
    }

    // ----- helpers --------------------------------------------------------------------------------------------

    private static final String SELECT = """
            SELECT id, kind, display_name, credentials_enc, scope_config::text, schedule, state, health, last_success_at,
                   last_error, version FROM identity_source""";

    private Optional<Row> find(UUID id) {
        return jdbc.query(SELECT + " WHERE id = ?", this::row, id).stream().findFirst();
    }

    private Row requireServiceNow(UUID id) {
        Row row = find(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Identity source not found"));
        if (!KIND.equals(row.kind())) throw conflict("Only ServiceNow sources are configured here");
        return row;
    }

    private Row row(ResultSet rs, int n) throws SQLException {
        Timestamp lastSuccess = rs.getTimestamp(9);
        return new Row(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4), read(rs.getString(5)),
                rs.getString(6), rs.getString(7), rs.getString(8), lastSuccess == null ? null : lastSuccess.toInstant(),
                rs.getString(10), rs.getLong(11));
    }

    private static SourceView view(Row row) {
        Object url = row.scope().get("instanceUrl");
        Object authType = row.scope().get("authType");
        return new SourceView(row.id(), row.kind(), row.displayName(), url == null ? null : url.toString(),
                authType == null ? null : authType.toString(), row.credentialsEnc() != null, storedFilters(row.scope()),
                row.schedule(), row.state(), row.health(), row.lastSuccessAt(), row.lastError(), row.version());
    }

    /** The scope as stored: instance, auth type, the three contract tables with their fields and filters. */
    private static Map<String, Object> scope(String url, ServiceNowAuthType authType, Map<String, String> filters) {
        Map<String, Object> tables = new LinkedHashMap<>();
        for (DirectoryTable table : DirectoryTable.values()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("fields", table.fields());
            entry.put("filter", filters.get(table.tableName()));
            tables.put(table.tableName(), entry);
        }
        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("instanceUrl", url);
        scope.put("authType", authType.name());
        scope.put("tables", tables);
        return scope;
    }

    static Map<String, String> storedFilters(Map<String, Object> scope) {
        Map<String, String> filters = new LinkedHashMap<>();
        if (!(scope.get("tables") instanceof Map<?, ?> tables)) return filters;
        for (DirectoryTable table : DirectoryTable.values()) {
            if (tables.get(table.tableName()) instanceof Map<?, ?> entry && entry.get("filter") instanceof String filter) {
                filters.put(table.tableName(), filter);
            }
        }
        return filters;
    }

    /** Validates per-table filters; keys must be one of the three contract tables. Blank filters are dropped. */
    static Map<String, String> filters(Map<String, String> requested) {
        Map<String, String> filters = new LinkedHashMap<>();
        if (requested == null) return filters;
        List<String> known = java.util.Arrays.stream(DirectoryTable.values()).map(DirectoryTable::tableName).toList();
        for (Map.Entry<String, String> entry : requested.entrySet()) {
            if (!known.contains(entry.getKey())) throw bad("Filters are allowed only for sys_user, sys_user_group and sys_user_grmember");
            try {
                String filter = ServiceNowDirectoryClient.validateFilter(entry.getValue());
                if (filter != null) filters.put(entry.getKey(), filter);
            } catch (IllegalArgumentException invalid) {
                throw bad(invalid.getMessage());
            }
        }
        return filters;
    }

    private String instanceUrl(String value) {
        if (value == null || value.isBlank()) throw bad("The ServiceNow instance URL is required");
        URI uri;
        try {
            uri = URI.create(value.strip());
        } catch (IllegalArgumentException malformed) {
            throw bad("The ServiceNow instance URL is not a valid URL");
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null || (uri.getRawPath() != null && !uri.getRawPath().isEmpty()
                && !"/".equals(uri.getRawPath()))) {
            throw bad("Enter only the instance address, for example https://acme.service-now.com");
        }
        try {
            hostPolicy.validate(ServiceNowDirectoryClient.PROVIDER_KEY, uri);
        } catch (IllegalArgumentException rejected) {
            throw bad("The ServiceNow instance URL is not an approved public HTTPS endpoint");
        }
        return "https://" + uri.getHost().toLowerCase(Locale.ROOT);
    }

    private static ServiceNowAuthType authType(String value) {
        if (value == null || value.isBlank()) return ServiceNowAuthType.BASIC;
        try {
            return ServiceNowAuthType.valueOf(value.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            throw bad("Auth type must be BASIC or BEARER");
        }
    }

    private static Credentials credentials(ServiceNowAuthType authType, String username, String secret) {
        if (secret == null || secret.isBlank()) throw bad("The integration account password or token is required");
        String user = blankToNull(username);
        if (authType == ServiceNowAuthType.BASIC && user == null) throw bad("The integration account username is required");
        if (user != null && user.length() > 255) throw bad("The username is limited to 255 characters");
        if (secret.length() > 4_096) throw bad("The password or token is limited to 4,096 characters");
        return new Credentials(authType == ServiceNowAuthType.BASIC ? user : null, secret.strip());
    }

    private static String schedule(String value) {
        if (value == null || value.isBlank()) return DEFAULT_SCHEDULE.toString();
        try {
            return OwnershipSourcePolicy.requireValidInterval(Duration.parse(value.strip())).toString();
        } catch (DateTimeParseException | IllegalArgumentException invalid) {
            throw bad("The schedule must be an ISO-8601 duration between PT15M and P7D");
        }
    }

    private static String displayName(String value) {
        try {
            return OwnershipNames.display(value);
        } catch (IllegalArgumentException ex) {
            throw bad(ex.getMessage());
        }
    }

    /** Decrypted connection details for the client. */
    private Connection connection(UUID tenant, Row source) {
        Credentials credentials = decrypt(tenant, source.credentialsEnc());
        return new Connection(String.valueOf(source.scope().get("instanceUrl")),
                ServiceNowAuthType.valueOf(String.valueOf(source.scope().get("authType"))), credentials.username(), credentials.secret());
    }

    private String encrypt(UUID tenant, Credentials credentials) {
        Map<String, String> plain = new LinkedHashMap<>();
        if (credentials.username() != null) plain.put("username", credentials.username());
        plain.put("secret", credentials.secret());
        return cipher.encrypt(tenant, P_CREDENTIALS, write(plain));
    }

    private Credentials decrypt(UUID tenant, String credentialsEnc) {
        if (credentialsEnc == null) throw conflict("The source has no stored credentials");
        try {
            Map<String, String> plain = json.readValue(cipher.decrypt(tenant, P_CREDENTIALS, credentialsEnc), new TypeReference<>() { });
            return new Credentials(plain.get("username"), plain.get("secret"));
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("Stored identity-source credentials are unreadable");
        }
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private Map<String, Object> read(String value) {
        try {
            return value == null ? Map.of() : json.readValue(value, new TypeReference<>() { });
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("identity_source.scope_config is not valid JSON");
        }
    }

    private void requireEnabled() {
        if (!enabled) throw conflict("ServiceNow directory sync is not enabled in this environment");
    }

    private void requireNotKilled() {
        if (claims.sourcePaused(KIND)) throw conflict("ServiceNow sources are paused by the platform kill switch");
    }

    private UUID requireReady() {
        UUID tenant = TenantContext.getCurrentTenantId();
        if (tenant == null) throw new IllegalStateException("Identity sources require a tenant context");
        TenantKeyRegistry.Readiness readiness = cipher.readiness(tenant);
        if (!readiness.ready()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Tenant encryption is not ready (" + readiness.reason() + ")");
        }
        return tenant;
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
}
