package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureContext;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Reads the ServiceNow directory tables ({@code sys_user}, {@code sys_user_group},
 * {@code sys_user_grmember}) for the identity-source sync (Phase 0B contract §1.2 and §1.5).
 *
 * <p>Pages are keyset-ordered by {@code (sys_updated_on, sys_id)}, never by offset, so rows that
 * change mid-run are neither skipped nor repeated. Only the contract's field list is requested and
 * kept. Every call goes through {@link OutboundHttpClient} with the {@value #PROVIDER_KEY}
 * provider policy, which re-checks the host on every request. The client holds no state and writes
 * nothing; response bodies are never put into exception messages or logs, because they hold PII.
 */
@Component
public class ServiceNowDirectoryClient {

    public static final String PROVIDER_KEY = "servicenow";
    public static final int DEFAULT_PAGE_SIZE = 500;
    static final List<Integer> PAGE_SIZE_LADDER = List.of(500, 250, 100, 25);
    static final int MAX_FILTER_LENGTH = 2_000;

    private static final Logger LOG = LoggerFactory.getLogger(ServiceNowDirectoryClient.class);
    private static final Pattern SYS_ID = Pattern.compile("(?i)[0-9a-f]{32}");
    private static final Pattern UPDATED_ON = Pattern.compile("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}");
    private static final Pattern FORBIDDEN_FILTER = Pattern.compile("(?i)ORDERBY|\\^NQ|sysparm_");

    private final OutboundHttpClient http;
    private final OutboundPolicyFactory policies;
    private final ObjectMapper objectMapper;

    public ServiceNowDirectoryClient(OutboundHttpClient http, OutboundPolicyFactory policies, ObjectMapper objectMapper) {
        this.http = http;
        this.policies = policies;
        this.objectMapper = objectMapper;
    }

    // ── Contract types ─────────────────────────────────────────────────────────────────────────

    /** The three approved tables and their exact field lists (contract §1.2). */
    public enum DirectoryTable {
        USERS("sys_user", List.of("sys_id", "user_name", "email", "first_name", "last_name", "name", "active",
                "locked_out", "employee_number", "manager", "department", "sys_updated_on")),
        GROUPS("sys_user_group", List.of("sys_id", "name", "active", "manager", "parent", "sys_updated_on")),
        MEMBERSHIPS("sys_user_grmember", List.of("sys_id", "user", "group", "sys_updated_on"));

        private final String tableName;
        private final List<String> fields;

        DirectoryTable(String tableName, List<String> fields) {
            this.tableName = tableName;
            this.fields = fields;
        }

        public String tableName() {
            return tableName;
        }

        public List<String> fields() {
            return fields;
        }
    }

    /** Where and how to connect. The secret never appears in {@link #toString()}. */
    public record Connection(String baseUrl, ServiceNowAuthType authType, String username, String secret) {
        @Override
        public String toString() {
            return "Connection[baseUrl=" + baseUrl + ", authType=" + authType + "]";
        }
    }

    /** The last {@code (sys_updated_on, sys_id)} pair read from a table; {@code null} means from the start. */
    public record Cursor(String updatedOn, String sysId) {
        public Cursor {
            if (updatedOn == null || !UPDATED_ON.matcher(updatedOn).matches()) {
                throw new IllegalArgumentException("Cursor updatedOn must be yyyy-MM-dd HH:mm:ss");
            }
            if (sysId == null || !SYS_ID.matcher(sysId).matches()) {
                throw new IllegalArgumentException("Cursor sysId must be a 32-character hex sys_id");
            }
            sysId = sysId.toLowerCase(Locale.ROOT);
        }

        boolean isAfter(Cursor other) {
            if (other == null) {
                return true;
            }
            int byTime = updatedOn.compareTo(other.updatedOn);
            return byTime > 0 || (byTime == 0 && sysId.compareTo(other.sysId) > 0);
        }
    }

    /**
     * One keyset page. {@code next} is the cursor after the page's last row (unchanged when the page
     * is empty); {@code last} is true when the table has no further rows. {@code pageSize} is the
     * size that succeeded, so the caller keeps using a reduced size once the ladder has stepped down.
     */
    public record Page(List<Map<String, String>> rows, Cursor next, boolean last, int pageSize) {}

    public enum ProbeOutcome { READABLE, DENIED }

    /** The connection test's view of one table: whether it can be read and, if so, how many rows match. */
    public record TableProbe(DirectoryTable table, ProbeOutcome outcome, Long totalCount) {}

    public enum FailureKind {
        /** 401: the credentials were rejected. */
        AUTHENTICATION_FAILED,
        /** 403: the integration account lacks read access to this table. */
        PERMISSION_DENIED,
        /** 429 after the bounded retries, or a Retry-After longer than the policy allows. */
        RATE_LIMITED,
        /** The host is not allow-listed, not HTTPS or resolves to a blocked address. */
        HOST_REJECTED,
        /** Network failure or 5xx after the bounded retries. */
        UNAVAILABLE,
        /** Not JSON, no {@code result} array, a row without a valid key, or a cursor that did not advance. */
        INVALID_RESPONSE
    }

    /** A failure with a message that is safe to show an admin: it never includes response content. */
    public static class ServiceNowDirectoryException extends RuntimeException {
        private final FailureKind kind;
        private final Integer status;
        private final transient boolean ladderEligible;

        public ServiceNowDirectoryException(FailureKind kind, Integer status, String message) {
            this(kind, status, message, false);
        }

        ServiceNowDirectoryException(FailureKind kind, Integer status, String message, boolean ladderEligible) {
            super(message);
            this.kind = kind;
            this.status = status;
            this.ladderEligible = ladderEligible;
        }

        public FailureKind kind() {
            return kind;
        }

        public Integer status() {
            return status;
        }
    }

    // ── Query rules ────────────────────────────────────────────────────────────────────────────

    /**
     * Validates an admin encoded-query filter (contract §1.2): at most 2,000 characters, no
     * {@code ORDERBY}, {@code ^NQ} or {@code sysparm_} fragments, and no leading {@code ^} or
     * {@code OR}, which would change how it combines with the system clauses. Returns the trimmed
     * filter, or {@code null} when blank.
     */
    public static String validateFilter(String filter) {
        if (filter == null || filter.isBlank()) {
            return null;
        }
        String trimmed = filter.trim();
        if (trimmed.length() > MAX_FILTER_LENGTH) {
            throw new IllegalArgumentException("ServiceNow filter must be at most " + MAX_FILTER_LENGTH + " characters");
        }
        if (FORBIDDEN_FILTER.matcher(trimmed).find()) {
            throw new IllegalArgumentException("ServiceNow filter must not contain ORDERBY, ^NQ or sysparm_");
        }
        if (trimmed.startsWith("^") || trimmed.regionMatches(true, 0, "OR", 0, 2) || trimmed.endsWith("^")) {
            throw new IllegalArgumentException("ServiceNow filter must not start or end with a condition separator");
        }
        return trimmed;
    }

    /**
     * Builds the keyset query: the admin filter AND rows strictly after {@code after} in
     * {@code (sys_updated_on, sys_id)} order.
     *
     * <p>In ServiceNow encoded queries {@code ^OR} binds tighter than {@code ^}, so the contract's
     * literal {@code sys_updated_on>T^ORsys_updated_on=T^sys_id>ID} reads as
     * {@code (updated>T OR updated=T) AND sys_id>ID} and would drop later rows with a smaller
     * sys_id. The equivalent form used here is
     * {@code updated>=T AND (updated>T OR sys_id>ID)}, which needs no {@code ^NQ} and lets the
     * admin filter be ANDed with a plain {@code ^}.
     */
    static String keysetQuery(String filter, Cursor after) {
        StringBuilder query = new StringBuilder();
        String validated = validateFilter(filter);
        if (validated != null) {
            query.append(validated).append('^');
        }
        if (after != null) {
            query.append("sys_updated_on>=").append(after.updatedOn())
                    .append("^sys_updated_on>").append(after.updatedOn())
                    .append("^ORsys_id>").append(after.sysId())
                    .append('^');
        }
        query.append("ORDERBYsys_updated_on^ORDERBYsys_id");
        return query.toString();
    }

    // ── Calls ──────────────────────────────────────────────────────────────────────────────────

    /**
     * Reads one row of {@code table} to check read access and returns the matching row count from
     * {@code X-Total-Count}. A 403 is reported as {@link ProbeOutcome#DENIED}; every other failure
     * (including 401) is thrown, because it is not specific to this table.
     */
    public TableProbe probe(Connection connection, DirectoryTable table, String filter) {
        String query = validateFilter(filter);
        try {
            ResponseEntity<String> response = get(connection, table, query, 1, "ServiceNow directory probe");
            readResult(response, table);
            return new TableProbe(table, ProbeOutcome.READABLE, totalCount(response));
        } catch (ServiceNowDirectoryException error) {
            if (error.kind() == FailureKind.PERMISSION_DENIED) {
                return new TableProbe(table, ProbeOutcome.DENIED, null);
            }
            throw error;
        }
    }

    /**
     * Fetches the next keyset page of {@code table} after {@code after}, starting at
     * {@code pageSize} and stepping down the 500/250/100/25 ladder on timeouts or malformed
     * responses. Rows contain only the table's contract fields.
     */
    public Page fetchPage(Connection connection, DirectoryTable table, String filter, Cursor after, int pageSize) {
        String query = keysetQuery(filter, after);
        List<Integer> sizes = PAGE_SIZE_LADDER.stream().filter(size -> size <= Math.max(pageSize, 25)).toList();
        for (int index = 0; index < sizes.size(); index++) {
            int size = sizes.get(index);
            try {
                return fetchPageWithSize(connection, table, query, after, size);
            } catch (ServiceNowDirectoryException error) {
                boolean hasFallback = index + 1 < sizes.size();
                if (!hasFallback || !error.ladderEligible) {
                    throw error;
                }
                LOG.warn("ServiceNow directory table {} failed at page size {} ({}); retrying at {}",
                        table.tableName(), size, error.kind(), sizes.get(index + 1));
            }
        }
        throw new IllegalStateException("ServiceNow directory page-size ladder exhausted");
    }

    private Page fetchPageWithSize(Connection connection, DirectoryTable table, String query, Cursor after, int size) {
        ResponseEntity<String> response = get(connection, table, query, size, "ServiceNow directory page");
        JsonNode result = readResult(response, table);
        List<Map<String, String>> rows = new ArrayList<>(result.size());
        Cursor next = after;
        for (JsonNode node : result) {
            Map<String, String> row = keepContractFields(node, table);
            Cursor rowCursor = rowCursor(row, table);
            if (!rowCursor.isAfter(next)) {
                throw invalid(table, "returned rows out of keyset order");
            }
            next = rowCursor;
            rows.add(row);
        }
        return new Page(List.copyOf(rows), next, rows.size() < size, size);
    }

    private ResponseEntity<String> get(Connection connection, DirectoryTable table, String query, int limit, String operation) {
        String uri = UriComponentsBuilder.fromUriString(connection.baseUrl())
                .path("/api/now/table/{table}")
                .queryParam("sysparm_fields", String.join(",", table.fields()))
                .queryParam("sysparm_exclude_reference_link", "true")
                .queryParam("sysparm_display_value", "false")
                .queryParam("sysparm_limit", limit)
                .queryParamIfPresent("sysparm_query", Optional.ofNullable(query))
                .buildAndExpand(table.tableName())
                .encode()
                .toUriString();
        OutboundPolicy policy = policies.forProvider(PROVIDER_KEY, 0L, null, null);
        return http.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers(connection)), String.class,
                operation, policy, context -> classify(context, table));
    }

    private OutboundFailureDecision<ServiceNowDirectoryException> classify(OutboundFailureContext context, DirectoryTable table) {
        Integer status = context.statusCodeValue();
        if (status != null && status == 401) {
            return OutboundFailureDecision.fail(new ServiceNowDirectoryException(FailureKind.AUTHENTICATION_FAILED, 401,
                    "ServiceNow rejected the integration account credentials"));
        }
        if (status != null && status == 403) {
            return OutboundFailureDecision.fail(new ServiceNowDirectoryException(FailureKind.PERMISSION_DENIED, 403,
                    "The integration account cannot read " + table.tableName()));
        }
        if (context.error() instanceof IllegalArgumentException) {
            return OutboundFailureDecision.fail(new ServiceNowDirectoryException(FailureKind.HOST_REJECTED, null,
                    "The ServiceNow instance URL is not allowed by the outbound host policy"));
        }
        if (status != null && status == 429) {
            Long retryAfter = context.retryAfterDelayMs();
            ServiceNowDirectoryException limited = new ServiceNowDirectoryException(FailureKind.RATE_LIMITED, 429,
                    "ServiceNow rate limit reached while reading " + table.tableName());
            if (retryAfter != null && retryAfter > context.policy().maxBackoffMs()) {
                return OutboundFailureDecision.fail(limited);
            }
            return OutboundFailureDecision.retry(retryAfter, limited);
        }
        ServiceNowDirectoryException unavailable = new ServiceNowDirectoryException(FailureKind.UNAVAILABLE, status,
                "ServiceNow did not respond successfully while reading " + table.tableName()
                        + (status == null ? "" : " (HTTP " + status + ")"),
                isTimeout(context.error()));
        return new OutboundFailureDecision<>(context.isRetryableByDefault(), context.retryAfterDelayMs(), unavailable);
    }

    private JsonNode readResult(ResponseEntity<String> response, DirectoryTable table) {
        String body = response.getBody();
        if (!response.getStatusCode().is2xxSuccessful() || body == null || body.isBlank()) {
            throw malformed(table, "returned an empty response");
        }
        MediaType contentType = response.getHeaders().getContentType();
        if (body.stripLeading().startsWith("<")
                || (contentType != null && !MediaType.APPLICATION_JSON.isCompatibleWith(contentType))) {
            throw malformed(table, "returned a non-JSON response; check the instance URL and API access");
        }
        JsonNode result;
        try {
            result = objectMapper.readTree(body).path("result");
        } catch (Exception parseError) {
            throw malformed(table, "returned invalid JSON");
        }
        if (!result.isArray()) {
            throw malformed(table, "did not return a result array");
        }
        return result;
    }

    private Map<String, String> keepContractFields(JsonNode node, DirectoryTable table) {
        if (!node.isObject()) {
            throw invalid(table, "returned a row that is not an object");
        }
        Map<String, String> row = new LinkedHashMap<>();
        for (String field : table.fields()) {
            JsonNode value = node.get(field);
            if (value == null || value.isNull() || value.isContainerNode()) {
                continue;
            }
            String text = value.asText().trim();
            if (!text.isEmpty()) {
                row.put(field, text);
            }
        }
        return row;
    }

    private Cursor rowCursor(Map<String, String> row, DirectoryTable table) {
        try {
            return new Cursor(row.get("sys_updated_on"), row.get("sys_id"));
        } catch (IllegalArgumentException malformed) {
            throw invalid(table, "returned a row without a valid sys_id and sys_updated_on");
        }
    }

    private static Long totalCount(ResponseEntity<String> response) {
        String header = response.getHeaders().getFirst("X-Total-Count");
        if (header == null) {
            return null;
        }
        try {
            return Long.parseLong(header.trim());
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static HttpHeaders headers(Connection connection) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        if (connection.authType() == ServiceNowAuthType.BEARER) {
            headers.setBearerAuth(connection.secret());
        } else {
            headers.setBasicAuth(connection.username(), connection.secret() == null ? "" : connection.secret(),
                    StandardCharsets.UTF_8);
        }
        return headers;
    }

    private static boolean isTimeout(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof SocketTimeoutException) {
                return true;
            }
        }
        return false;
    }

    /** A malformed body: a smaller page may succeed, as in the CMDB sync's fallback. */
    private static ServiceNowDirectoryException malformed(DirectoryTable table, String detail) {
        return new ServiceNowDirectoryException(FailureKind.INVALID_RESPONSE, null,
                "ServiceNow table " + table.tableName() + " " + detail, true);
    }

    /** Well-formed but unusable rows: a smaller page would return the same rows. */
    private static ServiceNowDirectoryException invalid(DirectoryTable table, String detail) {
        return new ServiceNowDirectoryException(FailureKind.INVALID_RESPONSE, null,
                "ServiceNow table " + table.tableName() + " " + detail, false);
    }
}
