package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Connection;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Cursor;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.DirectoryTable;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.FailureKind;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Page;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.ProbeOutcome;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.ServiceNowDirectoryException;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;
import org.springframework.web.client.RestTemplate;

class ServiceNowDirectoryClientTest {

    private static final String BASE = "https://example.test";
    private static final Connection BASIC = new Connection(BASE, ServiceNowAuthType.BASIC, "svc-directory", "s3cret");
    private static final String USER_FIELDS = "sys_id,user_name,email,first_name,last_name,name,active,locked_out,"
            + "employee_number,manager,department,sys_updated_on";
    private static final String ORDER = "ORDERBYsys_updated_on^ORDERBYsys_id";

    private MockRestServiceServer server;

    /** maxRetries 3, no backoff, Retry-After honoured up to 500 ms, network errors retried. */
    private ServiceNowDirectoryClient client(int maxRetries) {
        RestTemplate restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        return new ServiceNowDirectoryClient(
                new OutboundHttpClient(restTemplate, OutboundHostPolicy.forTests()),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0, maxRetries, 0, 500, true, true)),
                new ObjectMapper());
    }

    // ── Query rules ──────────────────────────────────────────────────────────────────────────

    @Test
    void keysetQueryOrdersByUpdatedOnThenSysIdAndAndsTheAdminFilter() {
        assertEquals(ORDER, ServiceNowDirectoryClient.keysetQuery(null, null));
        assertEquals("companyINa,b^" + ORDER, ServiceNowDirectoryClient.keysetQuery("  companyINa,b ", null));

        Cursor after = new Cursor("2026-11-14 10:00:00", sysId(7));
        assertEquals("companyINa,b^sys_updated_on>=2026-11-14 10:00:00^sys_updated_on>2026-11-14 10:00:00"
                        + "^ORsys_id>" + sysId(7) + "^" + ORDER,
                ServiceNowDirectoryClient.keysetQuery("companyINa,b", after));
    }

    @Test
    void adminFiltersCannotRemoveOrReorderTheSystemClauses() {
        for (String rejected : new String[] {
                "active=true^ORDERBYname", "active=true^NQactive=false", "active=true&sysparm_limit=1",
                "^active=true", "ORactive=true", "active=true^", "a".repeat(2_001)}) {
            assertThrows(IllegalArgumentException.class, () -> ServiceNowDirectoryClient.validateFilter(rejected), rejected);
        }
        assertNull(ServiceNowDirectoryClient.validateFilter("   "));
        assertEquals("active=true^ORlocked_out=false",
                ServiceNowDirectoryClient.validateFilter(" active=true^ORlocked_out=false "));
    }

    @Test
    void cursorsRejectValuesThatCouldInjectQueryClauses() {
        assertThrows(IllegalArgumentException.class, () -> new Cursor("2026-11-14 10:00:00^NQx", sysId(1)));
        assertThrows(IllegalArgumentException.class, () -> new Cursor("2026-11-14 10:00:00", "abc^ORDERBYx"));
        assertEquals(sysId(10), new Cursor("2026-11-14 10:00:00", sysId(10).toUpperCase()).sysId());
    }

    // ── Paging and cursor advance ─────────────────────────────────────────────────────────────

    @Test
    void pagesByKeysetAndAdvancesTheCursorToTheLastRow() {
        ServiceNowDirectoryClient client = client(3);
        server.expect(once(), requestTo(startsWith(BASE + "/api/now/table/sys_user?")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Basic "
                        + Base64.getEncoder().encodeToString("svc-directory:s3cret".getBytes(StandardCharsets.UTF_8))))
                .andExpect(params(Map.of(
                        "sysparm_fields", USER_FIELDS,
                        "sysparm_exclude_reference_link", "true",
                        "sysparm_display_value", "false",
                        "sysparm_limit", "25",
                        "sysparm_query", "active=true^" + ORDER)))
                .andRespond(json(rows(1, 25, "2026-11-14 10:00:00")));
        Cursor afterFirst = new Cursor("2026-11-14 10:00:00", sysId(25));
        server.expect(once(), requestTo(startsWith(BASE + "/api/now/table/sys_user?")))
                .andExpect(params(Map.of("sysparm_query", "active=true^sys_updated_on>=2026-11-14 10:00:00"
                        + "^sys_updated_on>2026-11-14 10:00:00^ORsys_id>" + sysId(25) + "^" + ORDER)))
                .andRespond(json(rows(26, 3, "2026-11-14 10:05:00")));

        Page first = client.fetchPage(BASIC, DirectoryTable.USERS, "active=true", null, 25);
        assertEquals(25, first.rows().size());
        assertFalse(first.last());
        assertEquals(afterFirst, first.next());

        Page second = client.fetchPage(BASIC, DirectoryTable.USERS, "active=true", first.next(), first.pageSize());
        assertEquals(3, second.rows().size());
        assertTrue(second.last());
        assertEquals(new Cursor("2026-11-14 10:05:00", sysId(28)), second.next());
        server.verify();
    }

    @Test
    void anEmptyPageKeepsTheCursorAndEndsTheTable() {
        ServiceNowDirectoryClient client = client(3);
        Cursor after = new Cursor("2026-11-14 10:00:00", sysId(3));
        server.expect(requestTo(startsWith(BASE + "/api/now/table/sys_user_group?"))).andRespond(json("[]"));

        Page page = client.fetchPage(BASIC, DirectoryTable.GROUPS, null, after, 500);

        assertTrue(page.rows().isEmpty());
        assertTrue(page.last());
        assertEquals(after, page.next());
        server.verify();
    }

    @Test
    void keepsOnlyTheContractFieldsAndUsesBearerAuth() {
        ServiceNowDirectoryClient client = client(3);
        server.expect(requestTo(startsWith(BASE + "/api/now/table/sys_user_grmember?")))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer token-1"))
                .andExpect(params(Map.of("sysparm_fields", "sys_id,user,group,sys_updated_on")))
                .andRespond(json("""
                        [{"sys_id":"%s","user":"%s","group":"%s","sys_updated_on":"2026-11-14 10:00:00",
                          "sys_created_by":"admin","password":"leak","user_ref":{"link":"https://x"}}]"""
                        .formatted(sysId(1), sysId(2), sysId(3))));

        Page page = client.fetchPage(new Connection(BASE, ServiceNowAuthType.BEARER, null, "token-1"),
                DirectoryTable.MEMBERSHIPS, null, null, 500);

        assertEquals(Map.of("sys_id", sysId(1), "user", sysId(2), "group", sysId(3),
                "sys_updated_on", "2026-11-14 10:00:00"), page.rows().get(0));
        server.verify();
    }

    @Test
    void rowsOutOfKeysetOrderFailWithoutSteppingDownThePageSize() {
        ServiceNowDirectoryClient client = client(3);
        server.expect(once(), requestTo(startsWith(BASE))).andRespond(json("""
                [{"sys_id":"%s","sys_updated_on":"2026-11-14 10:00:00"},
                 {"sys_id":"%s","sys_updated_on":"2026-11-14 10:00:00"}]""".formatted(sysId(5), sysId(4))));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.GROUPS, null, null, 500));

        assertEquals(FailureKind.INVALID_RESPONSE, error.kind());
        server.verify();
    }

    @Test
    void aRowAtOrBeforeTheCursorIsRejectedSoAnIgnoredQueryCannotLoopForever() {
        ServiceNowDirectoryClient client = client(3);
        Cursor after = new Cursor("2026-11-14 10:00:00", sysId(5));
        server.expect(once(), requestTo(startsWith(BASE))).andRespond(json("""
                [{"sys_id":"%s","sys_updated_on":"2026-11-14 10:00:00"}]""".formatted(sysId(5))));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.GROUPS, null, after, 500));

        assertEquals(FailureKind.INVALID_RESPONSE, error.kind());
        server.verify();
    }

    @Test
    void aRowWithoutAValidKeyIsRejected() {
        ServiceNowDirectoryClient client = client(3);
        server.expect(once(), requestTo(startsWith(BASE)))
                .andRespond(json("[{\"sys_id\":\"not-a-sys-id\",\"sys_updated_on\":\"2026-11-14 10:00:00\"}]"));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 500));

        assertEquals(FailureKind.INVALID_RESPONSE, error.kind());
        server.verify();
    }

    // ── Page-size ladder ─────────────────────────────────────────────────────────────────────

    @Test
    void aTimeoutStepsDownTheLadderAndReportsTheSizeThatWorked() {
        ServiceNowDirectoryClient client = client(1);
        server.expect(once(), requestTo(startsWith(BASE))).andExpect(params(Map.of("sysparm_limit", "500")))
                .andRespond(withException(new SocketTimeoutException("Read timed out")));
        server.expect(once(), requestTo(startsWith(BASE))).andExpect(params(Map.of("sysparm_limit", "250")))
                .andRespond(withException(new SocketTimeoutException("Read timed out")));
        server.expect(once(), requestTo(startsWith(BASE))).andExpect(params(Map.of("sysparm_limit", "100")))
                .andRespond(json(rows(1, 2, "2026-11-14 10:00:00")));

        Page page = client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 500);

        assertEquals(100, page.pageSize());
        assertEquals(2, page.rows().size());
        server.verify();
    }

    @Test
    void anHtmlResponseStepsDownTheLadderWithoutEchoingTheBody() {
        ServiceNowDirectoryClient client = client(1);
        for (String size : new String[] {"500", "250", "100", "25"}) {
            server.expect(once(), requestTo(startsWith(BASE))).andExpect(params(Map.of("sysparm_limit", size)))
                    .andRespond(withSuccess("<html>alice@example.com</html>", MediaType.TEXT_HTML));
        }

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 500));

        assertEquals(FailureKind.INVALID_RESPONSE, error.kind());
        assertFalse(error.getMessage().contains("alice"));
        server.verify();
    }

    @Test
    void aTimeoutAtTheSmallestSizeIsUnavailable() {
        ServiceNowDirectoryClient client = client(1);
        server.expect(once(), requestTo(startsWith(BASE))).andExpect(params(Map.of("sysparm_limit", "25")))
                .andRespond(withException(new SocketTimeoutException("Read timed out")));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 25));

        assertEquals(FailureKind.UNAVAILABLE, error.kind());
        server.verify();
    }

    // ── Rate limits ──────────────────────────────────────────────────────────────────────────

    @Test
    void aRateLimitWithRetryAfterIsRetriedThenSucceeds() {
        ServiceNowDirectoryClient client = client(3);
        HttpHeaders retryAfter = new HttpHeaders();
        retryAfter.set(HttpHeaders.RETRY_AFTER, "0");
        server.expect(once(), requestTo(startsWith(BASE)))
                .andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS).headers(retryAfter));
        server.expect(once(), requestTo(startsWith(BASE))).andRespond(json(rows(1, 1, "2026-11-14 10:00:00")));

        Page page = client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 500);

        assertEquals(1, page.rows().size());
        server.verify();
    }

    @Test
    void aRateLimitThatOutlastsTheRetriesIsRateLimited() {
        ServiceNowDirectoryClient client = client(3);
        server.expect(times(3), requestTo(startsWith(BASE))).andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 500));

        assertEquals(FailureKind.RATE_LIMITED, error.kind());
        assertEquals(429, error.status());
        server.verify();
    }

    @Test
    void aRetryAfterLongerThanThePolicyAllowsFailsWithoutWaiting() {
        ServiceNowDirectoryClient client = client(3);
        HttpHeaders retryAfter = new HttpHeaders();
        retryAfter.set(HttpHeaders.RETRY_AFTER, "3600");
        server.expect(once(), requestTo(startsWith(BASE)))
                .andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS).headers(retryAfter));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 500));

        assertEquals(FailureKind.RATE_LIMITED, error.kind());
        server.verify();
    }

    @Test
    void aServerErrorIsRetriedThenUnavailable() {
        ServiceNowDirectoryClient client = client(3);
        server.expect(times(3), requestTo(startsWith(BASE))).andRespond(withStatus(HttpStatus.BAD_GATEWAY));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 500));

        assertEquals(FailureKind.UNAVAILABLE, error.kind());
        assertEquals(502, error.status());
        server.verify();
    }

    // ── Permission denial and connection test ───────────────────────────────────────────────

    @Test
    void aDeniedTableFailsWithoutRetry() {
        ServiceNowDirectoryClient client = client(3);
        server.expect(once(), requestTo(startsWith(BASE + "/api/now/table/sys_user?")))
                .andRespond(withStatus(HttpStatus.FORBIDDEN));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.fetchPage(BASIC, DirectoryTable.USERS, null, null, 500));

        assertEquals(FailureKind.PERMISSION_DENIED, error.kind());
        assertEquals("The integration account cannot read sys_user", error.getMessage());
        server.verify();
    }

    @Test
    void probeReadsOneRowAndReportsTheCountOrTheDenial() {
        ServiceNowDirectoryClient client = client(3);
        HttpHeaders count = new HttpHeaders();
        count.set("X-Total-Count", "1234");
        server.expect(once(), requestTo(startsWith(BASE + "/api/now/table/sys_user?")))
                .andExpect(params(Map.of("sysparm_limit", "1", "sysparm_query", "active=true")))
                .andRespond(withSuccess(body(rows(1, 1, "2026-11-14 10:00:00")), MediaType.APPLICATION_JSON).headers(count));
        server.expect(once(), requestTo(startsWith(BASE + "/api/now/table/sys_user_grmember?")))
                .andRespond(withStatus(HttpStatus.FORBIDDEN));

        var users = client.probe(BASIC, DirectoryTable.USERS, "active=true");
        var memberships = client.probe(BASIC, DirectoryTable.MEMBERSHIPS, null);

        assertEquals(ProbeOutcome.READABLE, users.outcome());
        assertEquals(1234L, users.totalCount());
        assertEquals(ProbeOutcome.DENIED, memberships.outcome());
        assertNull(memberships.totalCount());
        server.verify();
    }

    @Test
    void probeThrowsOnRejectedCredentials() {
        ServiceNowDirectoryClient client = client(3);
        server.expect(once(), requestTo(startsWith(BASE))).andRespond(withStatus(HttpStatus.UNAUTHORIZED));

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.probe(BASIC, DirectoryTable.USERS, null));

        assertEquals(FailureKind.AUTHENTICATION_FAILED, error.kind());
        server.verify();
    }

    @Test
    void aHostOutsideTheAllowlistIsRejectedBeforeAnyRequest() {
        ServiceNowDirectoryClient client = client(3);
        Connection elsewhere = new Connection("https://attacker.example.com", ServiceNowAuthType.BASIC, "u", "p");

        ServiceNowDirectoryException error = assertThrows(ServiceNowDirectoryException.class,
                () -> client.probe(elsewhere, DirectoryTable.USERS, null));

        assertEquals(FailureKind.HOST_REJECTED, error.kind());
        server.verify();
    }

    @Test
    void connectionToStringHidesTheSecret() {
        assertFalse(BASIC.toString().contains("s3cret"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private static String sysId(int n) {
        return String.format("%032x", n);
    }

    private static String rows(int from, int count, String updatedOn) {
        StringJoiner joined = new StringJoiner(",", "[", "]");
        for (int n = from; n < from + count; n++) {
            joined.add("{\"sys_id\":\"%s\",\"user_name\":\"user%d\",\"email\":\"user%d@example.com\",\"active\":\"true\",\"sys_updated_on\":\"%s\"}"
                    .formatted(sysId(n), n, n, updatedOn));
        }
        return joined.toString();
    }

    private static String body(String resultArray) {
        return "{\"result\":" + resultArray + "}";
    }

    private static org.springframework.test.web.client.ResponseCreator json(String resultArray) {
        return withSuccess(body(resultArray), MediaType.APPLICATION_JSON);
    }

    private static org.hamcrest.Matcher<String> startsWith(String prefix) {
        return org.hamcrest.Matchers.startsWith(prefix);
    }

    /** Matches decoded query parameters, so expectations read as ServiceNow sees them. */
    private static RequestMatcher params(Map<String, String> expected) {
        return request -> {
            Map<String, String> actual = decodedQuery(request.getURI());
            expected.forEach((name, value) -> assertEquals(value, actual.get(name), name));
        };
    }

    private static Map<String, String> decodedQuery(URI uri) {
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : uri.getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            params.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return params;
    }
}
