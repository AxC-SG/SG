package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class JvnApiClientTest {
    private final RestTemplate restTemplate = new RestTemplate();
    private final JvnApiClient client = new JvnApiClient(new ObjectMapper(), new OutboundHttpClient(restTemplate),
            new OutboundPolicyFactory(new OutboundPolicyDefaults(0L, 1, 1L, 60000L, true, true)));
    private MockRestServiceServer server;
    private static final String URI = "https://example.test/myjvn?method=getVulnOverviewList&version=3.3&lang=en&feed=hnd&startItem=1&maxCountItem=50";

    @BeforeEach
    void setUp() {
        server = MockRestServiceServer.createServer(restTemplate);
        ReflectionTestUtils.setField(client, "apiUrl", "https://example.test/myjvn");
        ReflectionTestUtils.setField(client, "perPage", 50);
        ReflectionTestUtils.setField(client, "minRequestIntervalMs", 0L);
        ReflectionTestUtils.setField(client, "maxRetries", 1);
        ReflectionTestUtils.setField(client, "retryBaseBackoffMs", 1L);
    }

    @Test
    void blankAndUnrecognizedDocumentsCannotCompleteAsEmptyPages() {
        server.expect(requestTo(URI)).andRespond(withSuccess(" ", MediaType.APPLICATION_XML));
        server.expect(requestTo(URI)).andRespond(withSuccess("<html><body>temporarily unavailable</body></html>", MediaType.APPLICATION_XML));

        assertThrows(RuntimeException.class, () -> client.fetchPage(1));
        assertThrows(RuntimeException.class, () -> client.fetchPage(1));
        server.verify();
    }

    @Test
    void explicitEmptyStatusIsAccepted() {
        server.expect(requestTo(URI)).andRespond(withSuccess("""
                <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                         xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
                  <status:Status totalRes="0" totalResRet="0" firstRes="1" />
                </rdf:RDF>
                """, MediaType.APPLICATION_XML));

        var page = client.fetchPage(1);
        assertEquals(0, page.records().size());
        assertEquals(0, page.totalResults());
        server.verify();
    }

    @Test
    void missingInvalidAndNegativeStatusTotalsCannotCompleteAsEmptyPages() {
        for (String attribute : new String[]{"", " totalRes=\"unknown\"", " totalRes=\"-1\""}) {
            server.expect(requestTo(URI)).andRespond(withSuccess("""
                    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                             xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
                      <status:Status%s />
                    </rdf:RDF>
                    """.formatted(attribute), MediaType.APPLICATION_XML));
        }

        assertThrows(RuntimeException.class, () -> client.fetchPage(1));
        assertThrows(RuntimeException.class, () -> client.fetchPage(1));
        assertThrows(RuntimeException.class, () -> client.fetchPage(1));
        server.verify();
    }
}
