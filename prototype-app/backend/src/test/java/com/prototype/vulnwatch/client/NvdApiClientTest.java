package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class NvdApiClientTest {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final OutboundHttpClient outboundHttpClient = new OutboundHttpClient(restTemplate);
    private final OutboundPolicyFactory outboundPolicyFactory = new OutboundPolicyFactory(
            new OutboundPolicyDefaults(0L, 1, 1L, 60000L, true, true)
    );
    private final NvdApiClient client = new NvdApiClient(objectMapper, outboundHttpClient, outboundPolicyFactory);
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        server = MockRestServiceServer.createServer(restTemplate);
        ReflectionTestUtils.setField(client, "baseUrl", "https://services.nvd.nist.gov/rest/json/cves/2.0");
        ReflectionTestUtils.setField(client, "apiKey", "");
        ReflectionTestUtils.setField(client, "apiKeyFile", "");
        ReflectionTestUtils.setField(client, "resultsPerPage", 2000);
        ReflectionTestUtils.setField(client, "minRequestIntervalMs", 0L);
        ReflectionTestUtils.setField(client, "maxRetries", 1);
        ReflectionTestUtils.setField(client, "retryBaseBackoffMs", 1L);
        client.init();
    }

    @Test
    void hasApiKey_acceptsFullSyncUiOverrideWhenBackendConfigIsBlank() {
        assertTrue(client.hasApiKey("ui-provided-token"));
    }

    @Test
    void fetchPage_prefersFullSyncUiOverrideApiKeyHeader() {
        server.expect(requestTo("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=2000"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("apiKey", "ui-provided-token"))
                .andRespond(withSuccess("""
                        {
                          "resultsPerPage": 1,
                          "startIndex": 0,
                          "totalResults": 1,
                          "vulnerabilities": [
                            {
                              "cve": {
                                "id": "CVE-2024-0001",
                                "descriptions": [
                                  {
                                    "lang": "en",
                                    "value": "Test NVD record"
                                  }
                                ]
                              }
                            }
                          ]
                        }
                        """, MediaType.APPLICATION_JSON));

        NvdApiClient.NvdPage page = client.fetchPage(0, null, null, "ui-provided-token");

        assertEquals(1, page.records().size());
        assertEquals("CVE-2024-0001", page.records().get(0).cveId());
        server.verify();
    }

    @Test
    void fetchPage_appendsConfiguredQueryFilters() {
        server.expect(requestTo(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=2000"
                                + "&cpeName=cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
                                + "&isVulnerable&hasKev&cvssV3Severity=CRITICAL"
                ))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {
                          "resultsPerPage": 0,
                          "startIndex": 0,
                          "totalResults": 0,
                          "vulnerabilities": []
                        }
                        """, MediaType.APPLICATION_JSON));

        NvdApiClient.NvdPage page = client.fetchPage(
                0,
                null,
                null,
                new NvdApiClient.NvdQueryFilters(
                        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                        true,
                        true,
                        "CRITICAL",
                        null
                ),
                null
        );

        assertEquals(0, page.records().size());
        assertEquals(0, page.totalResults());
        assertEquals(0, page.startIndex());
        assertEquals(0, page.resultsPerPage());
        server.verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{}",
            "null",
            "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":0}",
            "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":0,\"vulnerabilities\":{}}",
            "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":\"0\",\"vulnerabilities\":[]}",
            "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":-1,\"vulnerabilities\":[]}",
            "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":2147483648,\"vulnerabilities\":[]}",
            "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":0,\"vulnerabilities\":[{}]}",
            "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":0,\"vulnerabilities\":[]} {}"
    })
    void fetchPage_rejectsMalformedFirstPage(String body) {
        server.expect(requestTo("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=2000"))
                .andRespond(withSuccess(body, MediaType.APPLICATION_JSON));

        assertThrows(RuntimeException.class, () -> client.fetchPage(0, null, null));
        server.verify();
    }

    @Test
    void fetchPage_rejectsMissingPaginationOnLaterPage() {
        server.expect(requestTo("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=2000&resultsPerPage=2000"))
                .andRespond(withSuccess("{\"vulnerabilities\":[]}", MediaType.APPLICATION_JSON));

        assertThrows(RuntimeException.class, () -> client.fetchPage(2000, null, null));
        server.verify();
    }

    @Test
    void fetchPage_explainsNvdInvalidApiKey404() {
        server.expect(requestTo("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=2000"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.TEXT_PLAIN)
                        .body("Invalid apiKey."));

        RuntimeException error = assertThrows(RuntimeException.class,
                () -> client.fetchPage(0, null, null, "invalid-key"));

        assertTrue(error.getMessage().contains("Replace the NVD API key and retry the full ingest"));
        server.verify();
    }
}
