package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OsvApiClient;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvQueryResponse;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvVulnerability;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvQueryRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@ExtendWith(MockitoExtension.class)
class OsvApiClientTest {

  @Mock
  private RestTemplate restTemplate;

  private OsvApiClient client;

  @BeforeEach
  void setUp() {
    client = new OsvApiClient(restTemplate);
  }

  @Test
  void testQueryByPackageVersion_Success() {
    OsvQueryResponse mockResponse = OsvQueryResponse.builder()
        .vulns(Arrays.asList(
            OsvVulnerability.builder()
                .id("GHSA-35jh-r3h4-6jhm")
                .summary("Command Injection in lodash")
                .aliases(Arrays.asList("CVE-2021-23337", "GHSA-r5fr-rjxr-66jc"))
                .build()
        ))
        .build();

    when(restTemplate.postForObject(anyString(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class)))
        .thenReturn(mockResponse);

    OsvQueryResponse result = client.queryByPackageVersion("npm", "lodash", "4.17.20");

    assertNotNull(result);
    assertEquals(1, result.getVulns().size());
    assertEquals("GHSA-35jh-r3h4-6jhm", result.getVulns().get(0).getId());
    assertTrue(result.getVulns().get(0).getAliases().contains("CVE-2021-23337"));
  }

  @Test
  void testQueryByPackageVersion_NoVulnerabilities() {
    OsvQueryResponse mockResponse = OsvQueryResponse.builder()
        .vulns(Collections.emptyList())
        .build();

    when(restTemplate.postForObject(anyString(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class)))
        .thenReturn(mockResponse);

    OsvQueryResponse result = client.queryByPackageVersion("npm", "safe-package", "1.0.0");

    assertNotNull(result);
    assertEquals(0, result.getVulns().size());
  }

  @Test
  void queryContinuesThroughTokenOnlyPageAndCombinesAllRecords() {
    OsvQueryResponse first = OsvQueryResponse.builder()
        .vulns(List.of(OsvVulnerability.builder().id("OSV-1").build()))
        .nextPageToken("next-1").build();
    OsvQueryResponse tokenOnly = OsvQueryResponse.builder().nextPageToken("next-2").build();
    OsvQueryResponse last = OsvQueryResponse.builder()
        .vulns(List.of(OsvVulnerability.builder().id("OSV-2").build())).build();
    when(restTemplate.postForObject(anyString(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class)))
        .thenReturn(first, tokenOnly, last);

    OsvQueryResponse result = client.queryByPackageVersion("npm", "lodash", null);

    assertEquals(List.of("OSV-1", "OSV-2"), result.getVulns().stream().map(OsvVulnerability::getId).toList());
    ArgumentCaptor<OsvQueryRequest> requests = ArgumentCaptor.forClass(OsvQueryRequest.class);
    verify(restTemplate, times(3)).postForObject(anyString(), requests.capture(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class));
    assertEquals(Arrays.asList(null, "next-1", "next-2"),
        requests.getAllValues().stream().map(OsvQueryRequest::getPageToken).toList());
  }

  @Test
  void repeatedContinuationTokenFailsInsteadOfReturningPartialResult() {
    OsvQueryResponse repeated = OsvQueryResponse.builder().nextPageToken("same-token").build();
    when(restTemplate.postForObject(anyString(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class))).thenReturn(repeated);

    assertThrows(IllegalStateException.class, () -> client.queryByPackageVersion("npm", "lodash", null));
    verify(restTemplate, times(2)).postForObject(anyString(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class));
  }

  @Test
  void pageLimitFailsInsteadOfReturningPartialResult() {
    java.util.concurrent.atomic.AtomicInteger page = new java.util.concurrent.atomic.AtomicInteger();
    when(restTemplate.postForObject(anyString(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class)))
        .thenAnswer(ignored -> OsvQueryResponse.builder()
            .nextPageToken("token-" + page.incrementAndGet()).build());

    assertThrows(IllegalStateException.class, () -> client.queryByPackageVersion("npm", "lodash", null));
    assertEquals(100, page.get());
  }

  @Test
  void continuationFieldsUseOsvWireNames() throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    assertEquals("cursor", mapper.readValue("{\"next_page_token\":\"cursor\"}", OsvQueryResponse.class)
        .getNextPageToken());
    String request = mapper.writeValueAsString(OsvQueryRequest.builder().pageToken("cursor").build());
    assertTrue(request.contains("\"page_token\":\"cursor\""));
  }

  @Test
  void testQueryByPackageVersion_ApiError() {
    when(restTemplate.postForObject(anyString(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class)))
        .thenThrow(new HttpClientErrorException(org.springframework.http.HttpStatus.BAD_REQUEST));

    assertThrows(IllegalStateException.class, () -> client.queryByPackageVersion("npm", "lodash", "4.17.20"));
  }

  @Test
  void testBatchQueryByPackages_MultiplePackages() {
    OsvQueryResponse mockResponse1 = OsvQueryResponse.builder()
        .vulns(Arrays.asList(
            OsvVulnerability.builder()
                .id("GHSA-npm-1")
                .summary("npm vuln")
                .build()
        ))
        .build();

    OsvQueryResponse mockResponse2 = OsvQueryResponse.builder()
        .vulns(Arrays.asList(
            OsvVulnerability.builder()
                .id("GHSA-python-1")
                .summary("python vuln")
                .build()
        ))
        .build();

    when(restTemplate.postForObject(anyString(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(OsvQueryResponse.class)))
        .thenReturn(mockResponse1)
        .thenReturn(mockResponse2);

    List<OsvApiClient.PackageVersion> packages = Arrays.asList(
        OsvApiClient.PackageVersion.builder()
            .ecosystem("npm")
            .name("lodash")
            .version("4.17.20")
            .build(),
        OsvApiClient.PackageVersion.builder()
            .ecosystem("Python")
            .name("django")
            .version("3.2.0")
            .build()
    );

    var results = client.batchQueryByPackages(packages);

    assertEquals(2, results.size());
    assertTrue(results.containsKey("npm:lodash@4.17.20"));
    assertTrue(results.containsKey("Python:django@3.2.0"));
  }
}
