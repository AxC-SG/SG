package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OsvApiClient;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvQueryResponse;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvVulnerability;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
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
