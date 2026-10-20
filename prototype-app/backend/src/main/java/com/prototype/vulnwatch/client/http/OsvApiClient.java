package com.prototype.vulnwatch.client.http;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;

@Service
@Slf4j
public class OsvApiClient {

  private static final String OSV_API_URL = "https://api.osv.dev/v1/query";
  private final RestTemplate restTemplate;

  @Autowired
  public OsvApiClient(RestTemplate restTemplate) {
    this.restTemplate = restTemplate;
  }

  public OsvQueryResponse queryByPackageVersion(String ecosystem, String packageName, String version) {
    log.debug("Querying OSV: {}:{}@{}", ecosystem, packageName, version);

    try {
      OsvQueryRequest request = OsvQueryRequest.builder()
          .pkg(OsvPackage.builder().ecosystem(ecosystem).name(packageName).build())
          .version(version)
          .build();

      OsvQueryResponse response = restTemplate.postForObject(OSV_API_URL, request, OsvQueryResponse.class);

      if (response != null) {
        log.debug("OSV returned {} vulnerabilities", response.getVulns().size());
        return response;
      }

      throw new IllegalStateException("OSV returned no usable response");

    } catch (HttpClientErrorException e) {
      log.warn("OSV query failed for {}:{}: {}", ecosystem, packageName, e.getMessage());
      throw new IllegalStateException("OSV query is unavailable", e);
    } catch (Exception e) {
      log.error("OSV query error for {}:{}", ecosystem, packageName, e);
      throw new IllegalStateException("OSV query is unavailable", e);
    }
  }

  public Map<String, OsvQueryResponse> batchQueryByPackages(List<PackageVersion> packages) {
    Map<String, OsvQueryResponse> results = new HashMap<>();

    for (PackageVersion pkg : packages) {
      try {
        String key = pkg.getEcosystem() + ":" + pkg.getName() + "@" + pkg.getVersion();
        OsvQueryResponse response = queryByPackageVersion(pkg.getEcosystem(), pkg.getName(), pkg.getVersion());
        results.put(key, response);
      } catch (Exception e) {
        throw new IllegalStateException("OSV batch query is incomplete", e);
      }
    }

    return results;
  }

  // DTO Classes

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvQueryRequest {
    @JsonProperty("package")
    private OsvPackage pkg;
    private String version;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvPackage {
    private String ecosystem;
    private String name;
    private String purl;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvQueryResponse {
    private List<OsvVulnerability> vulns;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvVulnerability {
    private String id;
    private String summary;
    private String details;
    private List<String> aliases;
    private java.time.Instant published;
    private java.time.Instant modified;
    private java.time.Instant withdrawn;
    private List<OsvAffected> affected;
    private List<OsvReference> references;
    private OsvDatabaseSpecific database_specific;
    private List<OsvSeverity> severity;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvAffected {
    private OsvPackage package_info;
    private List<OsvRange> ranges;
    private List<String> versions;

    @JsonProperty("package")
    private void unpackPackage(OsvPackage value) {
      this.package_info = value;
    }
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvRange {
    private String type;
    private List<OsvEvent> events;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvEvent {
    private String introduced;
    private String fixed;
    private String last_affected;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvSeverity {
    private String type;
    private String score;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvReference {
    private String type;
    private String url;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvDatabaseSpecific {
    private String cwe;
    private String severity;
    private Boolean github_reviewed;
    private java.time.Instant github_reviewed_at;
    private java.time.Instant nvd_published_at;
  }
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class PackageVersion {
    private String ecosystem;
    private String name;
    private String version;
  }
}
