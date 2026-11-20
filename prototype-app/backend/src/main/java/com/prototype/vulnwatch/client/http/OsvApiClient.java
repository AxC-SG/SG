package com.prototype.vulnwatch.client.http;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
  private static final int MAX_QUERY_PAGES = 100;
  private final RestTemplate restTemplate;

  @Autowired
  public OsvApiClient(RestTemplate restTemplate) {
    this.restTemplate = restTemplate;
  }

  /** Stream the complete public dataset without buffering the archive in heap. */
  public int streamDataset(java.util.function.Consumer<OsvVulnerability> sink) {
    Integer count = restTemplate.execute("https://storage.googleapis.com/osv-vulnerabilities/all.zip",
        org.springframework.http.HttpMethod.GET, null, response -> {
          var mapper = new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules()
              .disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
          int records = 0;
          try (var zip = new java.util.zip.ZipInputStream(response.getBody())) {
            java.util.zip.ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
              if (entry.isDirectory() || !entry.getName().endsWith(".json")) continue;
              byte[] bytes = zip.readNBytes(16 * 1024 * 1024 + 1);
              if (bytes.length > 16 * 1024 * 1024) throw new java.io.IOException("OSV record exceeds size limit");
              OsvVulnerability value = mapper.readValue(bytes, OsvVulnerability.class);
              if (value.getId() == null || value.getId().isBlank() || value.getModified() == null)
                throw new java.io.IOException("OSV record has no identifier or modification time");
              sink.accept(value);
              records++;
            }
          }
          if (records == 0) throw new java.io.IOException("OSV dataset contained no records");
          return records;
        });
    if (count == null) throw new IllegalStateException("OSV dataset unavailable");
    return count;
  }

  public OsvQueryResponse queryByPackageVersion(String ecosystem, String packageName, String version) {
    log.debug("Querying OSV: {}:{}@{}", ecosystem, packageName, version);

    try {
      List<OsvVulnerability> vulnerabilities = new ArrayList<>();
      Set<String> seenTokens = new HashSet<>();
      String pageToken = null;
      for (int page = 0; page < MAX_QUERY_PAGES; page++) {
        OsvQueryRequest request = OsvQueryRequest.builder()
            .pkg(OsvPackage.builder().ecosystem(ecosystem).name(packageName).build())
            .version(version)
            .pageToken(pageToken)
            .build();
        OsvQueryResponse response = restTemplate.postForObject(OSV_API_URL, request, OsvQueryResponse.class);
        if (response == null) {
          throw new IllegalStateException("OSV returned no usable response");
        }
        if (response.getVulns() != null) {
          vulnerabilities.addAll(response.getVulns());
        }
        String nextPageToken = response.getNextPageToken();
        if (nextPageToken == null || nextPageToken.isBlank()) {
          log.debug("OSV returned {} vulnerabilities across {} pages", vulnerabilities.size(), page + 1);
          return OsvQueryResponse.builder().vulns(vulnerabilities).build();
        }
        if (!seenTokens.add(nextPageToken)) {
          throw new IllegalStateException("OSV repeated a continuation token");
        }
        pageToken = nextPageToken;
      }
      throw new IllegalStateException("OSV query page limit reached before completion");

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
    @JsonProperty("page_token")
    private String pageToken;
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
    @JsonProperty("next_page_token")
    private String nextPageToken;
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
