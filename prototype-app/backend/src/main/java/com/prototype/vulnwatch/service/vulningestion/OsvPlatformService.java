package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OsvApiClient;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvQueryResponse;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvVulnerability;
import com.prototype.vulnwatch.domain.AdvisoryEquivalenceEntity;
import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.repo.AdvisoryEquivalenceRepository;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class OsvPlatformService {

  private final OsvApiClient osvApiClient;
  private final OsvAdvisoryRepository osvAdvisoryRepository;
  private final AdvisoryEquivalenceRepository equivalenceRepository;
  private final SoftwareIdentityRepository softwareIdentityRepository;
  private final ObjectMapper objectMapper;

  @Autowired
  public OsvPlatformService(
      OsvApiClient osvApiClient,
      OsvAdvisoryRepository osvAdvisoryRepository,
      AdvisoryEquivalenceRepository equivalenceRepository,
      SoftwareIdentityRepository softwareIdentityRepository) {
    this.osvApiClient = osvApiClient;
    this.osvAdvisoryRepository = osvAdvisoryRepository;
    this.equivalenceRepository = equivalenceRepository;
    this.softwareIdentityRepository = softwareIdentityRepository;
    this.objectMapper = new ObjectMapper().findAndRegisterModules();
  }

  private com.prototype.vulnwatch.service.IntelligenceStagingService staging;
  @Autowired void configureStaging(com.prototype.vulnwatch.service.IntelligenceStagingService staging) { this.staging=staging; }

  @Transactional
  public void syncOsvAdvisories() {
    log.info("Starting OSV advisory sync");

    try {
      Set<String> ecosystems = Set.of("npm", "Python", "Go", "Rust", "RubyGems");

      for (String ecosystem : ecosystems) {
        try {
          syncEcosystemPackages(ecosystem);
        } catch (Exception e) {
          throw new IllegalStateException("OSV ecosystem retrieval is incomplete: " + ecosystem, e);
        }
      }

      // Structured aliases are staged with each fetched record below.

      log.info("OSV advisory sync completed successfully");

    } catch (Exception e) {
      throw new IllegalStateException("OSV advisory sync failed; previous intelligence is retained", e);
    }
  }

  private void syncEcosystemPackages(String ecosystem) {
    log.debug("Syncing OSV for ecosystem: {}", ecosystem);

    try {
      Set<String> packages = getInventoryPackages().getOrDefault(ecosystem, Set.of());

      if (packages.isEmpty()) {
        log.debug("No packages found for ecosystem: {}", ecosystem);
        return;
      }

      log.info("Querying OSV for {} packages in ecosystem: {}", packages.size(), ecosystem);

      for (String packageName : packages) {
        try {
          OsvQueryResponse response = osvApiClient.queryByPackageVersion(
              ecosystem,
              packageName,
              null
          );

          if (response != null && response.getVulns() != null) {
            for (OsvVulnerability vuln : response.getVulns()) {
              saveOsvAdvisory(ecosystem, packageName, vuln);
            }
          }
        } catch (Exception e) {
          throw new IllegalStateException("OSV package retrieval is incomplete", e);
        }
      }

      log.debug("Completed OSV sync for ecosystem: {}", ecosystem);

    } catch (Exception e) {
      throw new IllegalStateException("OSV ecosystem retrieval is incomplete", e);
    }
  }

  private Map<String, Set<String>> getInventoryPackages() {
    log.debug("Fetching unique packages from inventory");
    Map<String, Set<String>> result = new HashMap<>();

    try {
      for (SoftwareIdentity identity : softwareIdentityRepository.findAll()) {
        String purl = identity.getPurl();
        if (purl == null || !purl.startsWith("pkg:")) {
          continue;
        }
        int slash = purl.indexOf('/');
        if (slash < 5) {
          continue;
        }
        String ecosystem = purl.substring(4, slash);
        String packageName = purl.substring(slash + 1).split("[@?\\#]", 2)[0];
        if (!packageName.isBlank()) {
          result.computeIfAbsent(ecosystem, ignored -> new HashSet<>()).add(packageName);
        }
      }

      log.debug("Found {} ecosystems with packages", result.size());
      return result;

    } catch (Exception e) {
      throw new IllegalStateException("OSV package inventory is unavailable", e);
    }
  }

  private void saveOsvAdvisory(String ecosystem, String packageName, OsvVulnerability vuln) {
    try {
      String severity = extractSeverity(vuln.getSeverity());
      BigDecimal cvssScore = extractCvssScore(vuln.getSeverity());

      OsvAdvisoryEntity entity = OsvAdvisoryEntity.builder()
          .osvId(vuln.getId())
          .ecosystem(ecosystem)
          .packageName(packageName)
          .summary(vuln.getSummary())
          .details(vuln.getDetails())
          .severity(severity)
          .cvssV3Score(cvssScore)
          .affectedRanges(objectMapper.writeValueAsString(vuln.getAffected()))
          .publishedAt(vuln.getPublished())
          .modifiedAt(vuln.getModified())
          .withdrawnAt(vuln.getWithdrawn())
          .references(objectMapper.writeValueAsString(vuln.getReferences()))
          .osvData(objectMapper.writeValueAsString(vuln))
          .source(determineSource(vuln))
          .syncedAt(Instant.now())
          .build();

      entity.setId(java.util.UUID.nameUUIDFromBytes(("sg-osv:"+vuln.getId()).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
      entity.setCreatedAt(Instant.now());entity.setUpdatedAt(Instant.now());
      var row=com.prototype.vulnwatch.service.IntelligenceEntityCodec.row(entity);
      for(String field:List.of("affected_ranges","osv_data","reference_data")) {
          Object value=row.get(field);if(value instanceof String text) row.put(field,objectMapper.readTree(text));
      }
      staging.append("OSV",vuln.getId(),null,"osv",row,"VALID");
      if(vuln.getAliases()!=null) {
        var cves=vuln.getAliases().stream().filter(alias -> alias.matches("CVE-[0-9]{4}-[0-9]{4,}")).toList();
        var ghsas=vuln.getAliases().stream().filter(alias -> alias.startsWith("GHSA-")).toList();
        for(String cve:cves) {
          if(ghsas.isEmpty()) createEquivalence(cve,null,vuln.getId(),"structured_alias");
          else for(String ghsa:ghsas) createEquivalence(cve,ghsa,vuln.getId(),"structured_alias");
        }
      }
      log.debug("Saved OSV advisory: {}", vuln.getId());

    } catch (Exception e) {
      throw new IllegalStateException("OSV advisory persistence failed", e);
    }
  }

  private void createEquivalence(String cveId, String ghsaId, String osvId, String reason) {
    try {
      if (equivalenceRepository.existsByNvdCveIdAndGhsaIdAndOsvId(cveId, ghsaId, osvId)) {
        return;
      }

      AdvisoryEquivalenceEntity eq = AdvisoryEquivalenceEntity.builder()
          .nvdCveId(cveId)
          .ghsaId(ghsaId)
          .osvId(osvId)
          .equivalenceConfidence(new BigDecimal("0.95"))
          .equivalenceReason(reason)
          .discoveredAt(Instant.now())
          .build();

      eq.setId(java.util.UUID.nameUUIDFromBytes(("sg-equivalence:"+cveId+":"+ghsaId+":"+osvId).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
      staging.append("EQUIVALENCE",osvId,null,"osv",com.prototype.vulnwatch.service.IntelligenceEntityCodec.row(eq),"VALID");
      log.debug("Created equivalence: {} -> {} -> {}", cveId, ghsaId, osvId);

    } catch (Exception e) {
      throw new IllegalStateException("Structured alias normalization failed",e);
    }
  }

  private String determineSource(OsvVulnerability vuln) {
    if (vuln.getAliases() != null) {
      for (String alias : vuln.getAliases()) {
        if (alias.startsWith("RUSTSEC")) return "rustsec";
        if (alias.startsWith("GHSA")) return "github";
      }
    }
    return "nvd";
  }

  private String extractSeverity(List<OsvApiClient.OsvSeverity> severities) {
    if (severities == null || severities.isEmpty()) return "UNKNOWN";

    for (OsvApiClient.OsvSeverity sev : severities) {
      if ("CVSS_V3".equals(sev.getType())) {
        return scoreToCvssRating(sev.getScore());
      }
    }
    return "UNKNOWN";
  }

  private BigDecimal extractCvssScore(List<OsvApiClient.OsvSeverity> severities) {
    if (severities == null) return null;

    for (OsvApiClient.OsvSeverity sev : severities) {
      if ("CVSS_V3".equals(sev.getType())) {
        return extractScoreFromCvss(sev.getScore());
      }
    }
    return null;
  }

  private String scoreToCvssRating(String cvssVector) {
    if (cvssVector == null) return "UNKNOWN";

    try {
      String[] parts = cvssVector.split("/");
      if (parts.length > 0) {
        String firstPart = parts[0].replace("CVSS:3.1/", "").replace("CVSS:3.0/", "");
        double score = Double.parseDouble(firstPart);
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MODERATE";
        return "LOW";
      }
    } catch (Exception e) {
      log.debug("Failed to parse CVSS rating", e);
    }
    return "UNKNOWN";
  }

  private BigDecimal extractScoreFromCvss(String cvssVector) {
    try {
      String[] parts = cvssVector.split("/");
      if (parts.length > 0) {
        String firstPart = parts[0].replace("CVSS:3.1/", "").replace("CVSS:3.0/", "");
        return new BigDecimal(firstPart);
      }
    } catch (Exception e) {
      log.debug("Failed to extract CVSS score", e);
    }
    return null;
  }
}
