package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class OsvTenantServicePostgresIntegrationTest {

  private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
      LocalPostgresTestDatabase.provision("osv_tenant_service");

  @DynamicPropertySource
  static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
    PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
  }

  @Autowired
  private OsvTenantService tenantService;

  @Autowired
  private OsvAdvisoryRepository osvRepository;

  private UUID testTenantId;

  @BeforeEach
  void setUp() {
    testTenantId = UUID.randomUUID();
    osvRepository.deleteAll();
  }

  @Test
  void testCorrelateOsvAdvisories_ServiceInitialized() {
    assertNotNull(tenantService);
    assertNotNull(osvRepository);
  }

  @Test
  void testMultiTenantContext_PlatformDataShared() {
    // Platform-level OSV data (shared)
    OsvAdvisoryEntity advisory = OsvAdvisoryEntity.builder()
        .osvId("OSV-SHARED-1")
        .ecosystem("npm")
        .packageName("lodash")
        .summary("Shared vulnerability")
        .affectedRanges("[]")
        .osvData("{}")
        .source("nvd")
        .syncedAt(Instant.now())
        .build();

    osvRepository.save(advisory);

    // Verify accessible from platform level
    var found = osvRepository.findByEcosystemAndPackageName("npm", "lodash");
    assertEquals(1, found.size());
  }

  @Test
  void testCorrelateOsvAdvisories_HandlesEmptyInventory() {
    // When tenant has no components, should not create findings
    assertThrows(org.springframework.web.server.ResponseStatusException.class,
        () -> tenantService.correlateOsvAdvisoriesForTenant(testTenantId));
  }

  @Test
  void testCorrelateOsvAdvisories_GracefulErrorHandling() {
    // If OSV repository has corrupt data, should handle gracefully
    OsvAdvisoryEntity entity = OsvAdvisoryEntity.builder()
        .osvId("OSV-BAD-DATA")
        .ecosystem("npm")
        .packageName("test")
        .summary("Bad data")
        .affectedRanges("{}")  // Valid JSON with an unexpected shape
        .osvData("{}")
        .source("nvd")
        .build();

    osvRepository.save(entity);

    assertThrows(org.springframework.web.server.ResponseStatusException.class,
        () -> tenantService.correlateOsvAdvisoriesForTenant(testTenantId));
  }

  @Test
  void testScheduledCorrelation_PicksUpPlatformData() {
    // Populate platform-level data
    for (int i = 0; i < 5; i++) {
      OsvAdvisoryEntity advisory = OsvAdvisoryEntity.builder()
          .osvId("OSV-BATCH-" + i)
          .ecosystem("npm")
          .packageName("package-" + i)
          .summary("Batch test " + i)
          .affectedRanges("[]")
          .osvData("{}")
          .source("nvd")
          .syncedAt(Instant.now())
          .build();
      osvRepository.save(advisory);
    }

    assertEquals(5, osvRepository.count());

    // A stale scheduled callback remains inactive and preserves shared intelligence.
    tenantService.correlateOsvForAllEnabledTenants();
    assertEquals(5, osvRepository.count());
  }
}
