package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import com.prototype.vulnwatch.client.http.OsvApiClient;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.repo.*;
import com.prototype.vulnwatch.service.IntelligenceStagingService;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OsvPlatformServiceTest {
    @Mock OsvApiClient client;
    @Mock OsvAdvisoryRepository approved;
    @Mock AdvisoryEquivalenceRepository equivalences;
    @Mock SoftwareIdentityRepository software;
    @Mock IntelligenceStagingService staging;
    private OsvPlatformService service;
    @BeforeEach void setup() {
        service=new OsvPlatformService(client,approved,equivalences,software);service.configureStaging(staging);
        var identity=new SoftwareIdentity();identity.setPurl("pkg:npm/lodash@4.17.20");
        when(software.findAll()).thenReturn(List.of(identity));
    }
    private void response(List<String> aliases) {
        var vulnerability=OsvApiClient.OsvVulnerability.builder().id("GHSA-35jh-r3h4-6jhm").summary("Command injection").aliases(aliases).build();
        when(client.queryByPackageVersion("npm","lodash",null)).thenReturn(OsvApiClient.OsvQueryResponse.builder().vulns(List.of(vulnerability)).build());
    }
    @Test void fetchedAdvisoriesAndStructuredAliasesArePreparedWithoutApprovedWrites() {
        response(List.of("CVE-2021-23337"));service.syncOsvAdvisories();
        ArgumentCaptor<Object> payload=ArgumentCaptor.forClass(Object.class);
        verify(staging).append(eq("OSV"),eq("GHSA-35jh-r3h4-6jhm"),isNull(),eq("osv"),payload.capture(),eq("VALID"));
        Map<?,?> row=(Map<?,?>)payload.getValue();assertEquals("npm",row.get("ecosystem"));assertEquals("lodash",row.get("package_name"));assertNotNull(row.get("id"));
        verify(staging).append(eq("EQUIVALENCE"),anyString(),isNull(),eq("osv"),any(),eq("VALID"));
        verify(approved,never()).save(any());verify(equivalences,never()).save(any());
    }
    @Test void repeatedIngestionKeepsStablePreparedRowIdentity() {
        response(List.of());service.syncOsvAdvisories();service.syncOsvAdvisories();
        ArgumentCaptor<Object> payload=ArgumentCaptor.forClass(Object.class);
        verify(staging,times(2)).append(eq("OSV"),anyString(),isNull(),eq("osv"),payload.capture(),eq("VALID"));
        assertEquals(((Map<?,?>)payload.getAllValues().get(0)).get("id"),((Map<?,?>)payload.getAllValues().get(1)).get("id"));
        verify(approved,never()).save(any());
    }
    @Test void multiCveRelationshipsRemainSeparateStructuredAssociations() {
        response(List.of("CVE-2021-23337","CVE-2021-23338","GHSA-35jh-r3h4-6jhm"));service.syncOsvAdvisories();
        ArgumentCaptor<Object> payload=ArgumentCaptor.forClass(Object.class);
        verify(staging,times(2)).append(eq("EQUIVALENCE"),anyString(),isNull(),eq("osv"),payload.capture(),eq("VALID"));
        Set<Object> cves=new HashSet<>();payload.getAllValues().forEach(row -> cves.add(((Map<?,?>)row).get("nvd_cve_id")));
        assertEquals(Set.of("CVE-2021-23337","CVE-2021-23338"),cves);
    }

    @Test void supportedPurlTypesMapToOsvEcosystemsAndKeepScopedNames() {
        List<SoftwareIdentity> inventory = new ArrayList<>();
        for (String purl : List.of(
                "pkg:npm/%40angular/core@17.0.0",
                "pkg:pypi/Django@4.0.0",
                "pkg:golang/github.com/Example/Module@v1.0.0",
                "pkg:cargo/serde@1.0.0",
                "pkg:gem/rails@7.0.0",
                "pkg:maven/org.example/unhandled@1.0")) {
            SoftwareIdentity identity = new SoftwareIdentity();
            identity.setPurl(purl);
            inventory.add(identity);
        }
        when(software.findAll()).thenReturn(inventory);
        when(client.queryByPackageVersion(anyString(), anyString(), isNull()))
                .thenReturn(OsvApiClient.OsvQueryResponse.builder().vulns(List.of()).build());

        service.syncOsvAdvisories();

        verify(software).findAll();
        verify(client).queryByPackageVersion("npm", "@angular/core", null);
        verify(client).queryByPackageVersion("PyPI", "Django", null);
        verify(client).queryByPackageVersion("Go", "github.com/Example/Module", null);
        verify(client).queryByPackageVersion("crates.io", "serde", null);
        verify(client).queryByPackageVersion("RubyGems", "rails", null);
        verify(client, times(5)).queryByPackageVersion(anyString(), anyString(), isNull());
        verifyNoInteractions(staging);
    }
}
