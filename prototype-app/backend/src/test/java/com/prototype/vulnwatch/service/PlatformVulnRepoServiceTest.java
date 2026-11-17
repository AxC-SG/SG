package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelSummarySourceRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class PlatformVulnRepoServiceTest {

    @Mock
    private VulnerabilityRepository vulnerabilityRepository;

    @Mock
    private VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository;

    @Mock
    private VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository;

    @Mock
    private VulnerabilityIntelDescriptionService vulnerabilityIntelDescriptionService;

    @Mock
    private FindingRepository findingRepository;

    @Mock
    private NamedParameterJdbcTemplate jdbcTemplate;

    private PlatformVulnRepoService service;

    @BeforeEach
    void setUp() {
        service = new PlatformVulnRepoService(
                vulnerabilityRepository,
                vulnerabilityIntelSummarySourceRepository,
                vulnerabilityIntelObservationRepository,
                vulnerabilityIntelDescriptionService,
                jdbcTemplate
        );
    }

    @Test
    void listVulnerabilitiesUsesSourceScopedQueryWhenSourceFilterPresent() {
        UUID vulnerabilityId = UUID.fromString("00000000-0000-0000-0000-000000000111");
        Vulnerability vulnerability = new Vulnerability();
        ReflectionTestUtils.setField(vulnerability, "id", vulnerabilityId);
        vulnerability.setExternalId("CVE-2026-1001");
        vulnerability.setTitle("Scoped result");
        vulnerability.setSeverity("HIGH");

        when(vulnerabilityRepository.searchPlatformCatalog(
                eq("CVE-"),
                eq(""),
                eq(""),
                eq(null),
                eq("ghsa"),
                any(Pageable.class)
        )).thenReturn(new PageImpl<>(List.of(vulnerability)));
        when(vulnerabilityIntelSummarySourceRepository.findByVulnerabilityIdIn(List.of(vulnerabilityId)))
                .thenReturn(List.of());
        when(vulnerabilityIntelDescriptionService.toDescriptionSnippet(null)).thenReturn(null);

        var response = service.listVulnerabilities(0, 25, null, null, null, "ghsa");

        assertEquals(1L, response.totalItems());
        assertEquals("CVE-2026-1001", response.items().get(0).externalId());
        verify(vulnerabilityRepository).searchPlatformCatalog(
                eq("CVE-"),
                eq(""),
                eq(""),
                eq(null),
                eq("ghsa"),
                any(Pageable.class)
        );
        verifyNoInteractions(findingRepository, jdbcTemplate);
        verify(vulnerabilityIntelObservationRepository, never()).findDistinctVulnerabilityIdsBySourceSystems(any());
        assertEquals("UNKNOWN", response.items().get(0).impactState());
        assertEquals(null, response.items().get(0).lastEvaluatedAt());
    }

    @Test
    void listVulnerabilitiesReturnsEmptyWhenSourceScopeHasNoMatches() {
        when(vulnerabilityRepository.searchPlatformCatalog(eq("CVE-"), eq(""), eq(""), eq(null),
                eq("ghsa"), any(Pageable.class))).thenReturn(Page.empty());

        var response = service.listVulnerabilities(0, 25, null, null, null, "ghsa");

        assertEquals(0L, response.totalItems());
        assertEquals(List.of(), response.items());
        verify(vulnerabilityRepository, never()).searchVulnerabilityIntelWithoutQueryScoped(
                any(),
                any(),
                anyBoolean(),
                anyList(),
                anyBoolean(),
                anyList(),
                anyBoolean(),
                anyList(),
                any(),
                any(Pageable.class)
        );
        verifyNoInteractions(vulnerabilityIntelSummarySourceRepository, vulnerabilityIntelObservationRepository,
                findingRepository, jdbcTemplate);
    }
}
