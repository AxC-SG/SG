package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.VulnerabilityIntelObservation;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ObservationIngestionServiceTest {
    private IntelligenceWriteContext.Scope publication;
    @org.junit.jupiter.api.BeforeEach void publicationScope() { publication=IntelligenceWriteContext.publication(); }
    @org.junit.jupiter.api.AfterEach void closePublicationScope() { publication.close(); }


    @Mock
    private VulnerabilityRepository vulnerabilityRepository;

    @Mock
    private VulnerabilityIntelObservationRepository observationRepository;

    @Mock
    private VulnerabilityIntelSummaryService summaryService;

    @Mock
    private VulnerabilityIntelCorrelationService correlationService;

    @Mock
    private VulnerabilitySourceNormalizationService normalizationService;

    @InjectMocks
    private ObservationIngestionService service;

    @Test
    void sourceOnlyFeedsDoNotCreateCanonicalVulnerabilityRowsWhenNoExistingCveExists() {
        when(normalizationService.normalizeExternalId("CVE-2026-4827")).thenReturn("CVE-2026-4827");
        when(normalizationService.normalizeSourceSystem("euvd")).thenReturn("euvd");
        when(normalizationService.isSourceOnlySourceSystem("euvd")).thenReturn(true);
        when(normalizationService.isExactCveQuery("CVE-2026-4827")).thenReturn(true);
        when(normalizationService.normalizeUpperNullable("MEDIUM")).thenReturn("MEDIUM");
        when(vulnerabilityRepository.findByExternalId("CVE-2026-4827")).thenReturn(Optional.empty());
        when(observationRepository.save(any(VulnerabilityIntelObservation.class)))
                .thenAnswer(invocation -> invocation.getArgument(0, VulnerabilityIntelObservation.class));

        var result = service.upsertObservation(
                new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                        "CVE-2026-4827",
                        "euvd",
                        "EUVD-2026-4827",
                        "https://euvd.enisa.europa.eu",
                        "Sample EUVD record",
                        "Sample EUVD description",
                        "MEDIUM",
                        4.0,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        null,
                        false,
                        null,
                        null,
                        "[]",
                        "CVE-2026-4827",
                        null,
                        null,
                        "{\"aliases\":[\"CVE-2026-4827\"]}"
                )
        );

        assertNull(result.vulnerability());
        assertTrue(result.observationCreated());
        verify(vulnerabilityRepository, never()).save(any());
        verify(observationRepository).save(any(VulnerabilityIntelObservation.class));
        verify(summaryService, never()).mergeCanonicalAndRefresh(any());
        verify(correlationService).correlateObservation(any(VulnerabilityIntelObservation.class));
    }
}
