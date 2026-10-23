package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.VexAssertion;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityIntelObservation;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.repo.VexAssertionRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class VexAssertionServiceTest {
    private IntelligenceWriteContext.Scope publication;
    @org.junit.jupiter.api.BeforeEach void publicationScope() { publication=IntelligenceWriteContext.publication(); }
    @org.junit.jupiter.api.AfterEach void closePublicationScope() { publication.close(); }


    @Mock
    private VexAssertionRepository vexAssertionRepository;

    @Mock
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Mock
    private VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository;

    @Test
    void refreshAssertionsExtractsPersistedStatementFromVexTarget() {
        ObjectMapper objectMapper = new ObjectMapper();
        VexAssertionService service = new VexAssertionService(
                vexAssertionRepository,
                vulnerabilityTargetRepository,
                vulnerabilityIntelObservationRepository,
                new VexPolicyService(),
                new ImpactEvaluationService(),
                objectMapper
        );

        Vulnerability vulnerability = vulnerability("CVE-2026-1111");
        VulnerabilityTarget target = new VulnerabilityTarget();
        ReflectionTestUtils.setField(target, "id", UUID.randomUUID());
        target.setVulnerability(vulnerability);
        target.setTargetType(VulnerabilityTargetType.PURL);
        target.setSource("vex-microsoft");
        target.setNormalizedTargetKey("pkg:maven/acme/demo@1.2.3");
        target.setEcosystem("maven");
        target.setNamespace("acme");
        target.setPackageName("demo");
        target.setVersionStart("1.0.0");
        target.setStartInclusive(true);
        target.setVersionEnd("2.0.0");
        target.setEndInclusive(false);
        target.setQualifiersJson("""
                {
                  "vexStatus":"AFFECTED",
                  "advisoryUrl":"https://example.test/msrc.json",
                  "advisoryDocumentId":"msrc-2026-001",
                  "advisoryTitle":"Demo VEX",
                  "vexProvider":"microsoft",
                  "vexTrustTier":"HIGH",
                  "vexPublishedAt":"2026-03-01T00:00:00Z",
                  "vexLastSeenAt":"2026-03-02T00:00:00Z"
                }
                """);

        VulnerabilityIntelObservation observation = new VulnerabilityIntelObservation();
        ReflectionTestUtils.setField(observation, "id", UUID.randomUUID());
        observation.setVulnerability(vulnerability);
        observation.setSourceSystem("vex-microsoft");
        observation.setSourceUrl("https://example.test/msrc.json");
        observation.setLastSeenAt(Instant.parse("2026-03-03T00:00:00Z"));

        when(vulnerabilityTargetRepository.findAllVexLikeTargetsByVulnerabilityIds(anyCollection()))
                .thenReturn(List.of(target));
        when(vulnerabilityIntelObservationRepository.findByVulnerabilityIdIn(anyCollection()))
                .thenReturn(List.of(observation));
        when(vexAssertionRepository.findByVulnerability_IdIn(anyCollection())).thenReturn(List.of());

        int refreshed = service.refreshAssertionsForVulnerabilityIds(List.of(vulnerability.getId()));

        ArgumentCaptor<List<VexAssertion>> saveCaptor = ArgumentCaptor.forClass(List.class);
        verify(vexAssertionRepository).saveAll(saveCaptor.capture());
        VexAssertion assertion = saveCaptor.getValue().get(0);

        assertEquals(1, refreshed);
        assertEquals("vex-microsoft", assertion.getSourceSystem());
        assertEquals("AFFECTED", assertion.getStatus());
        assertEquals("microsoft", assertion.getProvider());
        assertEquals("msrc-2026-001", assertion.getDocumentId());
        assertEquals("pkg:maven/acme/demo@1.2.3", assertion.getNormalizedProductKey());
        assertEquals(observation.getId(), assertion.getObservation().getId());
        assertNotNull(assertion.getStatementKey());
    }

    @Test
    void refreshAllAssertionsClearsPersistedRowsWhenNoVexTargetsRemain() {
        ObjectMapper objectMapper = new ObjectMapper();
        VexAssertionService service = new VexAssertionService(
                vexAssertionRepository,
                vulnerabilityTargetRepository,
                vulnerabilityIntelObservationRepository,
                new VexPolicyService(),
                new ImpactEvaluationService(),
                objectMapper
        );

        when(vulnerabilityTargetRepository.findAllVexLikeTargets()).thenReturn(List.of());
        when(vexAssertionRepository.findAll()).thenReturn(List.of(new VexAssertion()));

        int refreshed = service.refreshAllAssertions();

        assertEquals(0, refreshed);
        verify(vexAssertionRepository).deleteAllInBatch();
        verify(vexAssertionRepository, never()).saveAll(org.mockito.ArgumentMatchers.anyList());
    }

    private Vulnerability vulnerability(String externalId) {
        Vulnerability vulnerability = new Vulnerability();
        ReflectionTestUtils.setField(vulnerability, "id", UUID.randomUUID());
        vulnerability.setExternalId(externalId);
        return vulnerability;
    }
}
