package com.prototype.vulnwatch.service.cbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.BomEvidenceState;
import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.repo.CbomComponentRepository;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * CBOM keeps its own evaluator and findings store, so it gains only the evidence lifecycle.
 * A document going away withdraws what it reported; it does not resolve the risk.
 */
class CbomEvidenceWithdrawalTest {

    private CbomComponentRepository componentRepository;
    private CbomRiskFindingRepository findingRepository;
    private CbomIngestionService service;
    private UUID sourceBomId;

    @BeforeEach
    void setUp() {
        componentRepository = mock(CbomComponentRepository.class);
        findingRepository = mock(CbomRiskFindingRepository.class);
        service = new CbomIngestionService(
                mock(CbomComponentParser.class),
                mock(CbomRiskEngine.class),
                mock(CbomRiskScorer.class),
                mock(CbomPostureService.class),
                componentRepository,
                findingRepository,
                mock(CbomFindingMirrorService.class));
        sourceBomId = UUID.randomUUID();
    }

    private CbomRiskFinding finding(CbomFindingStatus status, Instant resolvedAt) {
        CbomRiskFinding finding = new CbomRiskFinding();
        finding.setStatus(status);
        finding.setResolvedAt(resolvedAt);
        finding.setLastSeenAt(Instant.parse("2024-01-01T00:00:00Z"));
        return finding;
    }

    @Test
    void supersedingADocumentWithdrawsEvidenceButNotTheFinding() {
        CbomRiskFinding open = finding(CbomFindingStatus.OPEN, null);
        when(findingRepository.findBySourceBomId(sourceBomId)).thenReturn(List.of(open));

        service.deactivateBySourceBomId(sourceBomId);

        assertEquals(BomEvidenceState.WITHDRAWN, open.getEvidenceState());
        assertNotNull(open.getWithdrawnAt());
        assertEquals(CbomFindingStatus.OPEN, open.getStatus(),
                "a withdrawn document does not mean the weak algorithm was fixed");
        assertNull(open.getResolvedAt());
    }

    // Plan: "CBOM withdrawal preserves finding status and resolution timestamps."
    @Test
    void anAlreadyResolvedFindingKeepsItsResolutionTimestamp() {
        Instant resolvedAt = Instant.parse("2023-06-01T12:00:00Z");
        CbomRiskFinding resolved = finding(CbomFindingStatus.RESOLVED, resolvedAt);
        when(findingRepository.findBySourceBomId(sourceBomId)).thenReturn(List.of(resolved));

        service.deactivateBySourceBomId(sourceBomId);

        assertEquals(BomEvidenceState.WITHDRAWN, resolved.getEvidenceState());
        assertEquals(CbomFindingStatus.RESOLVED, resolved.getStatus());
        assertEquals(resolvedAt, resolved.getResolvedAt(), "resolution history must survive withdrawal");
    }

    @Test
    void withdrawalDoesNotCountAsAnObservation() {
        CbomRiskFinding open = finding(CbomFindingStatus.OPEN, null);
        Instant seenBefore = open.getLastSeenAt();
        when(findingRepository.findBySourceBomId(sourceBomId)).thenReturn(List.of(open));

        service.deactivateBySourceBomId(sourceBomId);

        assertEquals(seenBefore, open.getLastSeenAt());
    }

    @Test
    void anAlreadyWithdrawnFindingIsNotRewritten() {
        CbomRiskFinding alreadyWithdrawn = finding(CbomFindingStatus.OPEN, null);
        alreadyWithdrawn.setEvidenceState(BomEvidenceState.WITHDRAWN);
        Instant firstWithdrawal = Instant.parse("2024-02-02T00:00:00Z");
        alreadyWithdrawn.setWithdrawnAt(firstWithdrawal);
        when(findingRepository.findBySourceBomId(sourceBomId)).thenReturn(List.of(alreadyWithdrawn));

        service.deactivateBySourceBomId(sourceBomId);

        assertEquals(firstWithdrawal, alreadyWithdrawn.getWithdrawnAt(),
                "the original withdrawal time is the audit record and must not move");
        verify(findingRepository, never()).saveAll(anyList());
    }

    @Test
    void componentsAreStillDeactivated() {
        when(findingRepository.findBySourceBomId(sourceBomId)).thenReturn(List.of());
        when(componentRepository.softDeleteBySourceBomId(sourceBomId)).thenReturn(4);

        assertEquals(4, service.deactivateBySourceBomId(sourceBomId));
        verify(findingRepository, never()).save(any());
    }
}
