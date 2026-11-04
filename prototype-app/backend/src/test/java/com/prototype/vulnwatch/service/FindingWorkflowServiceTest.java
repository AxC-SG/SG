package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingComment;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.dto.FindingCommentRequest;
import com.prototype.vulnwatch.dto.FindingCommentResponse;
import com.prototype.vulnwatch.dto.FindingTimelineResponse;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingCommentRepository;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class FindingWorkflowServiceTest {

    @Mock private FindingRepository findingRepository;
    @Mock private FindingCommentRepository findingCommentRepository;
    @Mock private FindingEventRepository findingEventRepository;
    @Mock private RiskPolicyRepository riskPolicyRepository;
    @Mock private AssetRepository assetRepository;
    @Mock private ObjectProvider<AuditEventService> auditEventServiceProvider;
    @Mock private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock private FindingListProjectionService findingListProjectionService;
    @Mock private TenantWorkRunner tenantWorkRunner;

    private FindingWorkflowService service;

    @BeforeEach
    void setUp() {
        service = new FindingWorkflowService(
                findingRepository,
                findingCommentRepository,
                findingEventRepository,
                riskPolicyRepository,
                assetRepository,
                new ObjectMapper(),
                auditEventServiceProvider,
                tenantSchemaExecutionService,
                findingListProjectionService,
                tenantWorkRunner
        );
        service.setSuppressionMutations(TestSuppressionMutations.create());
    }

    @Test
    void updateWorkflowThrowsWhenFindingNotFound() {
        UUID missingId = UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff");
        when(findingRepository.findById(missingId)).thenReturn(Optional.empty());

        FindingWorkflowUpdateRequest req = new FindingWorkflowUpdateRequest(
                "RESOLVED", null, null, null, null, null, null);

        assertThrows(EntityNotFoundException.class, () -> service.updateWorkflow(missingId, req));
    }

    @Test
    void updateWorkflowAppliesStatusChangeToExistingFinding() {
        UUID findingId = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        Finding finding = new Finding();
        finding.setStatus(FindingStatus.OPEN);
        ReflectionTestUtils.setField(finding, "id", findingId);

        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding));
        when(findingRepository.save(finding)).thenReturn(finding);
        when(findingEventRepository.save(any(FindingEvent.class))).thenAnswer(inv -> inv.getArgument(0));

        FindingWorkflowUpdateRequest req = new FindingWorkflowUpdateRequest(
                "RESOLVED", "analyst@example.com", null, null, null, null, "analyst@example.com");

        Finding result = service.updateWorkflow(findingId, req);

        assertNotNull(result);
        assertEquals(FindingStatus.RESOLVED, result.getStatus());
        verify(findingRepository).save(finding);
    }

    @Test
    void autoCloseFindingSetsReasonAndClosureMetadata() {
        Finding finding = new Finding();
        finding.setStatus(FindingStatus.OPEN);
        Instant closedAt = Instant.parse("2026-06-18T12:00:00Z");
        when(findingEventRepository.save(any(FindingEvent.class))).thenAnswer(inv -> inv.getArgument(0));

        service.autoCloseFinding(
                finding,
                FindingCloseReason.AUTO_NOT_OBSERVED,
                "Finding auto-closed because it was not observed",
                java.util.Map.of("consecutiveMisses", 2),
                closedAt);

        assertEquals(FindingStatus.AUTO_CLOSED, finding.getStatus());
        assertEquals(FindingCloseReason.AUTO_NOT_OBSERVED, finding.getClosedReason());
        assertEquals("system", finding.getClosedBy());
        assertEquals(closedAt, finding.getClosedAt());
        verify(findingEventRepository).save(any(FindingEvent.class));
    }

    @Test
    void bulkDeleteByIdsDelegatesToRepository() {
        UUID id1 = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        UUID id2 = UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc");
        List<UUID> ids = List.of(id1, id2);
        Finding f1 = new Finding();
        Finding f2 = new Finding();
        List<Finding> findings = List.of(f1, f2);
        when(findingRepository.findAllById(ids)).thenReturn(findings);
        when(findingCommentRepository.findByFindingOrderByCreatedAtAsc(any(Finding.class))).thenReturn(List.of());
        when(findingEventRepository.findByFindingOrderByCreatedAtAsc(any(Finding.class))).thenReturn(List.of());

        int deleted = service.bulkDelete(ids);

        assertEquals(2, deleted);
        verify(findingRepository).deleteAll(findings);
    }

    @Test
    void bulkDeleteWithEmptyListDeletesNothing() {
        int deleted = service.bulkDelete(List.of());

        assertEquals(0, deleted);
        verify(findingRepository, never()).findAllById(any());
    }

    @Test
    void addCommentPersistsCommentAndReturnsResponse() {
        UUID findingId = UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd");
        Finding finding = new Finding();
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding));

        FindingComment savedComment = mock(FindingComment.class);
        when(savedComment.getId()).thenReturn(UUID.randomUUID());
        when(savedComment.getAuthor()).thenReturn("analyst@example.com");
        when(savedComment.getBody()).thenReturn("Investigating patch availability");
        when(savedComment.getCreatedAt()).thenReturn(Instant.now());
        when(findingCommentRepository.save(any(FindingComment.class))).thenReturn(savedComment);
        when(findingEventRepository.save(any(FindingEvent.class))).thenAnswer(inv -> inv.getArgument(0));

        FindingCommentRequest req = new FindingCommentRequest("analyst@example.com", "Investigating patch availability");
        FindingCommentResponse response = service.addComment(findingId, req);

        assertNotNull(response);
        assertEquals("analyst@example.com", response.author());
        assertEquals("Investigating patch availability", response.body());
        verify(findingCommentRepository).save(any(FindingComment.class));
    }

    @Test
    void addCommentThrowsWhenFindingNotFound() {
        UUID missingId = UUID.fromString("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee");
        when(findingRepository.findById(missingId)).thenReturn(Optional.empty());

        FindingCommentRequest req = new FindingCommentRequest("analyst@example.com", "comment body");

        assertThrows(EntityNotFoundException.class, () -> service.addComment(missingId, req));
        verify(findingCommentRepository, never()).save(any());
    }

    @Test
    void getTimelineReturnsFindingEventsAndComments() {
        UUID findingId = UUID.fromString("ffffffff-ffff-ffff-ffff-000000000001");
        Finding finding = new Finding();
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding));
        when(findingEventRepository.findByFindingOrderByCreatedAtAsc(any(Finding.class))).thenReturn(List.of());
        when(findingCommentRepository.findByFindingOrderByCreatedAtAsc(any(Finding.class))).thenReturn(List.of());

        FindingTimelineResponse timeline = service.getTimeline(findingId);

        assertNotNull(timeline);
        assertEquals(findingId, timeline.findingId());
        assertEquals(0, timeline.events().size());
        assertEquals(0, timeline.comments().size());
    }
}
