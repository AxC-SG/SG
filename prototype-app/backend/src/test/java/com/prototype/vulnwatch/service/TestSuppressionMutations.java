package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;

final class TestSuppressionMutations {
    private TestSuppressionMutations() {}

    static CanonicalSuppressionMutationService create() {
        CanonicalSuppressionMutationService service = mock(CanonicalSuppressionMutationService.class);
        lenient().doAnswer(invocation -> {
            Finding finding = invocation.getArgument(0);
            finding.setSuppressionReason(invocation.getArgument(1));
            finding.setSuppressedUntil(invocation.getArgument(2));
            finding.setSuppressedByRuleId(invocation.getArgument(3));
            finding.setSuppressedByRuleName(invocation.getArgument(4));
            finding.setStatus(FindingStatus.SUPPRESSED);
            return null;
        }).when(service).suppress(any(), any(), any(), any(), any(), any(), any());
        lenient().doAnswer(invocation -> {
            clear(invocation.getArgument(0));
            return null;
        }).when(service).clearMetadata(any(), any(), anyString(), anyString());
        lenient().doAnswer(invocation -> {
            Finding finding = invocation.getArgument(0);
            clear(finding);
            finding.setStatus(FindingStatus.OPEN);
            finding.setDecisionState(FindingDecisionState.AFFECTED);
            return null;
        }).when(service).reopen(any(), any(), anyString(), anyString());
        return service;
    }

    private static void clear(Finding finding) {
        finding.setSuppressionReason(null);
        finding.setSuppressedUntil(null);
        finding.setSuppressedByRuleId(null);
        finding.setSuppressedByRuleName(null);
    }
}
