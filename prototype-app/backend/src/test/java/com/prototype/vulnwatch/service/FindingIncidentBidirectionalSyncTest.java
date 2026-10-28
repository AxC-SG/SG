package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.ticketing.TicketPush;
import com.prototype.vulnwatch.ticketing.TicketStatus;
import com.prototype.vulnwatch.ticketing.TicketingProvider;
import com.prototype.vulnwatch.ticketing.TicketingProviderRegistry;
import com.prototype.vulnwatch.ticketing.TicketingService;
import com.prototype.vulnwatch.ticketing.TicketingSystem;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/** Bidirectional reconciliation between findings and the tickets that track them. */
class FindingIncidentBidirectionalSyncTest {

    private final FindingRepository findings = mock(FindingRepository.class);
    private final Tenant tenant = mock(Tenant.class);
    private final TenantWorkRunner tenantWorkRunner = mock(TenantWorkRunner.class);
    private final FindingWorkflowService findingWorkflowService = mock(FindingWorkflowService.class);

    // ── Pull: ticket → finding ───────────────────────────────────────────────

    @Test
    void resolvesTheFindingWhenItsTicketIsResolved() {
        Finding finding = finding("INC0010005", "servicenow", "In Progress", FindingStatus.OPEN, "OPEN");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider provider = provider(TicketingSystem.SERVICENOW);
        when(provider.fetchStatus(tenant, "INC0010005"))
                .thenReturn(Optional.of(new TicketStatus("Resolved", true)));

        FindingIncidentSyncService.SyncResult result = runSync(provider);

        ArgumentCaptor<FindingWorkflowUpdateRequest> captor =
                ArgumentCaptor.forClass(FindingWorkflowUpdateRequest.class);
        // Goes through the workflow service so the transition is audited and projections refresh.
        verify(findingWorkflowService).updateWorkflow(eq(finding.getId()), captor.capture());
        assertEquals("RESOLVED", captor.getValue().status());
        assertEquals(FindingIncidentSyncService.SYNC_ACTOR, captor.getValue().actor());
        assertEquals(1, result.findingsResolved());
    }

    /**
     * The loop breaker. A ticket-driven close must record itself as already reflected, or the
     * push side would immediately send that same resolution back to the ticket that caused it.
     */
    @Test
    void aTicketDrivenCloseIsNotEchoedBackToTheTicket() {
        Finding finding = finding("INC0010005", "servicenow", "In Progress", FindingStatus.OPEN, "OPEN");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider provider = provider(TicketingSystem.SERVICENOW);
        when(provider.fetchStatus(tenant, "INC0010005"))
                .thenReturn(Optional.of(new TicketStatus("Resolved", true)));

        runSync(provider);

        verify(finding).setIncidentPushedStatus("RESOLVED");
        verify(provider, never()).pushFindingStatus(any(), any(), any());
    }

    @Test
    void leavesAnAlreadyResolvedFindingAlone() {
        Finding finding = finding("INC0010005", "servicenow", "Resolved", FindingStatus.RESOLVED, "RESOLVED");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider provider = provider(TicketingSystem.SERVICENOW);
        when(provider.fetchStatus(tenant, "INC0010005"))
                .thenReturn(Optional.of(new TicketStatus("Resolved", true)));

        FindingIncidentSyncService.SyncResult result = runSync(provider);

        verify(findingWorkflowService, never()).updateWorkflow(any(), any());
        assertEquals(0, result.findingsResolved());
    }

    // ── Push: finding → ticket ───────────────────────────────────────────────

    @Test
    void resolvesTheTicketWhenTheFindingIsResolvedInScout() {
        Finding finding = finding("SEC-42", "jira", "In Progress", FindingStatus.RESOLVED, "OPEN");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider provider = provider(TicketingSystem.JIRA);
        when(provider.fetchStatus(tenant, "SEC-42"))
                .thenReturn(Optional.of(new TicketStatus("In Progress", false)));
        when(provider.pushFindingStatus(eq(tenant), eq("SEC-42"), any(TicketPush.class))).thenReturn(true);

        FindingIncidentSyncService.SyncResult result = runSync(provider);

        ArgumentCaptor<TicketPush> captor = ArgumentCaptor.forClass(TicketPush.class);
        verify(provider).pushFindingStatus(eq(tenant), eq("SEC-42"), captor.capture());
        assertEquals(TicketPush.Action.RESOLVE, captor.getValue().action());
        verify(finding).setIncidentPushedStatus("RESOLVED");
        assertEquals(1, result.pushed());
    }

    @Test
    void reopensTheTicketWhenAResolvedFindingIsReopened() {
        Finding finding = finding("SEC-42", "jira", "Done", FindingStatus.OPEN, "RESOLVED");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider provider = provider(TicketingSystem.JIRA);
        when(provider.fetchStatus(tenant, "SEC-42"))
                .thenReturn(Optional.of(new TicketStatus("Done", false)));
        when(provider.pushFindingStatus(eq(tenant), eq("SEC-42"), any(TicketPush.class))).thenReturn(true);

        runSync(provider);

        ArgumentCaptor<TicketPush> captor = ArgumentCaptor.forClass(TicketPush.class);
        verify(provider).pushFindingStatus(eq(tenant), eq("SEC-42"), captor.capture());
        assertEquals(TicketPush.Action.REOPEN, captor.getValue().action());
    }

    @Test
    void commentsRatherThanClosingWhenAFindingIsSuppressed() {
        Finding finding = finding("SEC-42", "jira", "In Progress", FindingStatus.SUPPRESSED, "OPEN");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider provider = provider(TicketingSystem.JIRA);
        when(provider.fetchStatus(tenant, "SEC-42"))
                .thenReturn(Optional.of(new TicketStatus("In Progress", false)));
        when(provider.pushFindingStatus(eq(tenant), eq("SEC-42"), any(TicketPush.class))).thenReturn(true);

        runSync(provider);

        ArgumentCaptor<TicketPush> captor = ArgumentCaptor.forClass(TicketPush.class);
        verify(provider).pushFindingStatus(eq(tenant), eq("SEC-42"), captor.capture());
        assertEquals(TicketPush.Action.COMMENT, captor.getValue().action());
    }

    /** Nothing has drifted, so the ticket must not be touched at all. */
    @Test
    void pushesNothingWhenTheTicketAlreadyReflectsTheFinding() {
        Finding finding = finding("SEC-42", "jira", "In Progress", FindingStatus.OPEN, "OPEN");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider provider = provider(TicketingSystem.JIRA);
        when(provider.fetchStatus(tenant, "SEC-42"))
                .thenReturn(Optional.of(new TicketStatus("In Progress", false)));

        FindingIncidentSyncService.SyncResult result = runSync(provider);

        verify(provider, never()).pushFindingStatus(any(), any(), any());
        assertEquals(0, result.pushed());
    }

    /** A failed push must not be recorded as done, so the next run retries it. */
    @Test
    void doesNotRecordAFailedPushAsReflected() {
        Finding finding = finding("SEC-42", "jira", "In Progress", FindingStatus.RESOLVED, "OPEN");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider provider = provider(TicketingSystem.JIRA);
        when(provider.fetchStatus(tenant, "SEC-42"))
                .thenReturn(Optional.of(new TicketStatus("In Progress", false)));
        when(provider.pushFindingStatus(eq(tenant), eq("SEC-42"), any(TicketPush.class))).thenReturn(false);

        FindingIncidentSyncService.SyncResult result = runSync(provider);

        verify(finding, never()).setIncidentPushedStatus(any());
        assertEquals(0, result.pushed());
        assertEquals(1, result.failed());
    }

    @Test
    void oneProviderThrowingOnPushDoesNotStopTheOthers() {
        Finding jiraFinding = finding("SEC-42", "jira", "In Progress", FindingStatus.RESOLVED, "OPEN");
        Finding snowFinding = finding("INC0010005", "servicenow", "In Progress", FindingStatus.RESOLVED, "OPEN");
        when(findings.findForIncidentSync()).thenReturn(List.of(jiraFinding, snowFinding));

        TicketingProvider jira = provider(TicketingSystem.JIRA);
        TicketingProvider serviceNow = provider(TicketingSystem.SERVICENOW);
        when(jira.fetchStatus(tenant, "SEC-42")).thenReturn(Optional.of(new TicketStatus("In Progress", false)));
        when(serviceNow.fetchStatus(tenant, "INC0010005"))
                .thenReturn(Optional.of(new TicketStatus("In Progress", false)));
        when(jira.pushFindingStatus(eq(tenant), eq("SEC-42"), any(TicketPush.class)))
                .thenThrow(new RuntimeException("connection reset"));
        when(serviceNow.pushFindingStatus(eq(tenant), eq("INC0010005"), any(TicketPush.class))).thenReturn(true);

        FindingIncidentSyncService.SyncResult result = runSync(jira, serviceNow);

        verify(snowFinding).setIncidentPushedStatus("RESOLVED");
        assertEquals(1, result.pushed());
        assertEquals(1, result.failed());
    }

    private FindingIncidentSyncService.SyncResult runSync(TicketingProvider... providers) {
        TicketingProviderRegistry registry = new TicketingProviderRegistry(List.of(providers));
        TicketingService ticketingService = new TicketingService(registry, findings);
        FindingIncidentSyncService service = new FindingIncidentSyncService(
                findings, registry, ticketingService, findingWorkflowService, tenantWorkRunner);

        doAnswer(invocation -> {
            invocation.getArgument(0, Consumer.class).accept(tenant);
            return null;
        }).when(tenantWorkRunner).forEachActiveTenant(any());

        return service.syncAll();
    }

    private TicketingProvider provider(TicketingSystem system) {
        TicketingProvider provider = mock(TicketingProvider.class);
        when(provider.system()).thenReturn(system);
        return provider;
    }

    private Finding finding(
            String incidentId,
            String provider,
            String incidentStatus,
            FindingStatus status,
            String pushedStatus
    ) {
        Finding finding = mock(Finding.class);
        when(finding.getId()).thenReturn(UUID.randomUUID());
        when(finding.getTenant()).thenReturn(tenant);
        when(finding.getIncidentId()).thenReturn(incidentId);
        when(finding.getIncidentProvider()).thenReturn(provider);
        when(finding.getIncidentStatus()).thenReturn(incidentStatus);
        when(finding.getStatus()).thenReturn(status);
        when(finding.getIncidentPushedStatus()).thenReturn(pushedStatus);
        when(finding.getDisplayId()).thenReturn("F-0000001");
        return finding;
    }
}
