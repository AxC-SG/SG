package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.ticketing.TicketStatus;
import com.prototype.vulnwatch.ticketing.TicketingProvider;
import com.prototype.vulnwatch.ticketing.TicketingProviderRegistry;
import com.prototype.vulnwatch.ticketing.TicketingService;
import com.prototype.vulnwatch.ticketing.TicketingSystem;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * The status sync must ask each ticket's own system about it. A tenant that switched from
 * ServiceNow to Jira still holds ServiceNow incident numbers on older findings, and polling
 * Jira for {@code INC0010005} would fail on every run.
 */
class FindingIncidentSyncServiceProviderRoutingTest {

    private final FindingRepository findings = mock(FindingRepository.class);
    private final Tenant tenant = mock(Tenant.class);
    private final TenantWorkRunner tenantWorkRunner = mock(TenantWorkRunner.class);
    private final FindingWorkflowService findingWorkflowService = mock(FindingWorkflowService.class);

    @Test
    void pollsEachTicketAgainstTheSystemThatRaisedIt() {
        Finding jiraFinding = finding("SEC-42", "jira", "Open");
        Finding serviceNowFinding = finding("INC0010005", "servicenow", "New");
        Finding legacyFinding = finding("INC0000001", null, "New");

        when(findings.findForIncidentSync())
                .thenReturn(List.of(jiraFinding, serviceNowFinding, legacyFinding));

        TicketingProvider jira = provider(TicketingSystem.JIRA);
        TicketingProvider serviceNow = provider(TicketingSystem.SERVICENOW);
        when(jira.fetchStatus(tenant, "SEC-42")).thenReturn(Optional.of(new TicketStatus("In Progress", false)));
        when(serviceNow.fetchStatus(tenant, "INC0010005")).thenReturn(Optional.of(new TicketStatus("Resolved", false)));
        when(serviceNow.fetchStatus(tenant, "INC0000001")).thenReturn(Optional.of(new TicketStatus("Closed", false)));

        FindingIncidentSyncService.SyncResult result = runSync(jira, serviceNow);

        verify(jiraFinding).setIncidentStatus("In Progress");
        verify(serviceNowFinding).setIncidentStatus("Resolved");
        // A ticket with no recorded provider predates tracking and belongs to ServiceNow.
        verify(legacyFinding).setIncidentStatus("Closed");
        // The Jira key is never offered to ServiceNow, nor the incident numbers to Jira.
        verify(jira, never()).fetchStatus(tenant, "INC0010005");
        verify(jira, never()).fetchStatus(tenant, "INC0000001");
        verify(serviceNow, never()).fetchStatus(tenant, "SEC-42");
        assertEquals(3, result.updated());
        assertEquals(0, result.failed());
    }

    @Test
    void leavesTheLastKnownStatusInPlaceWhenAFetchFails() {
        Finding finding = finding("SEC-42", "jira", "In Progress");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider jira = provider(TicketingSystem.JIRA);
        when(jira.fetchStatus(tenant, "SEC-42")).thenReturn(Optional.empty());

        FindingIncidentSyncService.SyncResult result = runSync(jira);

        verify(finding, never()).setIncidentStatus(any());
        assertEquals(0, result.updated());
        assertEquals(1, result.failed());
    }

    /** A provider that throws must not abort the whole run for other tickets. */
    @Test
    void keepsGoingWhenOneProviderThrows() {
        Finding jiraFinding = finding("SEC-42", "jira", "Open");
        Finding serviceNowFinding = finding("INC0010005", "servicenow", "New");
        when(findings.findForIncidentSync()).thenReturn(List.of(jiraFinding, serviceNowFinding));

        TicketingProvider jira = provider(TicketingSystem.JIRA);
        TicketingProvider serviceNow = provider(TicketingSystem.SERVICENOW);
        when(jira.fetchStatus(tenant, "SEC-42")).thenThrow(new RuntimeException("connection reset"));
        when(serviceNow.fetchStatus(tenant, "INC0010005")).thenReturn(Optional.of(new TicketStatus("Resolved", false)));

        FindingIncidentSyncService.SyncResult result = runSync(jira, serviceNow);

        verify(serviceNowFinding).setIncidentStatus("Resolved");
        assertEquals(1, result.updated());
        assertEquals(1, result.failed());
    }

    @Test
    void countsFindingsAsFailedWhenNoProviderIsRegisteredForTheirSystem() {
        Finding jiraFinding = finding("SEC-42", "jira", "Open");
        when(findings.findForIncidentSync()).thenReturn(List.of(jiraFinding));

        FindingIncidentSyncService.SyncResult result = runSync(provider(TicketingSystem.SERVICENOW));

        verify(jiraFinding, never()).setIncidentStatus(any());
        assertEquals(1, result.failed());
    }

    @Test
    void reportsUnchangedWhenTheStatusHasNotMoved() {
        Finding finding = finding("SEC-42", "jira", "In Progress");
        when(findings.findForIncidentSync()).thenReturn(List.of(finding));

        TicketingProvider jira = provider(TicketingSystem.JIRA);
        when(jira.fetchStatus(tenant, "SEC-42")).thenReturn(Optional.of(new TicketStatus("In Progress", false)));

        FindingIncidentSyncService.SyncResult result = runSync(jira);

        verify(finding, never()).setIncidentStatus(any());
        assertEquals(0, result.updated());
        assertEquals(1, result.unchanged());
    }

    private FindingIncidentSyncService.SyncResult runSync(TicketingProvider... providers) {
        TicketingProviderRegistry registry = new TicketingProviderRegistry(List.of(providers));
        TicketingService ticketingService = new TicketingService(registry, findings);
        FindingIncidentSyncService service =
                new FindingIncidentSyncService(findings, registry, ticketingService,
                        findingWorkflowService, tenantWorkRunner);

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

    private Finding finding(String incidentId, String provider, String currentStatus) {
        Finding finding = mock(Finding.class);
        when(finding.getTenant()).thenReturn(tenant);
        when(finding.getIncidentId()).thenReturn(incidentId);
        when(finding.getIncidentProvider()).thenReturn(provider);
        when(finding.getIncidentStatus()).thenReturn(currentStatus);
        return finding;
    }
}
