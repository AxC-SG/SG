package com.prototype.vulnwatch.ticketing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class TicketingServiceTest {

    private final FindingRepository findings = mock(FindingRepository.class);
    private final Tenant tenant = mock(Tenant.class);
    private final UUID findingId = UUID.randomUUID();

    @Test
    void createsTheTicketInTheActiveSystemAndRecordsWhichSystemRaisedIt() {
        Finding finding = openFinding();
        when(findings.findById(findingId)).thenReturn(Optional.of(finding));

        TicketingProvider jira = provider(TicketingSystem.JIRA, true, new TicketRef(
                TicketingSystem.JIRA, "SEC-42", "10042",
                "https://acme.atlassian.net/browse/SEC-42", "Open", "created"));
        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(jira, provider(TicketingSystem.SERVICENOW, true, null))),
                findings);

        TicketRef ref = service.createTicketForFinding(tenant, findingId, TicketRequest.empty());

        assertEquals("SEC-42", ref.externalKey());
        verify(finding).setIncidentId("SEC-42");
        verify(finding).setIncidentStatus("Open");
        // Without this the daily sync would poll Jira keys against ServiceNow, or vice versa.
        verify(finding).setIncidentProvider("jira");
        verify(findings).save(finding);
    }

    @Test
    void fallsBackToServiceNowWhenJiraIsNotConfigured() {
        Finding finding = openFinding();
        when(findings.findById(findingId)).thenReturn(Optional.of(finding));

        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(
                        provider(TicketingSystem.JIRA, false, null),
                        provider(TicketingSystem.SERVICENOW, true, new TicketRef(
                                TicketingSystem.SERVICENOW, "INC0012345", "abc123",
                                "https://acme.service-now.com/incident.do?sys_id=abc123", "New", "created")))),
                findings);

        TicketRef ref = service.createTicketForFinding(tenant, findingId, TicketRequest.empty());

        assertEquals(TicketingSystem.SERVICENOW, ref.system());
        verify(finding).setIncidentProvider("servicenow");
    }

    @Test
    void refusesWhenNoTicketingSystemIsConfigured() {
        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(
                        provider(TicketingSystem.JIRA, false, null),
                        provider(TicketingSystem.SERVICENOW, false, null))),
                findings);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.createTicketForFinding(tenant, findingId, TicketRequest.empty()));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, ex.getStatusCode());
        // The finding is never even loaded, so a misconfigured tenant cannot mutate rows.
        verify(findings, never()).findById(any());
    }

    @Test
    void refusesToTicketAClosedFinding() {
        Finding finding = mock(Finding.class);
        when(finding.getStatus()).thenReturn(FindingStatus.RESOLVED);
        when(findings.findById(findingId)).thenReturn(Optional.of(finding));

        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(provider(TicketingSystem.JIRA, true, null))), findings);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.createTicketForFinding(tenant, findingId, TicketRequest.empty()));

        assertEquals(HttpStatus.CONFLICT, ex.getStatusCode());
        verify(findings, never()).save(any());
    }

    /** A second ticket would overwrite incident_id and orphan the first one. */
    @Test
    void refusesToTicketAFindingThatAlreadyHasOne() {
        Finding finding = mock(Finding.class);
        when(finding.getStatus()).thenReturn(FindingStatus.OPEN);
        when(finding.getIncidentId()).thenReturn("INC0012345");
        when(finding.getIncidentProvider()).thenReturn("servicenow");
        when(findings.findById(findingId)).thenReturn(Optional.of(finding));

        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(provider(TicketingSystem.JIRA, true, null))), findings);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.createTicketForFinding(tenant, findingId, TicketRequest.empty()));

        assertEquals(HttpStatus.CONFLICT, ex.getStatusCode());
        assertTrue(ex.getReason() != null && ex.getReason().contains("INC0012345"));
        verify(findings, never()).save(any());
    }

    @Test
    void reportsNotFoundForAnUnknownFinding() {
        when(findings.findById(findingId)).thenReturn(Optional.empty());
        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(provider(TicketingSystem.JIRA, true, null))), findings);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.createTicketForFinding(tenant, findingId, TicketRequest.empty()));

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
    }

    /**
     * Tickets raised before provider tracking existed carry no provider and all came from
     * ServiceNow. Treating them as unowned would silently drop them from status sync.
     */
    @Test
    void treatsATicketWithNoRecordedProviderAsServiceNow() {
        TicketingService service = new TicketingService(new TicketingProviderRegistry(List.of()), findings);
        Finding legacy = mock(Finding.class);
        when(legacy.getIncidentId()).thenReturn("INC0000001");
        when(legacy.getIncidentProvider()).thenReturn(null);

        assertEquals(TicketingSystem.SERVICENOW, service.owningSystem(legacy).orElseThrow());
    }

    @Test
    void reportsNoOwningSystemForAFindingWithoutATicket() {
        TicketingService service = new TicketingService(new TicketingProviderRegistry(List.of()), findings);
        Finding untouched = mock(Finding.class);
        when(untouched.getIncidentId()).thenReturn(null);

        assertTrue(service.owningSystem(untouched).isEmpty());
        assertTrue(service.owningSystem(null).isEmpty());
    }

    @Test
    void statusNamesTheActiveSystemAndTheOnesItOutranks() {
        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(
                        provider(TicketingSystem.SERVICENOW, true, null),
                        provider(TicketingSystem.JIRA, true, null))),
                findings);

        TicketingService.TicketingStatus status = service.status(tenant);

        assertEquals(TicketingSystem.JIRA, status.active());
        assertEquals(List.of(TicketingSystem.SERVICENOW), status.overridden());
    }

    private Finding openFinding() {
        Finding finding = mock(Finding.class);
        when(finding.getStatus()).thenReturn(FindingStatus.OPEN);
        when(finding.getIncidentId()).thenReturn(null);
        return finding;
    }

    private TicketingProvider provider(TicketingSystem system, boolean configured, TicketRef result) {
        TicketingProvider provider = mock(TicketingProvider.class);
        when(provider.system()).thenReturn(system);
        when(provider.isConfigured(eq(tenant))).thenReturn(configured);
        if (result != null) {
            when(provider.createForFinding(eq(tenant), any(Finding.class), any(TicketRequest.class)))
                    .thenReturn(result);
        }
        return provider;
    }
}
