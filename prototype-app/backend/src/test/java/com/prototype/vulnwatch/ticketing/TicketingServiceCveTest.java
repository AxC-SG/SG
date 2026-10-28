package com.prototype.vulnwatch.ticketing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
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
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * CVE-level ticketing. This path had no coverage at all before the framework took it over, and
 * it is the busier of the two: the CVE Assessment Workbench raises tickets through it whenever
 * findings are created.
 */
class TicketingServiceCveTest {

    private final FindingRepository findings = mock(FindingRepository.class);
    private final Tenant tenant = mock(Tenant.class);

    @Test
    void raisesOneTicketPerAssignmentGroup() {
        TicketingProvider provider = provider(TicketingSystem.SERVICENOW);
        TicketingService service = serviceWith(provider);

        List<TicketRef> refs = service.createTicketsForCve(tenant, "CVE-2026-1", request(
                asset("c1", "web-01", "openssl", "Platform Team"),
                asset("c2", "web-02", "openssl", "Platform Team"),
                asset("c3", "db-01", "openssl", "Database Team")));

        assertEquals(2, refs.size());
        ArgumentCaptor<CveTicketRequest> captor = ArgumentCaptor.forClass(CveTicketRequest.class);
        verify(provider, org.mockito.Mockito.times(2)).createForCve(eq(tenant), captor.capture());
        assertEquals(List.of("Platform Team", "Database Team"),
                captor.getAllValues().stream().map(CveTicketRequest::assignmentGroup).toList());
        assertEquals(2, captor.getAllValues().get(0).safeAssets().size());
        assertEquals(1, captor.getAllValues().get(1).safeAssets().size());
    }

    @Test
    void groupsAssetsWithNoAssignmentGroupByPackage() {
        TicketingProvider provider = provider(TicketingSystem.SERVICENOW);
        TicketingService service = serviceWith(provider);

        List<TicketRef> refs = service.createTicketsForCve(tenant, "CVE-2026-1", request(
                asset("c1", "web-01", "openssl", null),
                asset("c2", "web-02", "openssl", null),
                asset("c3", "db-01", "glibc", null)));

        assertEquals(2, refs.size());
        ArgumentCaptor<CveTicketRequest> captor = ArgumentCaptor.forClass(CveTicketRequest.class);
        verify(provider, org.mockito.Mockito.times(2)).createForCve(eq(tenant), captor.capture());
        // No group is known, so the provider applies its own default rather than inventing one here.
        assertTrue(captor.getAllValues().stream().allMatch(r -> r.assignmentGroup() == null));
        assertEquals(List.of("openssl", "openssl"),
                captor.getAllValues().get(0).safeAssets().stream().map(TicketAsset::packageName).toList());
        assertEquals(List.of("glibc"),
                captor.getAllValues().get(1).safeAssets().stream().map(TicketAsset::packageName).toList());
    }

    @Test
    void keepsGroupedAndUngroupedAssetsInSeparateTickets() {
        TicketingProvider provider = provider(TicketingSystem.SERVICENOW);
        TicketingService service = serviceWith(provider);

        List<TicketRef> refs = service.createTicketsForCve(tenant, "CVE-2026-1", request(
                asset("c1", "web-01", "openssl", "Platform Team"),
                asset("c2", "db-01", "glibc", null)));

        assertEquals(2, refs.size());
    }

    /** A CVE with no correlated assets still deserves one ticket, not silence. */
    @Test
    void raisesASingleTicketWhenNoAssetsAreSupplied() {
        TicketingProvider provider = provider(TicketingSystem.SERVICENOW);
        TicketingService service = serviceWith(provider);

        assertEquals(1, service.createTicketsForCve(tenant, "CVE-2026-1", request()).size());
        verify(findings, never()).saveAll(anyList());
    }

    /**
     * The whole point of routing this path through the framework: a tenant with Jira enabled
     * must get Jira issues for CVEs too, not ServiceNow incidents.
     */
    @Test
    void routesCveTicketsToJiraWhenJiraIsActive() {
        TicketingProvider serviceNow = provider(TicketingSystem.SERVICENOW);
        TicketingProvider jira = provider(TicketingSystem.JIRA);
        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(serviceNow, jira)), findings);

        List<TicketRef> refs = service.createTicketsForCve(tenant, "CVE-2026-1", request(
                asset("c1", "web-01", "openssl", "Platform Team")));

        assertEquals(TicketingSystem.JIRA, refs.get(0).system());
        verify(serviceNow, never()).createForCve(any(), any());
    }

    @Test
    void linksMatchingFindingsWithTheProviderThatRaisedTheTicket() {
        TicketingProvider provider = provider(TicketingSystem.JIRA);
        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(provider)), findings);

        UUID componentId = UUID.randomUUID();
        Finding finding = mock(Finding.class);
        when(finding.getStatus()).thenReturn(FindingStatus.OPEN);
        when(findings.findByComponentIdInAndVulnerabilityCveId(List.of(componentId), "CVE-2026-1"))
                .thenReturn(List.of(finding));

        service.createTicketsForCve(tenant, "CVE-2026-1", request(
                asset(componentId.toString(), "web-01", "openssl", "Platform Team")));

        verify(finding).setIncidentId("TICKET-1");
        verify(finding).setIncidentProvider("jira");
        // Seeding the watermark stops the next sync pushing a redundant update for a ticket
        // that was just created from this very status.
        verify(finding).setIncidentPushedStatus("OPEN");
        verify(findings).saveAll(anyList());
    }

    /** A malformed component id must not abort ticket creation for the rest of the group. */
    @Test
    void ignoresUnparseableComponentIdsWhenLinking() {
        TicketingProvider provider = provider(TicketingSystem.SERVICENOW);
        TicketingService service = serviceWith(provider);

        service.createTicketsForCve(tenant, "CVE-2026-1", request(
                asset("not-a-uuid", "web-01", "openssl", "Platform Team")));

        verify(findings, never()).findByComponentIdInAndVulnerabilityCveId(anyList(), anyString());
    }

    @Test
    void refusesWhenNoTicketingSystemIsConfigured() {
        TicketingProvider provider = mock(TicketingProvider.class);
        when(provider.system()).thenReturn(TicketingSystem.SERVICENOW);
        when(provider.isConfigured(tenant)).thenReturn(false);
        TicketingService service = new TicketingService(
                new TicketingProviderRegistry(List.of(provider)), findings);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.createTicketsForCve(tenant, "CVE-2026-1", request()));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, ex.getStatusCode());
    }

    private TicketingService serviceWith(TicketingProvider provider) {
        return new TicketingService(new TicketingProviderRegistry(List.of(provider)), findings);
    }

    private TicketingProvider provider(TicketingSystem system) {
        TicketingProvider provider = mock(TicketingProvider.class);
        when(provider.system()).thenReturn(system);
        when(provider.isConfigured(tenant)).thenReturn(true);
        when(provider.createForCve(eq(tenant), any(CveTicketRequest.class))).thenReturn(
                new TicketRef(system, "TICKET-1", "1", "https://example.test/TICKET-1", "New", "created"));
        return provider;
    }

    private static CveTicketRequest request(TicketAsset... assets) {
        return new CveTicketRequest("CVE-2026-1", null, "HIGH", "HIGH", null, null, null, null,
                List.of(assets));
    }

    private static TicketAsset asset(String componentId, String name, String pkg, String group) {
        return new TicketAsset(componentId, name, "sys-" + name, "HOST", pkg, "1.0", group);
    }
}
