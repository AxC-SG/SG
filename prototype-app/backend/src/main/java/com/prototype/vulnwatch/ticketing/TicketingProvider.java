package com.prototype.vulnwatch.ticketing;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Optional;

/**
 * One external ticketing system, behind a provider-neutral contract.
 *
 * <p>Implementations perform the remote call and nothing else. They must not write to
 * {@code findings} — {@link TicketingService} owns that, so every provider persists the same
 * fields in the same transaction and a new provider cannot forget to record which system
 * created the ticket.
 */
public interface TicketingProvider {

    TicketingSystem system();

    /**
     * Whether this tenant has enough configuration for ticket creation to succeed.
     * Must not make a remote call — this is evaluated on every ticket creation and on
     * connector listing.
     */
    boolean isConfigured(Tenant tenant);

    /**
     * Creates a ticket for a single finding.
     *
     * @throws org.springframework.web.server.ResponseStatusException if the tenant is not
     *         configured, or the remote system rejects or mangles the request
     */
    TicketRef createForFinding(Tenant tenant, Finding finding, TicketRequest request);

    /**
     * Creates one ticket covering a CVE and a group of affected assets.
     *
     * <p>The grouping decision belongs to {@link TicketingService}; a provider receives an
     * already-partitioned group and renders exactly one ticket for it.
     */
    TicketRef createForCve(Tenant tenant, CveTicketRequest request);

    /**
     * Current state of an existing ticket.
     *
     * <p>Returns empty when the ticket cannot be read, so a transient outage leaves the last
     * known status in place rather than overwriting it. Implementations decide
     * {@link TicketStatus#resolved()} themselves, from whatever the provider exposes — a
     * numeric state code, a status category — never by matching the display label.
     */
    Optional<TicketStatus> fetchStatus(Tenant tenant, String externalKey);

    /**
     * Reflects a Scout-side workflow change on an existing ticket.
     *
     * <p>Best effort by contract: returns {@code false} when the change could not be applied
     * (the remote system rejected it, or offers no route to that state) rather than throwing.
     * A ticket that cannot be transitioned must not block the sync for every other ticket, and
     * must not be recorded as pushed — {@link TicketingService} retries it on the next run.
     */
    boolean pushFindingStatus(Tenant tenant, String externalKey, TicketPush push);
}
