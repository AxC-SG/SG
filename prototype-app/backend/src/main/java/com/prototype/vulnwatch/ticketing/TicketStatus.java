package com.prototype.vulnwatch.ticketing;

/**
 * A ticket's current state, as the owning system reports it.
 *
 * @param label    the provider's own wording, shown to operators unchanged
 *                 ("In Progress", "Resolved", "Done")
 * @param resolved whether the provider considers the work finished
 *
 * <p>{@code resolved} is decided by the provider at fetch time rather than by matching the
 * label later. ServiceNow reports a numeric state code and Jira reports a status category
 * alongside a freely renameable name, so inferring completion from the label alone would
 * break on any instance with a customised workflow.
 */
public record TicketStatus(String label, boolean resolved) {

    public static TicketStatus of(String label, boolean resolved) {
        return new TicketStatus(label, resolved);
    }
}
