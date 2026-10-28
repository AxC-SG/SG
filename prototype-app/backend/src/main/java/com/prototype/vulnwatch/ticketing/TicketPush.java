package com.prototype.vulnwatch.ticketing;

/**
 * A change Scout wants reflected on an existing ticket.
 *
 * @param action what to do to the ticket
 * @param note   operator-facing explanation, written as a work note or comment
 */
public record TicketPush(Action action, String note) {

    public enum Action {
        /** Move the ticket to a completed state. */
        RESOLVE,
        /** Move a completed ticket back into active work. */
        REOPEN,
        /** Leave the state alone and just record a note. */
        COMMENT
    }

    public static TicketPush resolve(String note) {
        return new TicketPush(Action.RESOLVE, note);
    }

    public static TicketPush reopen(String note) {
        return new TicketPush(Action.REOPEN, note);
    }

    public static TicketPush comment(String note) {
        return new TicketPush(Action.COMMENT, note);
    }
}
