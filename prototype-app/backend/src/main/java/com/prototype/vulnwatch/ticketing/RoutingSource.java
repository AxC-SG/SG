package com.prototype.vulnwatch.ticketing;

/** Where a ticket's assignment group came from (Phase 0B §4.9); stored on {@code finding_ticket_attempts}. */
public enum RoutingSource {
    TEAM_MAPPING,
    TENANT_DEFAULT,
    USER_SELECTED,
    OVERRIDE,
    /** The pre-routing path: the read wave is off or the finding's domain is not canonical. */
    LEGACY
}
