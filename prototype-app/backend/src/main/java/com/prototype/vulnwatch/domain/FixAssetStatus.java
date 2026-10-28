package com.prototype.vulnwatch.domain;

/** State of one fix on one asset, as the reporting tool (or analyst scope) sees it. */
public enum FixAssetStatus {
    MISSING,
    SCHEDULED,
    IN_PROGRESS,
    INSTALLED,
    FAILED,
    PENDING_REBOOT,
    NOT_APPLICABLE,
    SUPERSEDED,
    /** A workaround or compensating control scoped onto the asset by an analyst. */
    APPLIED;

    /** Counts toward coverage: the asset is remediated by this fix. */
    public boolean remediated() {
        return this == INSTALLED || this == APPLIED;
    }

    /** Counts toward the applicable denominator for coverage. */
    public boolean applicable() {
        return this != NOT_APPLICABLE && this != SUPERSEDED;
    }
}
