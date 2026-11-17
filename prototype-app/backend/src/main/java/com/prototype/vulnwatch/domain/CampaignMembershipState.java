package com.prototype.vulnwatch.domain;

/** Whether every in-scope member has been materialized into campaign_findings (Phase 0B §4.2). */
public enum CampaignMembershipState {
    MATERIALIZING,
    COMPLETE
}
