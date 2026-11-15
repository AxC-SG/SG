package com.prototype.vulnwatch.domain;

/** How a campaign's membership was defined (Phase 0B §4.2): from CVE IDs or from finding IDs. */
public enum CampaignScopeKind {
    CVE,
    FINDINGS
}
