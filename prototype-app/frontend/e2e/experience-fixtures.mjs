// Deterministic fixtures for the UI 2.0 remaining-experience sweep (P7): the exposure dashboard,
// the CVE dashboard (/vuln-repo), campaigns list/detail, tenant operations views, the platform
// console operations view and the public authentication entry points (login, password setup,
// demo and workspace invites).
//
// Shapes follow frontend/src/features/dashboard/types.ts (exposure summary, grid exposure),
// features/vuln-repo-dashboard/types.ts (the EOL summary comes from inventory-fixtures.mjs), features/campaigns/types.ts,
// features/operations/types.ts and features/admin/types.ts (invite validation, auth token).
// All names are fictitious, hosts use example.test, and tokens are opaque fixture strings.
// Writes return canned results; nothing is persisted. Not authenticated evidence.

import { FIXED_TIME } from './time.mjs';

const BASE = FIXED_TIME;
const day = 86_400_000;
const iso = (offsetDays) => new Date(BASE + offsetDays * day).toISOString();

// ── Exported scenario constants ─────────────────────────────────────────────
export const PRIMARY_CAMPAIGN_ID = 'campaign-openssl-q4';
export const BLOCKED_CAMPAIGN_ID = 'campaign-log4j-legacy';
export const CRITICAL_CVE_ID = 'CVE-2026-31337';
export const EXPOSED_HOST_ID = 'asset-host-payments-01';
export const LOGIN_REJECTED_PASSWORD = 'wrong-password';
export const LOGIN_REJECTED_MESSAGE = 'Invalid email or password (fixture).';
export const VALID_INVITE_TOKEN = 'fixture-invite-token';
export const DELIVERY_ERROR_INVITE_TOKEN = 'fixture-delivery-error-token';
export const EXPIRED_INVITE_TOKEN = 'fixture-expired-token';
export const EXPIRED_INVITE_MESSAGE = 'This invite has expired (fixture).';
export const SETUP_TOKEN = 'fixture-setup-token';
export const FIXTURE_AUTH_TOKEN = 'fixture-session-token';

const ok = (json) => ({ status: 200, json });
const noContent = { status: 204, body: '' };
const notFound = { status: 404, json: { message: 'Not found (fixture)' } };
const parse = (body) => { try { return body ? JSON.parse(body) : {}; } catch { return {}; } };

// ── Exposure dashboard ──────────────────────────────────────────────────────
const exposureSummary = {
  openFindings: 1223,
  criticalFindings: 84,
  openCritical: 84,
  openHigh: 312,
  openMedium: 586,
  openLow: 241,
  averageOpenRiskScore: 6.2,
  topAssetsAtRisk: [{ key: 'payments-api-01.example.test', count: 142 }],
};

const gridExposure = {
  rows: [
    { assetType: 'HOST', critical: 41, high: 168, medium: 302, low: 117, total: 628 },
    { assetType: 'APPLICATION', critical: 22, high: 74, medium: 151, low: 66, total: 313 },
    { assetType: 'CONTAINER_IMAGE', critical: 18, high: 61, medium: 104, low: 42, total: 225 },
    { assetType: 'CLOUD_RESOURCE', critical: 3, high: 9, medium: 29, low: 16, total: 57 },
  ],
};

export const vulnRepoDashboard = {
  generatedAt: iso(0),
  summaryCards: {
    trackedCount: 248_316,
    trackedAddedLastWeek: 812,
    applicableCount: 1_942,
    applicableAddedLastWeek: 37,
    impactedInvestigationDoneCount: 286,
    impactedAddedLastWeek: 11,
    remediationCveCount: 74,
    needsAttentionCount: 58,
    criticalCount: 9_412,
    exploitCount: 29,
    exploitCoveragePercent: 10,
    impactedCriticalCount: 31,
    impactedHighCount: 117,
    impactedMediumCount: 102,
    impactedLowCount: 36,
    impactedKevCount: 12,
    kevAddedLastWeek: 2,
    criticalUninvestigatedCount: 6,
    kevReinvestigationCount: 3,
  },
  severityBreakdown: [
    { severity: 'CRITICAL', count: 31 },
    { severity: 'HIGH', count: 117 },
    { severity: 'MEDIUM', count: 102 },
    { severity: 'LOW', count: 36 },
  ],
  resolutionStatus: { unresolvedCount: 412, resolvedCount: 268, inProgressCount: 131, acceptedRiskCount: 24 },
  criticalUnresolved: [
    { externalId: CRITICAL_CVE_ID, title: 'OpenSSL X.509 name-constraint bypass enables certificate spoofing', severity: 'CRITICAL', statusLabel: 'Impacted', exploitKnown: true, findingCount: 64 },
    { externalId: 'CVE-2026-28810', title: 'glibc iconv buffer overflow in charset conversion', severity: 'CRITICAL', statusLabel: 'Impacted', exploitKnown: false, findingCount: 41 },
    { externalId: 'CVE-2026-27104', title: 'Kubernetes kubelet path traversal via subPath volume mounts', severity: 'CRITICAL', statusLabel: 'Under investigation', exploitKnown: true, findingCount: 18 },
    { externalId: 'CVE-2026-19022', title: 'Apache Tomcat request smuggling through malformed chunk extensions with an unusually long title that must wrap without widening the card', severity: 'CRITICAL', statusLabel: 'Impacted', exploitKnown: false, findingCount: 9 },
  ],
  topAffectedSoftware: [
    { softwareIdentityId: 'si-openssl', software: 'openssl', vendor: 'OpenSSL Project', cveCount: 14, criticalCount: 3, highCount: 6, impactedAssetCount: 212, highestSeverity: 'CRITICAL' },
    { softwareIdentityId: 'si-glibc', software: 'glibc', vendor: 'GNU', cveCount: 9, criticalCount: 1, highCount: 4, impactedAssetCount: 188, highestSeverity: 'CRITICAL' },
    { softwareIdentityId: 'si-tomcat', software: 'tomcat', vendor: 'Apache Software Foundation', cveCount: 7, criticalCount: 1, highCount: 3, impactedAssetCount: 46, highestSeverity: 'HIGH' },
    { softwareIdentityId: 'si-node', software: 'node', vendor: 'OpenJS Foundation', cveCount: 5, criticalCount: 0, highCount: 2, impactedAssetCount: 73, highestSeverity: 'HIGH' },
    { softwareIdentityId: 'si-curl', software: 'curl', vendor: 'curl', cveCount: 3, criticalCount: 0, highCount: 0, impactedAssetCount: 301, highestSeverity: 'MEDIUM' },
  ],
  recentAdvisories: [
    { externalId: CRITICAL_CVE_ID, title: 'OpenSSL X.509 name-constraint bypass', descriptionSnippet: 'A crafted certificate chain can bypass name constraints.', severity: 'CRITICAL', source: 'NVD', publishedAt: iso(-3), lastModifiedAt: iso(-1) },
    { externalId: 'GHSA-7f2x-9q3m-wx4p', title: 'Prototype pollution in a popular merge helper', descriptionSnippet: 'Untrusted keys can modify Object.prototype.', severity: 'HIGH', source: 'GHSA', publishedAt: iso(-2), lastModifiedAt: iso(-2) },
    { externalId: 'CVE-2026-28810', title: 'glibc iconv buffer overflow', descriptionSnippet: 'Out-of-bounds write when converting to ISO-2022-CN-EXT.', severity: 'CRITICAL', source: 'NVD', publishedAt: iso(-6), lastModifiedAt: iso(-4) },
  ],
  impactedAssets: [
    { assetId: EXPOSED_HOST_ID, assetName: 'payments-api-01', assetType: 'HOST', identifier: 'payments-api-01.example.test', environment: 'production', cveCount: 23 },
    { assetId: 'asset-host-ledger-02', assetName: 'ledger-db-02', assetType: 'HOST', identifier: 'ledger-db-02.example.test', environment: 'production', cveCount: 17 },
    { assetId: 'asset-host-edge-gw', assetName: 'edge-gateway-eu-west-1a-very-long-hostname-for-wrapping', assetType: 'HOST', identifier: 'edge-gateway-eu-west-1a.example.test', environment: 'production', cveCount: 11 },
    { assetId: 'asset-host-build-07', assetName: 'build-runner-07', assetType: 'HOST', identifier: 'build-runner-07.example.test', cveCount: 6 },
  ],
};

const platformSourceStats = {
  sources: {
    NVD: { total: 248_316, critical: 9_412, high: 41_207, medium: 118_330, low: 62_011, unknown: 17_356 },
    GHSA: { total: 21_904, critical: 1_212, high: 6_418, medium: 10_066, low: 3_802, unknown: 406 },
    KEV: { total: 1_284, critical: 512, high: 604, medium: 151, low: 9, unknown: 8 },
  },
};

// ── Campaigns ───────────────────────────────────────────────────────────────
function summary(overrides) {
  return {
    summary: null, status: 'ACTIVE', dueAt: iso(21), startedAt: iso(-14), updatedAt: iso(-1), cveIds: [],
    totalFindings: 0, resolvedFindings: 0, openFindings: 0, assetCount: 0, exceptionCount: 0,
    notifyGroupCount: 0, watchlistCount: 0, completionPercent: 0, ...overrides,
  };
}

export const campaigns = [
  summary({ id: PRIMARY_CAMPAIGN_ID, name: 'OpenSSL Q4 remediation sprint', summary: 'Roll the patched OpenSSL build across payments and ledger hosts.',
    cveIds: [CRITICAL_CVE_ID, 'CVE-2026-28810'], totalFindings: 64, resolvedFindings: 22, openFindings: 42, assetCount: 18,
    exceptionCount: 1, notifyGroupCount: 2, watchlistCount: 2, completionPercent: 34 }),
  summary({ id: BLOCKED_CAMPAIGN_ID, name: 'Legacy log4j decommission', summary: 'Retire batch hosts still bundling log4j 1.x.',
    status: 'BLOCKED', cveIds: ['CVE-2021-44228'], totalFindings: 12, resolvedFindings: 3, openFindings: 9, assetCount: 4,
    notifyGroupCount: 1, watchlistCount: 1, completionPercent: 25, dueAt: iso(-3) }),
  summary({ id: 'campaign-tomcat-draft', name: 'Tomcat request-smuggling patch', status: 'DRAFT', cveIds: ['CVE-2026-19022'], startedAt: null }),
  summary({ id: 'campaign-kubelet-review', name: 'Kubelet subPath hardening', status: 'IN_REVIEW', cveIds: ['CVE-2026-27104'],
    totalFindings: 18, resolvedFindings: 18, openFindings: 0, assetCount: 6, completionPercent: 100 }),
  summary({ id: 'campaign-curl-closed', name: 'curl 8.x upgrade', status: 'CLOSED', cveIds: ['CVE-2026-11002'],
    totalFindings: 40, resolvedFindings: 40, openFindings: 0, assetCount: 31, completionPercent: 100, dueAt: iso(-30) }),
];

function detailFor(campaign) {
  const primary = campaign.id === PRIMARY_CAMPAIGN_ID;
  const findings = primary ? [
    { findingId: 'f-uuid-1001', displayId: 'F-1001', vulnerabilityId: CRITICAL_CVE_ID, assetName: 'payments-api-01', assetIdentifier: 'payments-api-01.example.test',
      packageName: 'openssl', severity: 'CRITICAL', ownerGroup: 'Payments Platform', status: 'IMPACTED', dueAt: iso(7), incidentId: 'INC0012001' },
    { findingId: 'f-uuid-1002', displayId: 'F-1002', vulnerabilityId: CRITICAL_CVE_ID, assetName: 'ledger-db-02', assetIdentifier: 'ledger-db-02.example.test',
      packageName: 'openssl', severity: 'CRITICAL', ownerGroup: 'Data Platform', status: 'IN_PROGRESS', dueAt: iso(7), incidentId: null },
    { findingId: 'f-uuid-1003', displayId: 'F-1003', vulnerabilityId: 'CVE-2026-28810', assetName: 'build-runner-07', assetIdentifier: 'build-runner-07.example.test',
      packageName: 'glibc', severity: 'HIGH', ownerGroup: null, status: 'RESOLVED', dueAt: iso(-2), incidentId: null },
  ] : [];
  return {
    summary: campaign,
    vulnerabilities: campaign.cveIds.map((externalId, index) => ({ externalId, title: index === 0 ? 'OpenSSL X.509 name-constraint bypass' : 'glibc iconv buffer overflow', severity: index === 0 ? 'CRITICAL' : 'HIGH' })),
    notifyGroups: primary ? [
      { id: 'ng-payments', groupName: 'Payments Platform', groupEmail: 'payments-oncall@example.test', roleLabel: 'Owner group', triggerSummary: 'Status changes, overdue findings', notificationsPaused: false },
      { id: 'ng-data', groupName: 'Data Platform', groupEmail: null, roleLabel: 'Contributor', triggerSummary: null, notificationsPaused: true },
    ] : [],
    watchlist: primary ? [
      { id: 'wl-ciso', entryType: 'USER', label: 'Riley Security Lead', email: 'riley@example.test', triggerPolicy: 'ALL_EVENTS', active: true },
      { id: 'wl-cab', entryType: 'GROUP', label: 'Change Advisory Board', email: 'cab@example.test', triggerPolicy: 'STATUS_ONLY', active: true },
    ] : [],
    notes: primary ? [{ id: 'note-1', author: 'fixture.analyst@example.test', body: 'Payments hosts patched in the canary ring; ledger next.', createdAt: iso(-2) }] : [],
    exceptions: primary ? [{ id: 'exc-1', findingDisplayId: 'F-1002', assetName: 'ledger-db-02', packageName: 'openssl', title: 'Defer ledger DB until freeze ends',
      reason: 'Quarter-end change freeze.', status: 'PENDING_DECISION', requestedBy: 'fixture.analyst@example.test', requestedAt: iso(-1), decisionDueAt: iso(3),
      decisionedBy: null, decisionedAt: null }] : [],
    activity: [
      { id: 'act-1', activityType: 'CREATED', actor: 'fixture.analyst@example.test', body: 'Campaign created.', createdAt: iso(-14) },
      { id: 'act-2', activityType: 'STATUS_CHANGED', actor: 'fixture.analyst@example.test', body: `Status changed to ${campaign.status}.`, createdAt: iso(-13) },
    ],
    deliveryAttempts: [],
    findings,
    assets: primary ? [
      { assetId: EXPOSED_HOST_ID, assetName: 'payments-api-01', assetIdentifier: 'payments-api-01.example.test', environment: 'production', supportGroup: 'Payments Platform', openFindings: 3, resolvedFindings: 1 },
      { assetId: 'asset-host-ledger-02', assetName: 'ledger-db-02', assetIdentifier: 'ledger-db-02.example.test', environment: 'production', supportGroup: null, openFindings: 2, resolvedFindings: 0 },
    ] : [],
    evidence: findings.map((row) => ({ cveId: row.vulnerabilityId, displayId: row.displayId, assetName: row.assetName, assetIdentifier: row.assetIdentifier,
      packageName: row.packageName, severity: row.severity, ownerGroup: row.ownerGroup, status: row.status, incidentId: row.incidentId, dueAt: row.dueAt })),
    softwareItems: primary ? [
      { id: 'si-openssl', displayName: 'openssl', vendor: 'OpenSSL Project', assetCount: 18, openFindingCount: 40 },
      { id: 'si-glibc', displayName: 'glibc', vendor: 'GNU', assetCount: 3, openFindingCount: 2 },
    ] : [],
  };
}

// ── Operations ──────────────────────────────────────────────────────────────
const ingestionEfficiency = {
  sbomIngestionsLast24h: 42, sbomIngestionsPerHour: 1.75, sbomSuccessRatePercent: 97.6,
  syncRunsLast24h: 186, syncSuccessRatePercent: 94.1, queueBacklog: 3,
  recordsFetchedLast24h: 1_284_012, recordsInsertedLast24h: 18_402, recordsUpdatedLast24h: 211_736,
  sourceBreakdown: [
    { source: 'NVD', runs: 96, successes: 96, failures: 0, successRatePercent: 100, fetched: 812_004, inserted: 9_120, updated: 140_211 },
    { source: 'GHSA', runs: 48, successes: 41, failures: 7, successRatePercent: 85.4, fetched: 301_220, inserted: 6_012, updated: 52_002 },
    { source: 'servicenow-cmdb', runs: 24, successes: 24, failures: 0, successRatePercent: 100, fetched: 170_788, inserted: 3_270, updated: 19_523 },
  ],
};

const freshnessDrift = {
  staleThresholdHours: 24, staleSourceCount: 1, normalizationCoverageDrift7d: -0.4, cpeFallbackShareDrift7d: 1.2,
  sourceFreshness: [
    { source: 'NVD', lastSuccessfulAt: iso(-0.05), ageHours: 1.2, stale: false },
    { source: 'GHSA', lastSuccessfulAt: iso(-1.6), ageHours: 38.4, stale: true },
    { source: 'KEV', lastSuccessfulAt: iso(-0.2), ageHours: 4.8, stale: false },
  ],
};

const apiReadPath = {
  summaryReadModelReady: true, canonicalCveCount: 248_316, summaryCveCount: 247_902, summaryCoveragePercent: 99.8,
  filterCacheActive: true, filterCacheHits: 18_204, filterCacheMisses: 611, filterCacheHitRatioPercent: 96.8,
  sampleScope: 'JVM_LOCAL_RECENT_REQUESTS', maximumSamplesPerMetric: 500,
  endpointMetrics: [
    { key: 'findings-list', label: 'Findings List', requestCount: 500, successCount: 498, errorCount: 2, averageMs: 212, p95Ms: 640, p99Ms: 1_120, maxMs: 1_904, lastMs: 188, lastRecordedAt: iso(0) },
    { key: 'vuln-repo-dashboard', label: 'CVE Dashboard', requestCount: 214, successCount: 214, errorCount: 0, averageMs: 96, p95Ms: 240, p99Ms: 410, maxMs: 622, lastMs: 81, lastRecordedAt: iso(0) },
  ],
};

const sloStatus = {
  evaluatedAt: iso(0), overallCompliant: false,
  slos: [
    { name: 'delta_queue_processing_oldest_age', description: 'Delta queue processing age', unit: 'seconds', target: 600, current: 920, compliant: false, window: '15m freshness window' },
    { name: 'findings_list_p95', description: 'Findings list p95 latency', unit: 'ms', target: 800, current: 640, compliant: true, window: 'Recent samples' },
  ],
};

const metricCatalog = [
  { section: 'pipeline', key: 'sync_success_rate', label: 'Sync Success Rate', description: 'Percent of connector and source sync runs that completed in the last 24 hours.' },
  { section: 'platform-health', key: 'summary_coverage', label: 'Summary Coverage', description: 'Share of canonical CVEs present in the summary read model.' },
];

const performanceScorecard = {
  generatedAt: iso(0), scaleProfile: '1M inventory components / 250k findings / 100 concurrent users', overallCompliant: false,
  routeFailureCount: 1, routeNoDataCount: 1, freshnessFailureCount: 1, resourceFailureCount: 1, resourceNoDataCount: 0,
  routeItems: [
    { key: 'findings-list', label: 'Findings List', path: '/api/findings', category: 'paginated-list', status: 'PASS', unit: 'ms', targetP95Ms: 800, targetP99Ms: 1_500, requestCount: 500, currentP95Ms: 640, currentP99Ms: 1_120, compliant: true, note: 'Within target.' },
    { key: 'cve-workbench', label: 'CVE Workbench', path: '/api/vuln-repo/org-cves/{id}', category: 'record-detail', status: 'FAIL', unit: 'ms', targetP95Ms: 600, targetP99Ms: 1_200, requestCount: 88, currentP95Ms: 910, currentP99Ms: 1_640, compliant: false, note: 'Observed latency exceeds at least one current target.' },
    { key: 'inventory-export', label: 'Inventory Export', path: '/api/inventory/export', category: 'export', status: 'NO_DATA', unit: 'ms', targetP95Ms: 5_000, targetP99Ms: 9_000, requestCount: 0, currentP95Ms: 0, currentP99Ms: 0, compliant: true, note: 'No samples recorded yet.' },
  ],
  freshnessItems: [
    { key: 'delta_queue_processing_oldest_age', label: 'Delta Queue Processing Oldest Age', unit: 'seconds', targetValue: 600, currentValue: 920, compliant: false, window: '15m freshness window' },
  ],
  resourceItems: [
    { key: 'db-pool-active-utilization', label: 'DB Pool Active Utilization', category: 'database', status: 'FAIL', unit: '%', targetValue: 80, currentValue: 92, compliant: false, note: 'Active connections 23 of 25.' },
    { key: 'heap-utilization', label: 'Heap Utilization', category: 'jvm', status: 'PASS', unit: '%', targetValue: 85, currentValue: 61, compliant: true, note: 'Within ceiling.' },
  ],
};

const operationalOverview = {
  ingestionSuccessRateLast24h: 94.1, recomputeP95Ms: 1_840, normalizationCoveragePercent: 91.3, correlationNoiseReductionPercent: 62.4, openCriticalFindings: 84,
};

const tenantAttention = [
  { tenantId: '00000000-0000-0000-0000-0000000000a1', tenantName: 'Acme Payments', tenantStatus: 'ACTIVE', reasons: ['Connector sync failing', 'Stale vulnerability source'],
    affectedConnectors: ['sccm-cmdb'], latestRelevantSyncAt: iso(-1.5) },
  { tenantId: '00000000-0000-0000-0000-0000000000a2', tenantName: 'Globex Retail', tenantStatus: 'ACTIVE', reasons: ['No successful sync in 48h'], affectedConnectors: ['servicenow-cmdb'], latestRelevantSyncAt: null },
];

const connectorIssues = [
  { connectorKey: 'sccm-cmdb', affectedTenantCount: 1, affectedTenants: ['Acme Payments'] },
  { connectorKey: 'servicenow-cmdb', affectedTenantCount: 1, affectedTenants: ['Globex Retail'] },
];

// ── Public authentication entry ────────────────────────────────────────────
export const testPersonas = [
  { key: 'tenant-admin', label: 'Tenant Admin', subject: 'persona.admin@example.test', tenantSlug: 'fixture', tenantName: 'Fixture Tenant', roles: ['TENANT_ADMIN'] },
  { key: 'security-analyst', label: 'Security Analyst', subject: 'persona.analyst@example.test', tenantSlug: 'fixture', tenantName: 'Fixture Tenant', roles: ['SECURITY_ANALYST'] },
  { key: 'platform-owner', label: 'Platform Owner', subject: 'persona.owner@example.test', tenantSlug: null, tenantName: null, roles: ['PLATFORM_OWNER'] },
];

function inviteFor(token, kind) {
  if (token === EXPIRED_INVITE_TOKEN) return { status: 410, json: { message: EXPIRED_INVITE_MESSAGE } };
  const deliveryError = token === DELIVERY_ERROR_INVITE_TOKEN;
  const common = {
    valid: true, status: deliveryError ? 'DELIVERY_ERROR' : 'PENDING', email: 'new.user@example.test', tenantId: '00000000-0000-0000-0000-000000000001',
    tenantName: 'Fixture Tenant', inviteExpiresAt: iso(6),
    message: deliveryError ? 'The invite email could not be delivered (fixture).' : 'Your invite is ready (fixture).',
  };
  return ok(kind === 'demo'
    ? { ...common, demoExpiresAt: iso(7), loginUrl: '/login' }
    : { ...common, inviteeName: 'New User', role: 'SECURITY_ANALYST' });
}

// ── Router ──────────────────────────────────────────────────────────────────
/** Returns a Playwright fulfil object for P7 dashboard/campaign/operations/auth requests, or undefined. */
export function experienceFixtureFor(rawUrl, method = 'GET', body = null) {
  const url = new URL(rawUrl);
  const path = url.pathname.replace(/^\/api/, '');
  const json = parse(body);
  const isGet = method === 'GET';

  // Exposure dashboard and the CVE dashboard
  if (path === '/dashboard/exposure-summary') return ok(exposureSummary);
  if (path === '/dashboard/grid-exposure') return ok(gridExposure);
  if (path === '/vuln-repo/dashboard' || path === '/platform/vuln-repo/dashboard') return ok(vulnRepoDashboard);
  if (path === '/platform/vuln-repo/source-stats') return ok(platformSourceStats);

  // Campaigns
  if (path === '/campaigns' && isGet) {
    const status = url.searchParams.get('status');
    return ok(status ? campaigns.filter((item) => item.status === status) : campaigns);
  }
  if (path === '/campaigns' && method === 'POST') {
    return ok(detailFor(summary({ id: 'campaign-created', name: json.name ?? 'New campaign', status: 'DRAFT', cveIds: json.cveIds ?? [], startedAt: null })));
  }
  const campaign = path.match(/^\/campaigns\/([^/]+)(?:\/(.+))?$/);
  if (campaign) {
    const record = campaigns.find((item) => item.id === decodeURIComponent(campaign[1]));
    if (!record) return notFound;
    const action = campaign[2];
    if (!action && isGet) return ok(detailFor(record));
    if (action === 'status') return ok(detailFor({ ...record, status: json.status ?? record.status, updatedAt: iso(0) }));
    if (action === 'notes') return ok({ id: 'note-new', author: 'fixture.analyst@example.test', body: json.body ?? '', createdAt: iso(0) });
    if (action === 'ai-insights' || action === 'ai-advisories') return { status: 503, json: { message: 'AI generation is not available in fixtures.' } };
    if (/^exceptions\/[^/]+\/status$/.test(action ?? '')) return ok(detailFor(record));
  }

  // Operations (tenant views and the platform console operations view)
  if (path === '/operations/ingestion-efficiency') return ok({ generatedAt: iso(0), data: ingestionEfficiency });
  if (path === '/operations/freshness-drift') return ok({ generatedAt: iso(0), data: freshnessDrift });
  if (path === '/operations/api-read-path') return ok({ generatedAt: iso(0), data: apiReadPath });
  if (path === '/operations/metric-catalog') return ok({ generatedAt: iso(0), data: metricCatalog });
  if (path === '/operations/performance-scorecard') return ok(performanceScorecard);
  if (path === '/operations/overview') return ok({ generatedAt: iso(0), data: operationalOverview });
  if (path === '/operations/tenant-attention') return ok(tenantAttention);
  if (path === '/operations/connector-issues') return ok(connectorIssues);
  if (path === '/slo/status') return ok(sloStatus);
  // /operations/quality redirects to the inventory quality workspace, which needs its filter lists.
  if (path === '/operations/quality/filters') {
    return ok({ issueTypes: ['UNRESOLVED_IDENTITY', 'MISSING_VERSION'], severities: ['HIGH', 'MEDIUM', 'LOW'], assetTypes: ['HOST', 'APPLICATION'],
      sourceSystems: ['servicenow-cmdb', 'sbom-github'], ecosystems: ['npm', 'maven'] });
  }

  // Public authentication entry
  if (path === '/auth/login' && method === 'POST') {
    return json.password === LOGIN_REJECTED_PASSWORD
      ? { status: 401, json: { message: LOGIN_REJECTED_MESSAGE } }
      : ok({ token: FIXTURE_AUTH_TOKEN, tokenType: 'Bearer', expiresAt: iso(1) });
  }
  if (path === '/auth/setup-session' && method === 'POST') {
    return json.setupToken === SETUP_TOKEN ? noContent : { status: 410, json: { message: 'Password setup link is invalid or expired (fixture).' } };
  }
  if (path === '/auth/setup-password' && method === 'POST') return ok({ token: FIXTURE_AUTH_TOKEN, tokenType: 'Bearer' });
  if (path === '/dev/test-personas') return ok(testPersonas);
  if (path === '/demo-invites/validate') return inviteFor(json.token, 'demo');
  if (path === '/tenant-invites/validate') return inviteFor(json.token, 'tenant');
  if (path === '/demo-invites/accept' || path === '/tenant-invites/accept') return ok({ status: 'ACCEPTED', email: 'new.user@example.test' });
  return undefined;
}
