// Deterministic Connectors and configuration fixtures for UI 2.0 visual/behaviour review (P6).
//
// Shapes follow frontend/src/features/connect/types.ts, features/configurations/types.ts,
// features/ai-security/types.ts (connector configs, runs, scopes, feature flags),
// features/intelligence/api.ts (platform review/release/schedule records) and the IngestionJob,
// BomSource, BomIngestionResult and VulnIntelSourcesSummary types in api/client.ts.
// All hosts use example.test, account and subscription IDs are documentation-style fakes, and
// credentials only ever appear as hasCredential / hasCredentialSecret / hasToken booleans.
// Writes return canned results (saves echo the request body merged over the fixture record);
// nothing is persisted. Not authenticated evidence.

import { FIXED_TIME } from './time.mjs';

const BASE = FIXED_TIME;
const day = 86_400_000;
const iso = (offsetDays) => new Date(BASE + offsetDays * day).toISOString();

// ── Exported scenario constants ─────────────────────────────────────────────
/** Catalog health: ServiceNow synced (ok dot), SCCM last test FAILED (fail dot), AWS synced, Azure not configured. */
export const HEALTHY_CONNECTOR = 'servicenow-cmdb';
export const FAILING_CONNECTOR = 'sccm-cmdb';
export const UNCONFIGURED_CONNECTOR = 'azure-discovery';
export const SCCM_FAILURE_MESSAGE = "Login failed for user 'svc-scoutgrid-read' (fixture). Check the SQL credential and site database permissions.";

/** AWS Cloud Discovery multi-account targets; testing the sandbox target deterministically fails. */
export const AWS_ACCOUNT_ID = '111122223333';
export const AWS_PRIMARY_TARGET_ID = 'aws-target-prod';
export const FAILING_AWS_TARGET_ID = 'aws-target-sandbox';
export const AWS_TARGET_FAILURE_MESSAGE = 'AccessDenied: sts:AssumeRole on arn:aws:iam::444455556666:role/ScoutGridDiscovery (fixture).';

/**
 * Validation path: PUT /api/connectors/servicenow-cmdb with a baseUrl that does not start with
 * https:// returns 400. The UI renders `${message} (baseUrl: ...)` via formatApiError.
 */
export const SERVICENOW_INVALID_BASE_URL = 'http://cmdb.example.test';
export const SERVICENOW_VALIDATION_MESSAGE = 'Connector configuration is invalid';
export const SERVICENOW_VALIDATION_FIELD_MESSAGE = 'must be an https:// URL';

/** Run history. */
export const FAILED_RUN_ID = 'sync-run-inv-sccm-0007';
export const RUNNING_RUN_ID = 'sync-run-inv-aws-0012';
export const QUEUED_RUN_ID = 'sync-run-inv-sn-0013';
export const COMPLETED_RUN_ID = 'sync-run-inv-sn-0011';
export const GITHUB_COMPLETED_RUN_ID = 'sync-run-inv-gh-0010';
export const FAILED_INGESTION_JOB_ID = 'job-ai-aws-0031';
export const QUEUED_INGESTION_JOB_ID = 'job-ai-copilot-0033';
export const BOM_FETCH_JOB_ID = 'job-bom-fetch-0034';

/** Configurations. */
export const SUPPRESSION_RULE_IDS = ['supp-rule-dev-low', 'supp-rule-vendor-disputed', 'supp-rule-legacy-expired'];
export const OWNERSHIP_RULE_IDS = ['own-rule-payments', 'own-rule-data', 'own-rule-default'];
export const CORRELATION_DISABLED_SOURCES = ['euvd', 'jvn', 'advisory'];

/** Platform vuln-intel: GHSA's latest run failed; a review candidate builds READY. */
export const FAILED_VULN_INTEL_SOURCE = 'GHSA';
export const VULN_INTEL_FAILURE_MESSAGE = 'GitHub GraphQL API rate limit exceeded (fixture); retry after 2026-10-24T13:00:00Z.';
export const REVIEW_CANDIDATE_ID = 'candidate-0007';
export const ACTIVE_RELEASE_ID = 'release-0042';

/**
 * Auto-finding rules live only in localStorage (ConfigurationsPage AutoFindingRulesSection has no
 * API). Journeys can seed them with context.addInitScript(([k, v]) => localStorage.setItem(k, v),
 * [AUTO_FINDING_RULES_STORAGE_KEY, JSON.stringify(autoFindingRules)]).
 */
export const AUTO_FINDING_RULES_STORAGE_KEY = 'auto_finding_rules_v1';
export const autoFindingRules = [
  { id: 'afr-critical-kev', name: 'Critical or KEV on production', enabled: true, investigate: true, createFindings: true, createServiceNowIncident: true,
    cveConditions: [{ id: 'afr-critical-kev-1', column: 'cvssScore', operator: '>=', value: '9' }, { id: 'afr-critical-kev-2', column: 'isInKev', operator: '=', value: 'true' }],
    softwareScope: 'ALL', selectedSoftware: [], assetScope: 'TAGS', assetTags: 'env:prod', findingType: 'CVE_ASSET', scheduleHours: '12' },
  { id: 'afr-high-epss', name: 'High EPSS, investigate only', enabled: false, investigate: true, createFindings: false, createServiceNowIncident: false,
    cveConditions: [{ id: 'afr-high-epss-1', column: 'epssScore', operator: '>=', value: '0.5' }],
    softwareScope: 'ALL', selectedSoftware: [], assetScope: 'ALL', assetTags: '', findingType: 'CVE_ASSET', scheduleHours: '24' },
];

const ok = (json) => ({ status: 200, json });
const noContent = { status: 204, body: '' };
const notFound = { status: 404, json: { message: 'Not found (fixture)' } };
const trigger = (runId, message) => ok({ runId, status: 'QUEUED', message });

// ── Inventory connector configs ─────────────────────────────────────────────
const serviceNowConfig = {
  id: 'cfg-servicenow-1', sourceSystem: 'servicenow', configured: true, baseUrl: 'https://cmdb.example.test', authType: 'BASIC',
  username: 'svc-scoutgrid-cmdb', hasCredentialSecret: true, installTable: 'cmdb_sam_sw_install', discoveryModelTable: 'cmdb_sam_sw_discovery_model',
  ciTable: 'cmdb_ci', installQuery: '', discoveryQuery: '', installFields: 'sys_id,display_name,version,installed_on', discoveryFields: 'sys_id,name,version,publisher',
  pageSize: 1000, enabled: true, autoSyncEnabled: true, intervalMinutes: 720,
  lastTestStatus: 'SUCCESS', lastTestMessage: 'All three tables reachable (fixture).', lastTestedAt: iso(-0.3), lastSyncAt: iso(-0.25),
};

const sccmConfig = {
  id: 'cfg-sccm-1', sourceSystem: 'sccm', configured: true, jdbcUrl: 'jdbc:sqlserver://sccm-db.example.test:1433;databaseName=CM_FX1',
  authType: 'SQL_AUTH', username: 'svc-scoutgrid-read', hasCredential: true, siteCode: 'FX1', databaseName: 'CM_FX1', fetchSize: 500,
  queryTimeoutSeconds: 120, mockMode: false, enabled: true, autoSyncEnabled: true, intervalMinutes: 1440,
  lastTestStatus: 'FAILED', lastTestMessage: SCCM_FAILURE_MESSAGE, lastTestedAt: iso(-0.5), lastSyncAt: iso(-9),
};

const awsConfig = {
  id: 'cfg-aws-1', sourceSystem: 'aws', configured: true, authType: 'CROSS_ACCOUNT_ROLE', accessKeyId: '', hasCredential: false,
  crossAccountRoleArn: `arn:aws:iam::${AWS_ACCOUNT_ID}:role/ScoutGridDiscovery`, externalId: 'scoutgrid-fixture-ext-7c1d', awsAccountId: AWS_ACCOUNT_ID,
  regionsJson: JSON.stringify(['us-east-1', 'us-west-2', 'eu-west-1']), resourceTypesJson: '["EC2"]', enabled: true, autoSyncEnabled: true, intervalMinutes: 1440,
  lastTestStatus: 'SUCCESS', lastTestMessage: 'Role assumed; 3 regions reachable (fixture).', lastTestedAt: iso(-1.1), lastSyncAt: iso(-1),
};

const azureConfig = {
  sourceSystem: 'azure', configured: false, authType: 'CLIENT_SECRET', azureTenantId: '', clientId: '', hasCredential: false,
  subscriptionIdsJson: '[]', regionsJson: '[]', enabled: false, autoSyncEnabled: false, intervalMinutes: 1440,
};

const awsTargets = [
  { id: AWS_PRIMARY_TARGET_ID, accountId: AWS_ACCOUNT_ID, accountName: 'production', roleArn: `arn:aws:iam::${AWS_ACCOUNT_ID}:role/ScoutGridDiscovery`,
    externalId: 'scoutgrid-fixture-ext-7c1d', enabled: true, regionsJson: JSON.stringify(['us-east-1', 'us-west-2']), resourceTypesJson: '["EC2"]',
    lastTestStatus: 'SUCCESS', lastTestMessage: 'Role assumed (fixture).', lastTestedAt: iso(-1.1), lastSyncAt: iso(-1),
    hostCount: 184, ssmManagedHostCount: 171, missingIamInstanceProfileCount: 9, softwareInventoryHostCount: 166 },
  { id: FAILING_AWS_TARGET_ID, accountId: '444455556666', accountName: 'sandbox', roleArn: 'arn:aws:iam::444455556666:role/ScoutGridDiscovery',
    externalId: 'scoutgrid-fixture-ext-91aa', enabled: true, regionsJson: JSON.stringify(['eu-west-1']), resourceTypesJson: '["EC2"]',
    lastTestStatus: 'FAILED', lastTestMessage: AWS_TARGET_FAILURE_MESSAGE, lastTestedAt: iso(-0.4), lastSyncAt: iso(-12),
    hostCount: 23, ssmManagedHostCount: 11, missingIamInstanceProfileCount: 12, softwareInventoryHostCount: 10 },
];

// ── Vulnerability source filter configs (tenant correlation toggles) ───────
const VULN_SOURCES = ['nvd', 'kev', 'ghsa', 'redhat', 'microsoft', 'euvd', 'jvn', 'advisory', 'epss'];
const vulnSourceConfigs = VULN_SOURCES.map((sourceSystem, index) => ({
  sourceSystem, configured: true, enabledForCorrelation: !CORRELATION_DISABLED_SOURCES.includes(sourceSystem),
  isVulnerable: sourceSystem === 'nvd', hasKev: sourceSystem === 'kev', knownRansomwareCampaignUse: false,
  cvssV3Severity: sourceSystem === 'nvd' ? 'HIGH' : undefined, severity: sourceSystem === 'ghsa' ? 'HIGH' : undefined,
  cvssScore: sourceSystem === 'nvd' ? 7 : undefined, dateAddedFrom: sourceSystem === 'kev' ? '2024-01-01' : undefined,
  updatedAt: iso(-3 - index),
}));
const vulnSourceProcessing = {
  tenant_id: '00000000-0000-0000-0000-000000000001', status: 'CURRENT', required_revision: 42, completed_revision: 42, completed_generation: 42,
  last_completed_at: iso(-0.2), last_error: null, current_release_id: ACTIVE_RELEASE_ID, current_generation: 42,
};

// ── Run history ─────────────────────────────────────────────────────────────
const run = (id, syncType, runDomain, status, startedDays, durationMinutes, counts, metadata, extra = {}) => ({
  id, syncType, runDomain, runClass: 'INGESTION', status, recordsFetched: counts[0], recordsInserted: counts[1], recordsUpdated: counts[2], recordsFailed: counts[3],
  startedAt: iso(startedDays), completedAt: durationMinutes == null ? undefined : new Date(BASE + startedDays * day + durationMinutes * 60_000).toISOString(),
  metadataJson: metadata ? JSON.stringify(metadata) : undefined, ...extra,
});

const inventoryRuns = [
  run(RUNNING_RUN_ID, 'AWS_DISCOVERY', 'INVENTORY', 'RUNNING', -0.01, null, [96, 0, 0, 0],
    { sourceSystem: 'aws', triggerMode: 'Scheduled', awsAccountId: AWS_ACCOUNT_ID, regions: ['us-east-1', 'us-west-2', 'eu-west-1'], resourceTypes: ['EC2'], stage: 'DESCRIBE_INSTANCES' }, { queuePosition: 1 }),
  run(QUEUED_RUN_ID, 'SERVICENOW_CMDB', 'INVENTORY', 'QUEUED', -0.005, null, [0, 0, 0, 0],
    { sourceSystem: 'servicenow', triggerMode: 'Manual', message: 'Waiting for the AWS discovery run to finish.' }, { queuePosition: 2 }),
  run(COMPLETED_RUN_ID, 'SERVICENOW_CMDB', 'INVENTORY', 'COMPLETED', -0.27, 14, [5210, 38, 412, 0],
    { sourceSystem: 'servicenow', triggerMode: 'Scheduled', tableName: 'cmdb_sam_sw_install', installRowsProcessed: 4980, discoveryRowsProcessed: 230, unmatchedDiscoveryRows: 6,
      ciCreated: 12, ciAliasesCreated: 4, softwareInstancesCreated: 38, softwareInstancesUpdated: 412, inventoryComponentsCreated: 38, inventoryComponentsUpdated: 412, assetsIngested: 318, findingsGenerated: 27 }),
  run(FAILED_RUN_ID, 'SCCM_CMDB', 'INVENTORY', 'FAILED', -0.52, 1, [0, 0, 0, 0],
    { sourceSystem: 'sccm', triggerMode: 'Scheduled', stage: 'CONNECT' }, { errorMessage: SCCM_FAILURE_MESSAGE }),
  run('sync-run-inv-gh-0009', 'GITHUB_REPOSITORY_SBOM', 'INVENTORY', 'PARTIAL_SUCCESS', -0.8, 6, [14, 212, 9, 2],
    { sourceSystem: 'github', triggerMode: 'Scheduled', scope: 'fixture-org/payments-api', componentsIngested: 212, findingsGenerated: 9, message: '2 manifests could not be parsed (fixture).' }),
  run(GITHUB_COMPLETED_RUN_ID, 'GITHUB_GHCR_SBOM', 'INVENTORY', 'COMPLETED', -1.2, 3, [6, 88, 4, 0],
    { sourceSystem: 'github', triggerMode: 'Manual', scope: 'ghcr.io/fixture-org', componentsIngested: 88, findingsGenerated: 4 }),
  run('sync-run-inv-aws-0008', 'AWS_DISCOVERY', 'INVENTORY', 'COMPLETED', -1, 9, [207, 4, 203, 0],
    { sourceSystem: 'aws', triggerMode: 'Scheduled', awsAccountId: AWS_ACCOUNT_ID, regions: ['us-east-1', 'us-west-2'], assetsDiscovered: 207, assetsUpserted: 207, ssmAssetsIngested: 171, assetsMarkedInactive: 3 }),
  run('sync-run-inv-ai-az-0006', 'AI_SECURITY_AZURE_DISCOVERY', 'INVENTORY', 'COMPLETED', -1.5, 4, [64, 11, 53, 0],
    { provider: 'AZURE', triggerMode: 'Connector', connectorId: 'azure-foundry-conn-1', subscriptionIds: ['00000000-1111-2222-3333-444444444444'], families: ['FOUNDRY_PROJECTS', 'FOUNDRY_AGENTS'] }),
];

const ingestionJob = (jobId, jobType, sourceType, assetIdentifier, status, requestedDays, extra = {}) => ({
  jobId, jobType, sourceType, assetIdentifier, status, requestedBy: 'fixture.analyst@example.test', requestedAt: iso(requestedDays),
  startedAt: status === 'QUEUED' ? null : iso(requestedDays + 0.001), completedAt: ['SUCCEEDED', 'FAILED'].includes(status) ? iso(requestedDays + 0.004) : null,
  attemptCount: status === 'QUEUED' ? 0 : 1, failureCode: null, failureMessage: null, sbomUploadId: null, resultJson: null, ...extra,
});
const bomFetchResult = { bomId: 'bom-0042', assetId: 'asset-payments-api', bomType: 'SBOM', format: 'CYCLONEDX_JSON', formatVersion: '1.6', specFamily: 'CYCLONEDX',
  documentFormat: 'JSON', supportLevel: 'FULL', supported: true, warnings: [], componentsIngested: 128, findingsGenerated: 6, status: 'SUCCEEDED', action: 'CREATED' };
const ingestionJobs = [
  ingestionJob(QUEUED_INGESTION_JOB_ID, 'AI_SECURITY_COPILOT_STUDIO', 'CONNECTOR', 'copilot:copilot-conn-1', 'QUEUED', -0.002),
  ingestionJob(FAILED_INGESTION_JOB_ID, 'AI_SECURITY_AWS_BEDROCK', 'CONNECTOR', `aws:ai-aws-conn-1`, 'FAILED', -0.6,
    { failureCode: 'ASSUME_ROLE_DENIED', failureMessage: 'The ScoutGrid AI Security role could not be assumed (fixture). Update the trust policy External ID.' }),
  ingestionJob(BOM_FETCH_JOB_ID, 'BOM_FETCH', 'URL', 'asset-payments-api', 'SUCCEEDED', -2, { sbomUploadId: 'upload-0042', resultJson: JSON.stringify(bomFetchResult) }),
  ingestionJob('job-sbom-0029', 'SBOM_FETCH', 'API_ENDPOINT', 'billing-core', 'SUCCEEDED', -3, { sbomUploadId: 'upload-0029', resultJson: JSON.stringify({ ...bomFetchResult, bomId: 'bom-0029', assetId: 'asset-billing-core', componentsIngested: 74 }) }),
];

const vulnIntelRuns = [
  run('sync-run-vi-nvd-0101', 'NVD', 'VULN_INTEL', 'COMPLETED', -0.15, 11, [1840, 312, 1528, 0], { triggerMode: 'Scheduled' }),
  run('sync-run-vi-kev-0100', 'KEV', 'VULN_INTEL', 'COMPLETED', -0.4, 1, [1312, 4, 0, 0], { triggerMode: 'Scheduled' }),
  run('sync-run-vi-ghsa-0099', 'GHSA', 'VULN_INTEL', 'FAILED', -0.45, 2, [600, 0, 0, 600], { triggerMode: 'Scheduled' }, { errorMessage: VULN_INTEL_FAILURE_MESSAGE }),
  run('sync-run-vi-msft-0098', 'CSAF_MICROSOFT', 'VULN_INTEL', 'RUNNING', -0.01, null, [214, 0, 0, 0], { triggerMode: 'Manual' }),
  run('sync-run-vi-rh-0097', 'CSAF_REDHAT', 'VULN_INTEL', 'COMPLETED', -1, 18, [3021, 88, 640, 0], { triggerMode: 'Scheduled' }),
  run('sync-run-vi-epss-0096', 'EPSS', 'VULN_INTEL', 'COMPLETED', -0.9, 3, [251004, 0, 251004, 0], { triggerMode: 'Scheduled' }),
  run('sync-run-vi-eol-0095', 'EOL_FULL_REFRESH', 'VULN_INTEL', 'COMPLETED', -2, 7, [412, 3, 61, 0], { triggerMode: 'Scheduled' }),
];
const processingRuns = [
  run('sync-run-proc-0050', 'TENANT_CORRELATION', 'PROCESSING', 'COMPLETED', -0.2, 5, [0, 41, 380, 0], { triggerMode: 'Release' }, { runClass: 'RECOMPUTE' }),
];

const sourceStatus = (status, completedDays, inserted, updated, fetched, errorMessage) => ({
  status, completedAt: completedDays == null ? undefined : iso(completedDays), recordsInserted: inserted, recordsUpdated: updated, recordsFetched: fetched, ...(errorMessage ? { errorMessage } : {}),
});
const vulnIntelSummary = { sources: {
  NVD: sourceStatus('completed', -0.15, 312, 1528, 1840), KEV: sourceStatus('completed', -0.4, 4, 0, 1312),
  GHSA: sourceStatus('failed', -0.45, 0, 0, 600, VULN_INTEL_FAILURE_MESSAGE), CSAF_MICROSOFT: sourceStatus('running', null, 0, 0, 214),
  CSAF_REDHAT: sourceStatus('completed', -1, 88, 640, 3021), EUVD: sourceStatus('completed', -1.3, 52, 410, 462), JVN: sourceStatus('never', null, 0, 0, 0),
  EPSS: sourceStatus('completed', -0.9, 0, 251004, 251004), OSV: sourceStatus('never', null, 0, 0, 0), EOL_FULL_REFRESH: sourceStatus('completed', -2, 3, 61, 412),
} };

// ── Platform intelligence review / releases / schedules ────────────────────
const SCHEDULED = [['NVD', true, 2], ['KEV', true, 24], ['GHSA', true, 6], ['CSAF_MICROSOFT', true, 24], ['CSAF_REDHAT', true, 24], ['EUVD', false, 24],
  ['JVN', false, 48], ['EPSS', true, 24], ['OSV', false, 12], ['EOL_FULL_REFRESH', true, 168], ['EOL_DATE_SWEEP', true, 24]];
const schedules = SCHEDULED.map(([sync_type, enabled, interval_hours]) => ({ sync_type, enabled, interval_hours, next_due_at: enabled ? iso(interval_hours / 24) : null }));
const releases = [
  { id: ACTIVE_RELEASE_ID, generation: 42, predecessor_id: 'release-0041', kind: 'INCREMENTAL', actor: 'fixture.owner@example.test', published_at: iso(-0.3), digest: `sha256:${'4f'.repeat(32)}` },
  { id: 'release-0041', generation: 41, predecessor_id: 'release-0040', kind: 'INCREMENTAL', actor: 'fixture.owner@example.test', published_at: iso(-1.3), digest: `sha256:${'a3'.repeat(32)}` },
];
const releaseProcessing = [
  vulnSourceProcessing,
  { tenant_id: '00000000-0000-0000-0000-0000000000a1', status: 'PROCESSING', required_revision: 42, completed_revision: 41, completed_generation: 41, last_completed_at: iso(-1.2), last_error: null },
  { tenant_id: '00000000-0000-0000-0000-0000000000a5', status: 'FAILED', required_revision: 42, completed_revision: 40, completed_generation: 40, last_completed_at: iso(-2.2), last_error: 'Tenant suspended (fixture)' },
];
const candidate = (selected = ['sync-run-vi-nvd-0101']) => ({
  id: REVIEW_CANDIDATE_ID, status: 'READY', base_release_id: ACTIVE_RELEASE_ID, digest: `sha256:${'7e'.repeat(32)}`, selected_run_ids: selected,
  expanded_run_ids: [...new Set([...selected, 'sync-run-vi-kev-0100'])], normalization_policy: 'canonical-v3',
  quality_report: { prepared_records: 3, unchanged_records: 1840, rejected_records: 1, identifier_conflicts: 0 }, error_code: null, published_release_id: null,
});
const candidateRecords = [
  { id: 1, kind: 'UPSERT', external_id: 'CVE-2026-41001', source_system: 'nvd', validation: 'VALID', payload: { severity: 'CRITICAL', cvssScore: 9.8 } },
  { id: 2, kind: 'UPSERT', external_id: 'CVE-2026-41002', source_system: 'nvd', validation: 'VALID', payload: { severity: 'HIGH', cvssScore: 7.5 } },
  { id: 3, kind: 'KEV_ADDED', external_id: 'CVE-2025-30065', source_system: 'kev', validation: 'VALID', payload: { dateAdded: '2026-10-23' } },
  { id: 4, kind: 'UPSERT', external_id: 'CVE-2026-4100X', source_system: 'nvd', validation: 'REJECTED_MALFORMED_ID', payload: { reason: 'Identifier is not a CVE ID' } },
];

// ── GitHub SBOM sources and BOM sources ─────────────────────────────────────
const githubSources = [
  { id: 'gh-src-payments', name: 'Payments API dependency graph', owner: 'fixture-org', repo: 'payments-api', path: 'dependency-graph/sbom', assetType: 'APPLICATION',
    assetName: 'payments-api', assetIdentifier: 'github:fixture-org/payments-api', frequency: 'INTERVAL', intervalMinutes: 1440, enabled: true,
    lastRunAt: iso(-0.8), lastRunStatus: 'SUCCESS', hasToken: true },
  { id: 'gh-src-billing', name: 'Billing core manifests', owner: 'fixture-org', repo: 'billing-core', path: 'sbom/cyclonedx.json', assetType: 'APPLICATION',
    assetName: 'billing-core', assetIdentifier: 'github:fixture-org/billing-core', frequency: 'INTERVAL', intervalMinutes: 720, enabled: true,
    lastRunAt: iso(-1.6), lastRunStatus: 'FAILURE', lastError: 'sbom/cyclonedx.json not found on default branch (fixture).', hasToken: true },
  { id: 'gh-src-ghcr', name: 'GHCR image attestations', owner: 'fixture-org', repo: '', path: 'ghcr/attestations', assetType: 'CONTAINER_IMAGE',
    assetName: 'ghcr.io/fixture-org', assetIdentifier: 'ghcr:fixture-org', frequency: 'ONCE', intervalMinutes: 0, enabled: true, hasToken: false },
];
const bomSources = [
  { id: 'bom-source-1', assetId: 'asset-payments-api', bomType: 'SBOM', supplier: 'Fixture Platform Team', sourceKey: 'payments-api', sourceReference: 'https://sbom.example.test/payments-api.cdx.json',
    currentBomId: 'bom-0042', revision: 4, completeness: 'COMPLETE_ASSET_SOFTWARE', state: 'ACTIVE', createdAt: iso(-60), updatedAt: iso(-2),
    supportedComponentCount: 128, withdrawnComponentCount: 3, latestAssertionBy: 'fixture.analyst@example.test', latestAssertionAt: iso(-2) },
  { id: 'bom-source-2', assetId: 'asset-claims-agent', bomType: 'AIBOM', supplier: 'ML Platform', sourceKey: 'claims-agent', sourceReference: null,
    currentBomId: 'bom-0014', revision: 3, completeness: 'PARTIAL', state: 'ACTIVE', createdAt: iso(-40), updatedAt: iso(-5),
    supportedComponentCount: 17, withdrawnComponentCount: 0, latestAssertionBy: null, latestAssertionAt: null },
  { id: 'bom-source-3', assetId: null, bomType: 'VENDOR', supplier: 'Example Vendor Ltd', sourceKey: 'vendor-gateway-appliance', sourceReference: null,
    currentBomId: 'bom-0023', revision: 1, completeness: 'PARTIAL', state: 'HELD_ENTITLEMENT', createdAt: iso(-20), updatedAt: iso(-20),
    supportedComponentCount: 46, withdrawnComponentCount: 0, latestAssertionBy: null, latestAssertionAt: null },
];

// ── AI Security connectors ──────────────────────────────────────────────────
const aiAwsConnector = {
  id: 'ai-aws-conn-1', accountId: AWS_ACCOUNT_ID, roleArn: `arn:aws:iam::${AWS_ACCOUNT_ID}:role/ScoutAiSecurity`, authMode: 'CROSS_ACCOUNT_ROLE',
  externalId: 'scoutgrid-ai-fixture-3b9e', regions: ['us-east-1', 'us-west-2'], enabled: true, createdAt: iso(-30), updatedAt: iso(-3),
};
const awsIdentity = { accountId: AWS_ACCOUNT_ID, arn: `arn:aws:sts::${AWS_ACCOUNT_ID}:assumed-role/ScoutAiSecurity/scoutgrid-fixture`, principalId: 'AROAFIXTUREPRINCIPAL:scoutgrid-fixture' };
const awsPreflight = {
  identity: awsIdentity, providerApiCalls: 14, explicitlyRequested: true,
  resourceFamilies: [
    { resourceFamily: 'BEDROCK_AGENTS', region: 'us-east-1', status: 'COMPLETE', actions: [{ action: 'bedrock:ListAgents', status: 'VERIFIED_ALLOWED', detail: '' }], customerRemediation: '' },
    { resourceFamily: 'BEDROCK_GUARDRAILS', region: 'us-east-1', status: 'COMPLETE', actions: [{ action: 'bedrock:ListGuardrails', status: 'VERIFIED_EMPTY', detail: '' }], customerRemediation: '' },
    { resourceFamily: 'AGENTCORE_GATEWAYS', region: 'us-west-2', status: 'UNAUTHORIZED', actions: [{ action: 'bedrock-agentcore:ListGateways', status: 'UNAUTHORIZED', detail: 'AccessDenied (fixture)' }],
      customerRemediation: 'Add bedrock-agentcore:ListGateways to the ScoutAiSecurity role.' },
  ],
};
const awsRequirements = {
  matrixVersion: 3, provider: 'AWS', prohibitedMutationActions: ['bedrock:DeleteAgent', 'bedrock:UpdateGuardrail'],
  resourceFamilies: [
    { resourceFamily: 'BEDROCK_AGENTS', scope: 'REGIONAL', requiredActions: ['bedrock:ListAgents', 'bedrock:GetAgent'], optionalEnrichmentActions: ['bedrock:ListAgentActionGroups'],
      verificationProbe: 'bedrock:ListAgents', capabilities: ['AGENT_INVENTORY'], policies: ['policy.aws.2'], customerRemediation: 'Grant read-only Bedrock agent actions.' },
  ],
};
const azureFoundryConfig = {
  configured: true, azureTenantId: '00000000-aaaa-bbbb-cccc-000000000001', clientId: '00000000-aaaa-bbbb-cccc-000000000002', hasCredential: true,
  primarySubscriptionId: '00000000-1111-2222-3333-444444444444', subscriptionIds: ['00000000-1111-2222-3333-444444444444', '00000000-1111-2222-3333-555555555555'],
  regions: ['eastus2', 'swedencentral'], foundryEndpointUrl: 'https://fixture-foundry.example.test', connectorId: 'azure-foundry-conn-1', credentialExpiresAt: iso(120),
};
const featureFlags = [
  { featureKey: 'COPILOT_DISCOVERY', enabled: true, killSwitch: false, updatedBy: 'fixture.admin@example.test', updatedAt: iso(-6) },
  { featureKey: 'COPILOT_RUNTIME', enabled: false, killSwitch: false, updatedBy: null, updatedAt: null },
  { featureKey: 'AZURE_NEW_FOUNDRY', enabled: true, killSwitch: false, updatedBy: 'fixture.admin@example.test', updatedAt: iso(-8) },
  { featureKey: 'AZURE_CLASSIC_FOUNDRY', enabled: false, killSwitch: false, updatedBy: 'fixture.admin@example.test', updatedAt: iso(-8) },
];
const copilotConnectors = [
  { id: 'copilot-conn-1', organizationUrl: 'https://fixture-org.crm.example.test', credentialProfileId: 'cred-profile-entra-1', discoveryEnabled: true,
    executionEnabled: false, killSwitch: false, scheduleCron: '0 0 */6 * * *', allowedDataverseHosts: ['fixture-org.crm.example.test'], createdAt: iso(-21), updatedAt: iso(-4) },
];
const aiRun = (id, status, startedDays, fetched, failed, errorMessage = null) => ({
  id, status, collectionStatus: status, assessmentStatus: status === 'COMPLETED' ? 'COMPLETE' : status, assessedSubjects: fetched, failedPolicies: failed ? 1 : 0,
  recordsFetched: fetched, recordsFailed: failed, startedAt: iso(startedDays), completedAt: status === 'RUNNING' ? null : iso(startedDays + 0.003), errorMessage,
});
const aiRunsByProvider = {
  AZURE: [aiRun('run-ai-az-0016', 'COMPLETED', -1.5, 64, 0), aiRun('run-ai-az-0015', 'PARTIAL', -2.5, 58, 2, 'AuthorizationFailed on 2 Foundry project scopes (fixture)')],
  MICROSOFT_COPILOT: [aiRun('run-ai-cp-0004', 'COMPLETED', -0.9, 12, 0)],
};
const scopesFor = (runId) => [
  { id: `${runId}-scope-1`, runId, accountId: runId.includes('-az-') ? '00000000-1111-2222-3333-444444444444' : AWS_ACCOUNT_ID, region: runId.includes('-az-') ? 'eastus2' : 'us-east-1',
    resourceFamily: runId.includes('-az-') ? 'FOUNDRY_AGENTS' : 'BEDROCK_AGENTS', scopeKey: 'agents', status: 'COMPLETE', acceptedChunks: 4, expectedChunks: 4,
    diagnosticCode: null, diagnostics: {}, startedAt: iso(-0.45), completedAt: iso(-0.44) },
  { id: `${runId}-scope-2`, runId, accountId: runId.includes('-az-') ? '00000000-1111-2222-3333-555555555555' : AWS_ACCOUNT_ID, region: runId.includes('-az-') ? 'swedencentral' : 'us-west-2',
    resourceFamily: runId.includes('-az-') ? 'FOUNDRY_PROJECTS' : 'AGENTCORE_GATEWAYS', scopeKey: 'gateways', status: 'PARTIAL', acceptedChunks: 1, expectedChunks: 3,
    diagnosticCode: 'ACCESS_DENIED', diagnostics: { items: [{ code: 'ACCESS_DENIED', message: 'List call was denied (fixture).', retryable: false,
      missingPermissions: [runId.includes('-az-') ? 'Microsoft.CognitiveServices/accounts/projects/read' : 'bedrock-agentcore:ListGateways'], correlationId: 'corr-fixture-0001' }] },
    startedAt: iso(-0.45), completedAt: iso(-0.44) },
];

// ── Configurations ──────────────────────────────────────────────────────────
const riskPolicy = {
  criticalThreshold: 9.0, highThreshold: 7.0, criticalSlaDays: 7, highSlaDays: 30, mediumSlaDays: 60, lowSlaDays: 120,
  assetCriticalSlaMultiplier: 0.5, assetHighSlaMultiplier: 0.75, assetMediumSlaMultiplier: 1.0, assetLowSlaMultiplier: 1.5,
  autoCloseEnabled: true, autoCloseAssetIdentifier: '', autoCloseAfterDays: 14, autoCloseRequiredConsecutiveMisses: 3,
  autoCloseNotObservedEnabled: true, autoCloseComponentRemovedEnabled: true, autoCloseAssetRetiredEnabled: true, autoCloseSourceDisabledEnabled: false,
  autoCloseDuplicateEnabled: true, autoCloseRunIntervalDays: 1, autoCloseLastRunAt: iso(-0.6), findingGenerationMode: 'AUTO',
  findingsScoreConfig: JSON.stringify([
    { table: 'VULNERABILITY', column: 'cvssScore', values: [{ operator: '>=', value: '9', weight: 0.25 }, { operator: '<=', value: '8', weight: 0.1 }] },
    { table: 'VULNERABILITY', column: 'isInKev', values: [{ operator: '=', value: 'true', weight: 0.25 }] },
    { table: 'VULNERABILITY', column: 'exploitExists', values: [{ operator: '=', value: 'true', weight: 0.15 }] },
    { table: 'ASSET', column: 'businessCriticality', values: [{ operator: '=', value: 'high', weight: 0.2 }] },
    { table: 'ASSET', column: 'internetFacing', values: [{ operator: '=', value: 'true', weight: 0.15 }] },
  ]),
  triageExploitabilityWeight: 1.4, triageBlastRadiusWeight: 1.0, triageEolRiskWeight: 0.6, triageSlaBreachWeight: 1.2, triageMissingOwnerBoost: 0.5, triagePatchGapBoost: 0.3,
};
const ownershipCondition = (logic, conditions) => JSON.stringify({ logic, conditions: conditions.map(([table, column, operator, value]) => ({ table, column, operator, value })) });
const ownershipRules = [
  { id: OWNERSHIP_RULE_IDS[0], name: 'Payments services', condition: ownershipCondition('AND', [['ASSET', 'tags', 'contains', 'team:payments'], ['ASSET', 'environment', '=', 'production']]),
    userGroup: 'Payments Platform', executionOrder: 1, matchedCount: 142, createdAt: iso(-45), updatedAt: iso(-6) },
  { id: OWNERSHIP_RULE_IDS[1], name: 'Data platform hosts', condition: ownershipCondition('OR', [['ASSET', 'owner', '=', 'data-platform@example.test'], ['SOFTWARE', 'vendor', '=', 'Apache']]),
    userGroup: 'Data Platform', executionOrder: 2, matchedCount: 87, createdAt: iso(-30), updatedAt: iso(-30) },
  { id: OWNERSHIP_RULE_IDS[2], name: 'Default infrastructure owner', condition: ownershipCondition('AND', [['ASSET', 'assetType', '=', 'HOST']]),
    userGroup: 'Core Infrastructure', executionOrder: 3, matchedCount: 311, createdAt: iso(-90), updatedAt: iso(-12) },
];
const suppressionCondition = (rows) => JSON.stringify(rows.map(([table, column, operator, value]) => ({ table, column, operator, value })));
const suppressionRules = [
  { id: SUPPRESSION_RULE_IDS[0], name: 'Low severity on development assets', state: 'APPROVED', recordType: 'FINDING',
    conditionsJson: suppressionCondition([['VULNERABILITY', 'severity', '=', 'LOW'], ['ASSET', 'environment', '=', 'development']]), conditionLogic: 'AND',
    reason: 'Development hosts are rebuilt weekly from patched images.', validFrom: iso(-30), validTo: iso(60), createdAt: iso(-31), updatedAt: iso(-30), suppressedCount: 214 },
  { id: SUPPRESSION_RULE_IDS[1], name: 'Vendor-disputed CVE in gateway appliance', state: 'IN_REVIEW', recordType: 'CVE',
    conditionsJson: suppressionCondition([['VULNERABILITY', 'externalId', '=', 'CVE-2026-41002']]), conditionLogic: 'AND',
    reason: 'Vendor VEX states the vulnerable code path is not shipped.', createdAt: iso(-3), updatedAt: iso(-2), suppressedCount: 0 },
  { id: SUPPRESSION_RULE_IDS[2], name: 'Legacy batch window exception', state: 'EXPIRED', recordType: 'FINDING',
    conditionsJson: suppressionCondition([['ASSET', 'tags', 'contains', 'legacy-batch']]), conditionLogic: 'OR',
    reason: 'Temporary exception during the 2026 Q3 migration.', validFrom: iso(-120), validTo: iso(-10), createdAt: iso(-121), updatedAt: iso(-10), suppressedCount: 38 },
];

// ── Router ──────────────────────────────────────────────────────────────────
const parse = (body) => { try { return body ? JSON.parse(body) : {}; } catch { return {}; } };

/** Returns a Playwright fulfil object for Connectors/Configurations requests, or undefined. */
export function connectFixtureFor(rawUrl, method = 'GET', body = null) {
  const url = new URL(rawUrl);
  const path = url.pathname.replace(/^\/api/, '');
  const params = url.searchParams;
  const json = parse(body);
  const isGet = method === 'GET';

  // Tenant vulnerability-source correlation toggles
  if (path === '/connectors/vulnerability-sources') return ok(vulnSourceConfigs);
  if (path === '/connectors/vulnerability-sources/processing') return ok(vulnSourceProcessing);
  const vulnSource = path.match(/^\/connectors\/vulnerability-sources\/([^/]+)$/);
  if (vulnSource) {
    const config = vulnSourceConfigs.find((item) => item.sourceSystem === decodeURIComponent(vulnSource[1]));
    if (!config) return notFound;
    return ok(isGet ? config : { ...config, ...json, updatedAt: iso(0) });
  }

  // ServiceNow CMDB
  if (path === '/connectors/servicenow-cmdb') {
    if (isGet) return ok(serviceNowConfig);
    if (typeof json.baseUrl === 'string' && !json.baseUrl.startsWith('https://')) {
      return { status: 400, json: { message: SERVICENOW_VALIDATION_MESSAGE, code: 'VALIDATION_FAILED', fields: { baseUrl: SERVICENOW_VALIDATION_FIELD_MESSAGE } } };
    }
    const { credentialSecret, ...rest } = json;
    return ok({ ...serviceNowConfig, ...rest, hasCredentialSecret: serviceNowConfig.hasCredentialSecret || Boolean(credentialSecret) });
  }
  if (path === '/connectors/servicenow-cmdb/test') {
    return ok({ status: 'SUCCESS', message: 'Connected to cmdb.example.test; all tables reachable (fixture).', ciTableReachable: true, installTableReachable: true, discoveryTableReachable: true, testedAt: iso(0) });
  }
  if (path === '/connectors/servicenow-cmdb/sync') return trigger(QUEUED_RUN_ID, 'ServiceNow CMDB sync queued (fixture).');

  // SCCM / MECM (live JDBC disabled in the pilot; test is the deterministic failure path)
  if (path === '/connectors/sccm-cmdb') {
    if (isGet) return ok(sccmConfig);
    const { credentialSecret, ...rest } = json;
    return ok({ ...sccmConfig, ...rest, hasCredential: sccmConfig.hasCredential || Boolean(credentialSecret) });
  }
  if (path === '/connectors/sccm-cmdb/test') {
    return ok({ status: 'FAILED', message: SCCM_FAILURE_MESSAGE, systemViewReachable: false, softwareViewReachable: false, testedAt: iso(0) });
  }
  if (path === '/connectors/sccm-cmdb/sync') return trigger(FAILED_RUN_ID, 'SCCM sync queued (fixture).');

  // AWS Cloud Discovery
  if (path === '/connectors/aws-discovery') {
    if (isGet) return ok(awsConfig);
    const { credentialSecret, ...rest } = json;
    return ok({ ...awsConfig, ...rest, hasCredential: awsConfig.hasCredential || Boolean(credentialSecret) });
  }
  if (path === '/connectors/aws-discovery/test') {
    return ok({ status: 'SUCCESS', message: 'Role assumed; all selected regions reachable (fixture).', resolvedAccountId: AWS_ACCOUNT_ID,
      reachableRegions: JSON.parse(awsConfig.regionsJson), warnings: [], regionErrors: {}, testedAt: iso(0) });
  }
  if (path === '/connectors/aws-discovery/sync') return trigger(RUNNING_RUN_ID, 'AWS Cloud Discovery sync queued (fixture).');
  if (path === '/connectors/aws-discovery/targets') {
    if (isGet) return ok(awsTargets);
    return ok({ ...awsTargets[0], ...json, id: 'aws-target-new', lastTestStatus: undefined, lastTestMessage: undefined, lastTestedAt: undefined, lastSyncAt: undefined,
      hostCount: 0, ssmManagedHostCount: 0, missingIamInstanceProfileCount: 0, softwareInventoryHostCount: 0 });
  }
  const awsTarget = path.match(/^\/connectors\/aws-discovery\/targets\/([^/]+)(?:\/(test|sync))?$/);
  if (awsTarget) {
    const target = awsTargets.find((candidate) => candidate.id === decodeURIComponent(awsTarget[1]));
    if (!target) return notFound;
    if (awsTarget[2] === 'test') {
      return target.id === FAILING_AWS_TARGET_ID
        ? ok({ status: 'FAILED', message: AWS_TARGET_FAILURE_MESSAGE, reachableRegions: [], warnings: [], regionErrors: { 'eu-west-1': 'AccessDenied (fixture)' }, testedAt: iso(0) })
        : ok({ status: 'SUCCESS', message: 'Role assumed (fixture).', resolvedAccountId: target.accountId, reachableRegions: JSON.parse(target.regionsJson), warnings: [], regionErrors: {}, testedAt: iso(0) });
    }
    if (awsTarget[2] === 'sync') return trigger(RUNNING_RUN_ID, `AWS discovery queued for ${target.accountName} (fixture).`);
    if (method === 'DELETE') return noContent;
    return ok(isGet ? target : { ...target, ...json });
  }

  // Azure Cloud Discovery (not configured; paused for the pilot)
  if (path === '/connectors/azure-discovery') return ok(isGet ? azureConfig : { ...azureConfig, ...json, configured: true });
  if (path === '/connectors/azure-discovery/targets') return ok(isGet ? [] : { id: 'azure-target-new', enabled: true, regionsJson: '[]', hostCount: 0, ...json });
  if (path === '/connectors/azure-discovery/test') {
    return ok({ status: 'FAILED', message: 'Azure Cloud Discovery is disabled for the pilot (fixture).', reachableSubscriptions: [], warnings: [], subscriptionErrors: {}, testedAt: iso(0) });
  }
  if (path === '/connectors/azure-discovery/sync') return trigger('sync-run-inv-az-new', 'Azure discovery queued (fixture).');

  // GitHub SBOM pipelines and BOM sources
  if (path === '/github-sbom-sources') {
    if (isGet) return ok(githubSources);
    const { githubToken, ...rest } = json;
    return ok({ ...githubSources[0], ...rest, id: 'gh-src-new', assetName: rest.repo || rest.owner, assetIdentifier: `github:${rest.owner}/${rest.repo ?? ''}`,
      intervalMinutes: rest.intervalMinutes ?? 0, lastRunAt: undefined, lastRunStatus: undefined, lastError: undefined, hasToken: Boolean(githubToken) });
  }
  if (path === '/github-sbom-sources/ghcr/run' || path === '/github-sbom-sources/repository/run') return trigger(GITHUB_COMPLETED_RUN_ID, 'GitHub SBOM run queued (fixture).');
  const githubSource = path.match(/^\/github-sbom-sources\/([^/]+)(\/run)?$/);
  if (githubSource) {
    const source = githubSources.find((candidate) => candidate.id === githubSource[1]);
    if (!source) return notFound;
    if (githubSource[2]) return trigger(GITHUB_COMPLETED_RUN_ID, `Run queued for ${source.name} (fixture).`);
    if (method === 'DELETE') return noContent;
    return ok(isGet ? source : { ...source, ...json });
  }
  if (path === '/bom/sources') return ok(bomSources);
  if (path === '/bom/fetch' && method === 'POST') return ok({ jobId: BOM_FETCH_JOB_ID, status: 'QUEUED', message: 'BOM fetch queued (fixture).', existingJob: false, retryAfterSeconds: null });
  if (path === '/bom/upload' && method === 'POST') {
    const { componentsIngested, ...result } = bomFetchResult;
    return ok({ ...result, bomId: 'bom-upload-0043', componentCount: componentsIngested, status: 'SUCCESS' });
  }
  if (path === '/sbom-fetch' && method === 'POST') return ok({ assetId: 'asset-billing-core', sbomUploadId: 'upload-0043', componentsIngested: 74, findingsGenerated: 3 });

  // Run history
  if (path === '/sync-runs') {
    const category = params.get('category') ?? 'all';
    const limit = Number(params.get('limit') ?? 100);
    const runs = category === 'inventory' ? inventoryRuns
      : category === 'vuln-intel' || category === 'vulnerability' ? vulnIntelRuns
      : category === 'processing' ? processingRuns
      : [...inventoryRuns, ...vulnIntelRuns, ...processingRuns];
    return ok(runs.slice(0, limit));
  }
  if (path === '/sync-runs/sources-summary') return ok(vulnIntelSummary);
  if (path === '/ingestion-jobs') {
    const size = Number(params.get('size') ?? 25);
    const page = Number(params.get('page') ?? 0);
    return ok({ items: ingestionJobs.slice(page * size, page * size + size), page, size, totalItems: ingestionJobs.length, totalPages: Math.max(1, Math.ceil(ingestionJobs.length / size)) });
  }
  const ingestionJobMatch = path.match(/^\/ingestion-jobs\/([^/]+)$/);
  if (ingestionJobMatch) return ingestionJobs.find((job) => job.jobId === decodeURIComponent(ingestionJobMatch[1])) ? ok(ingestionJobs.find((job) => job.jobId === decodeURIComponent(ingestionJobMatch[1]))) : notFound;

  // Platform vuln-intel feed triggers
  const feedSync = path.match(/^\/ingestion\/(nvd-sync|nvd-full-sync|kev-sync|ghsa-sync|euvd-sync|jvn-sync|csaf\/microsoft-sync|csaf\/redhat-sync)$/);
  if (feedSync && method === 'POST') return trigger(`sync-run-vi-${feedSync[1].replace(/\W+/g, '-')}-new`, `${feedSync[1]} queued (fixture).`);

  // AI Security connectors
  if (path === '/connectors/ai-security/aws') return ok(isGet ? aiAwsConnector : { ...aiAwsConnector, ...json, updatedAt: iso(0) });
  if (path === '/connectors/ai-security/aws/test') {
    return ok({ success: true, code: null, message: 'Role assumed; 2 of 3 family scopes verified (fixture).', retryable: false, missingPermissions: ['bedrock-agentcore:ListGateways'], identity: awsIdentity, preflight: awsPreflight });
  }
  if (path === '/connectors/ai-security/aws/requirements') return ok(awsRequirements);
  if (path === '/connectors/ai-security/aws/preflight') return ok(awsPreflight);
  if (path === '/connectors/ai-security/aws/run') return ok({ jobId: 'job-ai-aws-new', status: 'QUEUED', message: 'AWS AI discovery queued (fixture).' });
  if (path === '/connectors/ai-security/azure-foundry') {
    if (isGet) return ok(azureFoundryConfig);
    const { clientSecret, subscriptionIds, region, ...rest } = json;
    return ok({ ...azureFoundryConfig, ...rest, hasCredential: azureFoundryConfig.hasCredential || Boolean(clientSecret),
      subscriptionIds: typeof subscriptionIds === 'string' ? subscriptionIds.split(',').map((value) => value.trim()).filter(Boolean) : azureFoundryConfig.subscriptionIds,
      regions: typeof region === 'string' ? region.split(',').map((value) => value.trim()).filter(Boolean) : azureFoundryConfig.regions });
  }
  if (path === '/connectors/ai-security/azure-foundry/test') {
    return ok({ success: true, code: null, message: 'Foundry endpoint reachable; Reader role verified (fixture).', retryable: false, correlationId: 'corr-fixture-az-01',
      resourceFamilies: [{ resourceFamily: 'FOUNDRY_AGENTS', required: ['Microsoft.CognitiveServices/accounts/read'], granted: ['Microsoft.CognitiveServices/accounts/read'], missing: [], status: 'GRANTED' }] });
  }
  if (path === '/connectors/ai-security/azure-foundry/run') return ok({ jobId: 'job-ai-az-new', status: 'QUEUED', message: 'Azure AI discovery queued (fixture).' });
  if (path === '/connectors/ai-security/feature-flags') return ok(featureFlags);
  const flag = path.match(/^\/connectors\/ai-security\/feature-flags\/([^/]+)$/);
  if (flag) {
    const current = featureFlags.find((item) => item.featureKey === decodeURIComponent(flag[1])) ?? { featureKey: decodeURIComponent(flag[1]), enabled: false, killSwitch: false };
    return ok({ ...current, ...json, updatedBy: 'fixture.analyst@example.test', updatedAt: iso(0) });
  }
  if (path === '/connectors/ai-security/copilot-studio') return ok(isGet ? copilotConnectors : { ...copilotConnectors[0], ...json, updatedAt: iso(0) });
  const copilot = path.match(/^\/connectors\/ai-security\/copilot-studio\/([^/]+)\/(test|run|runtime-run)$/);
  if (copilot) {
    if (copilot[2] === 'test') return ok({ bots: { ready: true, status: 200, state: 'READY' }, components: { ready: true, status: 200, state: 'READY' }, executions: { ready: false, status: 403, state: 'NOT_ENABLED' } });
    if (copilot[2] === 'run') return ok({ jobId: QUEUED_INGESTION_JOB_ID, status: 'QUEUED', message: 'Copilot discovery already queued (fixture).', existingJob: true, retryAfterSeconds: null });
    return ok({ accepted: 0, duplicates: 0, windowStart: iso(-0.04) });
  }
  // Provider-scoped AI runs; unscoped /ai-security/runs stays with the inventory fixtures.
  if (path === '/ai-security/runs' && aiRunsByProvider[params.get('provider')]) return ok(aiRunsByProvider[params.get('provider')]);
  const scopes = path.match(/^\/ai-security\/runs\/([^/]+)\/scopes$/);
  if (scopes) return ok(scopesFor(decodeURIComponent(scopes[1])));

  // Platform intelligence review, releases and schedules
  if (path === '/platform/intelligence/schedules') return ok(schedules);
  const schedule = path.match(/^\/platform\/intelligence\/schedules\/([^/]+)$/);
  if (schedule) {
    const current = schedules.find((item) => item.sync_type === decodeURIComponent(schedule[1]));
    if (!current) return notFound;
    const enabled = json.enabled ?? current.enabled;
    const interval_hours = json.intervalHours ?? current.interval_hours;
    return ok({ ...current, enabled, interval_hours, next_due_at: enabled ? iso(interval_hours / 24) : null });
  }
  if (path === '/platform/intelligence/releases') return ok(releases);
  if (/^\/platform\/intelligence\/releases\/[^/]+\/processing$/.test(path)) return ok(releaseProcessing);
  if (/^\/platform\/intelligence\/releases\/[^/]+\/withdraw$/.test(path)) return ok({ ...releases[0], kind: 'WITHDRAWAL' });
  if (path === '/platform/intelligence/candidates' && method === 'POST') return ok(candidate(json.syncRunIds?.length ? json.syncRunIds : undefined));
  const candidateMatch = path.match(/^\/platform\/intelligence\/candidates\/([^/]+)(?:\/(records|publish|reject))?$/);
  if (candidateMatch) {
    if (candidateMatch[1] !== REVIEW_CANDIDATE_ID) return notFound;
    if (candidateMatch[2] === 'records') return ok(Number(params.get('page') ?? 0) === 0 ? candidateRecords : []);
    if (candidateMatch[2] === 'publish') return ok({ ...candidate(), status: 'PUBLISHED', published_release_id: 'release-0043' });
    if (candidateMatch[2] === 'reject') return ok({ ...candidate(), status: 'REJECTED' });
    return ok(candidate());
  }
  const feedTrigger = path.match(/^\/platform\/intelligence\/feeds\/(OSV|EPSS)\/run$/);
  if (feedTrigger) return trigger(`sync-run-vi-${feedTrigger[1].toLowerCase()}-new`, `${feedTrigger[1]} staging queued (fixture).`);

  // Configurations: risk policy, ownership, suppression
  if (path === '/risk-policy') return ok(isGet ? riskPolicy : { ...riskPolicy, ...json });
  if (path === '/risk-policy/recompute-findings-scores') return ok({ updated: 1284 });
  if (path === '/risk-policy/auto-close/execute-now') return ok({ updated: 17 });
  if (path === '/ownership-rules') {
    if (isGet) return ok(ownershipRules);
    return ok({ id: 'own-rule-new', executionOrder: ownershipRules.length + 1, matchedCount: 0, createdAt: iso(0), updatedAt: iso(0), ...json });
  }
  if (path === '/ownership-rules/apply') return ok({ updated: 540 });
  const ownership = path.match(/^\/ownership-rules\/([^/]+)(\/apply)?$/);
  if (ownership) {
    const rule = ownershipRules.find((candidate) => candidate.id === ownership[1]);
    if (!rule) return notFound;
    if (ownership[2]) return ok({ updated: rule.matchedCount });
    if (method === 'DELETE') return noContent;
    return ok({ ...rule, ...json, updatedAt: iso(0) });
  }
  if (path === '/suppression-rules') {
    if (isGet) return ok(suppressionRules);
    return ok({ id: 'supp-rule-new', createdAt: iso(0), updatedAt: iso(0), suppressedCount: 0, ...json });
  }
  if (/^\/suppression-rules\/cve-reopen\/[^/]+$/.test(path)) return noContent;
  const suppression = path.match(/^\/suppression-rules\/([^/]+)(?:\/(execute|reopen-all))?$/);
  if (suppression) {
    const rule = suppressionRules.find((candidate) => candidate.id === suppression[1]);
    if (!rule) return notFound;
    if (suppression[2] === 'execute') return ok({ suppressed: rule.state === 'APPROVED' ? 12 : 0 });
    if (suppression[2] === 'reopen-all') return ok({ reopened: rule.suppressedCount });
    if (method === 'DELETE') return noContent;
    return ok({ ...rule, ...json, updatedAt: iso(0) });
  }

  return undefined;
}
