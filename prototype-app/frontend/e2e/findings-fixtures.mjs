// Deterministic Findings-family fixtures for UI 2.0 visual/behaviour review (P2).
//
// Shapes follow frontend/src/features/findings/types.ts and features/ai-security/types.ts.
// All names, identifiers and counts are synthetic. These fixtures answer the browser's
// /api requests only; they do not reproduce backend filtering semantics beyond what is
// needed to make narrowing, paging and scope visibly observable. Not authenticated evidence.

const BASE = Date.parse('2026-10-24T12:00:00Z');
const day = 86_400_000;
const iso = (offsetDays) => new Date(BASE + offsetDays * day).toISOString();

const SEVERITIES = ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'LOW'];
const STATUSES = ['OPEN', 'OPEN', 'OPEN', 'OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED'];
const ASSETS = [
  ['prod-api-gw-01', 'HOST'], ['payments-svc', 'CONTAINER'], ['billing-core', 'HOST'], ['vpn-edge-02', 'HOST'],
  ['auth-svc', 'CONTAINER'], ['checkout-web', 'CONTAINER'], ['aks-node-pool-3', 'HOST'], ['etl-worker-07', 'HOST'],
];
const PACKAGES = [
  ['log4j-core', '2.14.1'], ['openssl', '3.0.7'], ['spring-webmvc', '5.3.18'], ['jackson-databind', '2.13.2'],
  ['lodash', '4.17.20'], ['nginx', '1.22.0'], ['semver', '7.5.1'], ['curl', '8.1.0'], ['glibc', '2.35'], ['postgresql-libs', '14.6'],
];
const OWNERS = ['Priya Raman', undefined, 'Marcus Lee', 'Ana Souza', 'Team Platform', undefined];
const GROUPS = ['Payments Platform', 'Core Infra', 'Identity', undefined];

export const findings = Array.from({ length: 62 }, (_, index) => {
  const [assetName, assetType] = ASSETS[index % ASSETS.length];
  const [packageName, packageVersion] = PACKAGES[index % PACKAGES.length];
  const severity = SEVERITIES[index % SEVERITIES.length];
  const status = STATUSES[index % STATUSES.length];
  const dueOffset = [-6, 3, 21, undefined, -1, 45][index % 6];
  const aiLinked = index % 9 === 2;
  return {
    id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
    displayId: `F-${10420 + index * 3}`,
    componentId: `component-${index + 1}`,
    assetName,
    assetIdentifier: `${assetName}.fixture.internal`,
    assetType,
    packageName,
    packageVersion,
    vulnerabilityId: `CVE-2026-${String(31337 - index * 397).padStart(5, '0')}`,
    source: 'NVD',
    creationSource: index % 3 === 0 ? 'MANUAL' : 'AUTOMATIC',
    severity,
    inKev: index % 4 === 1,
    epss: Number(((index * 7) % 97 / 100).toFixed(2)),
    riskScore: Number((9.8 - (index % 12) * 0.6).toFixed(1)),
    confidenceScore: 0.92,
    matchedBy: 'CPE',
    assignedTo: OWNERS[index % OWNERS.length],
    dueAt: dueOffset === undefined ? undefined : iso(dueOffset),
    evidence: 'cpe:2.3 match (fixture)',
    firstObservedAt: iso(-30 + (index % 20)),
    lastObservedAt: iso(-(index % 5)),
    decisionState: 'AFFECTED',
    status,
    updatedAt: iso(-(index % 5)),
    incidentId: index % 5 === 0 ? `INC00${41200 + index}` : undefined,
    incidentStatus: index % 5 === 0 ? 'In Progress' : undefined,
    ownerGroup: GROUPS[index % GROUPS.length],
    isEol: index % 11 === 4,
    affectedAiResources: aiLinked ? [{ id: `ai-res-${index}`, name: index % 2 ? 'support-agent-model' : 'claims-embedding-dataset', resourceKind: index % 2 ? 'MODEL' : 'DATASET' }] : undefined,
  };
});

const PAGE_SIZE = 25;

function dueBand(finding) {
  if (finding.status !== 'OPEN') return null;
  if (!finding.dueAt) return 'no-sla';
  const delta = Date.parse(finding.dueAt) - Date.now();
  if (delta < 0) return 'overdue';
  return delta < 7 * day ? 'due-soon' : 'on-track';
}

function narrow(items, params) {
  const all = (key) => params.getAll(key);
  return items.filter((finding) => {
    if (all('severity').length && !all('severity').includes(finding.severity)) return false;
    if (all('status').length && !all('status').includes(finding.status)) return false;
    if (all('creationSource').length && !all('creationSource').includes(finding.creationSource)) return false;
    if (all('assetType').length && !all('assetType').includes(finding.assetType)) return false;
    if (params.get('assetName') && finding.assetName !== params.get('assetName')) return false;
    if (params.get('vulnerabilityId') && !finding.vulnerabilityId.includes(params.get('vulnerabilityId'))) return false;
    if (params.get('packageName') && !finding.packageName.includes(params.get('packageName'))) return false;
    if (params.get('unassignedOnly') === 'true' && finding.assignedTo) return false;
    if (params.get('incidentLinked') === 'true' && !finding.incidentId) return false;
    if (params.get('dueDateBand') && dueBand(finding) !== params.get('dueDateBand')) return false;
    if (params.get('hasAffectedAiResource') === 'true' && !finding.affectedAiResources?.length) return false;
    const groupField = params.get('groupField');
    if (groupField && params.has('groupValue') && String(finding[groupKey(groupField)] ?? '') !== params.get('groupValue')) return false;
    return true;
  });
}

function groupKey(field) {
  return { severity: 'severity', status: 'status', assetName: 'assetName', asset: 'assetName', packageName: 'packageName', package: 'packageName', ownerGroup: 'ownerGroup', supportGroup: 'ownerGroup', assignedTo: 'assignedTo', owner: 'assignedTo' }[field] ?? field;
}

function counts(items, key) {
  const map = new Map();
  items.forEach((item) => map.set(item[key], (map.get(item[key]) ?? 0) + 1));
  return [...map.entries()].filter(([value]) => value != null).map(([value, count]) => ({ key: value, count }));
}

function findingPage(params) {
  const matched = narrow(findings, params);
  const cursorIndex = Number((params.get('cursor') ?? 'c0').replace('c', '')) || 0;
  const start = cursorIndex * PAGE_SIZE;
  const items = matched.slice(start, start + PAGE_SIZE);
  return {
    items,
    page: cursorIndex,
    size: PAGE_SIZE,
    totalItems: matched.length,
    totalPages: Math.max(1, Math.ceil(matched.length / PAGE_SIZE)),
    nextCursor: start + PAGE_SIZE < matched.length ? `c${cursorIndex + 1}` : null,
  };
}

function summary(params) {
  const open = narrow(findings, params).filter((finding) => finding.status === 'OPEN');
  return {
    openCount: open.length,
    criticalOpenCount: open.filter((finding) => finding.severity === 'CRITICAL').length,
    withIncidentCount: open.filter((finding) => finding.incidentId).length,
    unassignedOpenCount: open.filter((finding) => !finding.assignedTo).length,
    overdueOpenCount: open.filter((finding) => dueBand(finding) === 'overdue').length,
    noSlaOpenCount: open.filter((finding) => dueBand(finding) === 'no-sla').length,
  };
}

function distributions(params) {
  const scoped = narrow(findings, params);
  const topAssets = counts(scoped.filter((finding) => finding.status === 'OPEN'), 'assetName')
    .sort((left, right) => right.count - left.count).slice(0, 4).map(({ key, count }) => ({ assetName: key, count }));
  return { severityCounts: counts(scoped, 'severity'), statusCounts: counts(scoped, 'status'), topAssets };
}

function backlogHealth(params) {
  const scoped = narrow(findings, params);
  const band = (value) => scoped.filter((finding) => dueBand(finding) === value).length;
  return { overdue: band('overdue'), dueSoon: band('due-soon'), onTrack: band('on-track'), noSla: band('no-sla') };
}

const filterValues = {
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
  statuses: ['OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED'],
  decisionStates: ['AFFECTED'], matchMethods: ['CPE'], vexStatuses: [], vexFreshness: [], vexProviders: [],
  owners: OWNERS.filter(Boolean), supportGroups: GROUPS.filter(Boolean), assignedTo: OWNERS.filter(Boolean), ownershipSources: [],
};

export const aiFindings = [
  ['AIF-101B8AF0', 'HIGH', 'Guardrail contains a non-blocking filter', 'customer-support-guardrail', 'AZURE', 'AI_POSTURE'],
  ['AIF-209C7BD1', 'CRITICAL', 'Model endpoint allows public access', 'support-agent-model', 'AWS', 'AI_POSTURE'],
  ['AIF-31A0E442', 'HIGH', 'Agent can reach an unauthenticated knowledge base', 'claims-triage-agent', 'AWS', 'AI_EXPOSURE'],
  ['AIF-47D2C019', 'MEDIUM', 'Copilot agent shares connector credentials', 'hr-helpdesk-copilot', 'MICROSOFT_COPILOT', 'AI_POSTURE'],
  ['AIF-58F1A3B7', 'LOW', 'Prompt logging retention exceeds policy', 'sales-summary-agent', 'AZURE', 'AI_POSTURE'],
].map(([displayId, severity, title, artifactName, provider, findingKind], index) => ({
  id: `ai-finding-${index + 1}`,
  displayId,
  policyId: `policy.${provider.toLowerCase()}.${index + 1}`,
  policyVersion: '1.0.0',
  artifactId: `artifact-${index + 1}`,
  subjectType: findingKind === 'AI_EXPOSURE' ? 'EXPOSURE_PATH' : 'ARTIFACT',
  findingKind,
  exposurePaths: findingKind === 'AI_EXPOSURE' ? [{ id: 'exposure-1', title: 'Public agent → knowledge base', state: 'VALIDATED_EXPOSURE', status: 'OPEN' }] : [],
  artifactName,
  evidenceSource: provider,
  severity,
  status: index === 4 ? 'RESOLVED' : 'OPEN',
  title,
  evidence: { provider },
  reviewDisposition: 'UNREVIEWED',
  firstObservedAt: iso(-12 + index),
  lastObservedAt: iso(-index * 0.01),
  resolvedAt: index === 4 ? iso(-1) : null,
}));

const aiPolicy = (finding) => ({
  id: finding.policyId, version: '1.0.0', name: finding.title, severity: finding.severity, artifactTypes: ['MODEL'],
  requiredResourceFamilies: [], description: `${finding.title} (fixture policy).`, remediation: 'Restrict access to approved principals.',
  controlMappings: {}, available: true, enabled: true, openFindings: 1, lifetimeFindings: 3, lastEvaluatedAt: iso(0),
  decisionCoverage: 0.96, decisionCoverageThreshold: 0.9, decisionCoverageStatus: 'PASS', evaluatedArtifacts: 24, noDecisionCount: 1, lifecycle: 'PUBLISHED',
});

const actionQueue = [
  { id: 'exposure-1', kind: 'VALIDATED_EXPOSURE', title: 'Review public model access path', severity: 'CRITICAL', priority: 92, owner: 'AI Platform', provider: 'AWS', accountId: '111122223333', remediation: 'Restrict endpoint access', confidence: 0.94, lastObservedAt: iso(0) },
  { id: 'ai-finding-1', kind: 'POLICY_FINDING', title: 'Guardrail contains a non-blocking filter', severity: 'HIGH', priority: 71, owner: 'Support Engineering', provider: 'AZURE', accountId: 'sub-7f3a', remediation: 'Switch filter to blocking mode', confidence: null, lastObservedAt: iso(-0.1) },
];

const exposures = [
  ['exposure-1', 'Public agent → knowledge base', 'CRITICAL', 'VALIDATED_EXPOSURE', 0.94, 3],
  ['exposure-2', 'Shared connector → HR records', 'HIGH', 'EXPOSURE_HYPOTHESIS', 0.61, 2],
  ['exposure-3', 'Unrestricted model invoke role', 'MEDIUM', 'VALIDATED_EXPOSURE', 0.82, 1],
].map(([id, title, severity, state, confidence, affectedSystems], index) => ({
  id, correlationId: `corr.ai.${index + 1}`, correlationVersion: '2', title, severity, state, status: 'OPEN', confidence,
  rootCauseArtifactId: `artifact-${index + 2}`, firstObservedAt: iso(-9 + index), lastObservedAt: iso(-index * 0.2), findingId: null,
  affectedSystems, impact: 'Unauthenticated callers can retrieve internal documents through the agent.',
  rootCause: 'Knowledge base data source permits anonymous retrieval.', breakpoint: 'Require IAM authorisation on the retrieval API.',
  confidenceMethod: 'producer-calibrated',
}));

const priorities = exposures.map((exposure, index) => ({
  id: exposure.id, title: exposure.title, severity: exposure.severity, priority: 92 - index * 17, severityPoints: 40 - index * 8,
  confidencePoints: 20, publicExposurePoints: 15, criticalityPoints: 10, recencyPoints: 7 - index, activityPoints: 0,
  confidence: exposure.confidence, rootCauseArtifactId: exposure.rootCauseArtifactId, breakpoint: exposure.breakpoint,
  owner: index === 2 ? 'Unowned' : 'AI Platform', provider: 'AWS', accountId: '111122223333', lastObservedAt: exposure.lastObservedAt,
}));

const exposureDetail = (exposure) => ({
  exposure,
  observations: [{
    id: 'obs-1', runId: 'run-77', state: exposure.state, entryArtifactId: 'artifact-3', systemId: 'system-claims',
    pathJson: JSON.stringify({ hops: ['public-agent', 'retrieval-api', 'knowledge-base'] }),
    evidenceJson: JSON.stringify({ anonymousRetrieval: true, observedBy: 'fixture-producer' }),
    validFrom: iso(-2), validUntil: null, confidence: exposure.confidence, observedAt: iso(-0.5),
  }],
  associations: [{ systemId: 'system-claims', artifactId: null, role: 'ENTRY' }, { systemId: null, artifactId: 'artifact-3', role: 'ROOT_CAUSE' }],
});

const NOT_FOUND = Symbol('not-found');
export { NOT_FOUND };

/** Returns a JSON body, NOT_FOUND, or undefined when the request is outside the Findings family. */
export function findingsFixtureFor(rawUrl) {
  const url = new URL(rawUrl);
  const path = url.pathname.replace(/^\/api/, '');
  const params = url.searchParams;
  if (path === '/findings') return findingPage(params);
  if (path === '/findings/summary') return summary(params);
  if (path === '/findings/distributions') return distributions(params);
  if (path === '/findings/backlog-health') return backlogHealth(params);
  if (path === '/findings/filters') return filterValues;
  if (path === '/findings/queues') return [];
  if (path === '/findings/projection-status') return { lastComputedAt: iso(0), findingCount: findings.length, sourceFindingCount: findings.length, stale: false, driftCount: 0 };
  if (path === '/findings/groups') {
    const scoped = narrow(findings, params);
    return counts(scoped, groupKey(params.get('field') ?? 'severity')).sort((left, right) => right.count - left.count);
  }
  if (path === '/assets') return [];
  if (path.startsWith('/cve-detail/')) return NOT_FOUND;
  if (path === '/ai-security/findings') {
    const status = params.get('status');
    const provider = params.get('provider');
    const items = aiFindings.filter((finding) => (!status || finding.status === status) && (!provider || finding.evidenceSource === provider));
    return { items, page: 0, size: Number(params.get('size') ?? 50), total: items.length };
  }
  if (path.startsWith('/ai-security/findings/')) {
    return aiFindings.find((finding) => finding.id === decodeURIComponent(path.split('/')[3])) ?? NOT_FOUND;
  }
  if (path === '/ai-action-queue') return actionQueue;
  if (path === '/ai-policies') return aiFindings.map((finding) => ({ policyId: finding.policyId }));
  if (path.startsWith('/ai-policies/')) {
    const finding = aiFindings.find((candidate) => candidate.policyId === decodeURIComponent(path.split('/')[2]));
    return finding ? aiPolicy(finding) : NOT_FOUND;
  }
  if (path === '/ai-exposures') return { items: exposures, nextCursor: null };
  if (path.startsWith('/ai-exposures/')) {
    const exposure = exposures.find((candidate) => candidate.id === decodeURIComponent(path.split('/')[2]));
    return exposure ? exposureDetail(exposure) : NOT_FOUND;
  }
  if (path === '/ai-exposure-priorities') return priorities;
  if (path.startsWith('/ai-security/artifacts/')) return NOT_FOUND;
  return undefined;
}
