// Fix Intelligence and Cloud Resources fixtures: one imported patch and one analyst workaround,
// the Remediation options panel context, and an empty cloud resource inventory.
import { FIXED_TIME } from './time.mjs';

const day = 24 * 60 * 60 * 1000;
const iso = (offsetDays) => new Date(FIXED_TIME + offsetDays * day).toISOString();
const ok = (json) => ({ status: 200, json });
const notFound = { status: 404, json: { message: 'Not found (fixture)' } };

export const PRIMARY_FIX_ID = 'fix-kb5034441';
export const WORKAROUND_FIX_ID = 'fix-smbv1';

const fixes = [
  {
    id: PRIMARY_FIX_ID, displayId: 'KB5034441', title: '2026-10 Cumulative Update for Windows Server 2022', fixType: 'PATCH', severity: 'CRITICAL',
    ecosystem: 'WINDOWS', status: 'ACTIVE', sources: ['SCCM'], applicableAssets: 4, remediatedAssets: 3, coveragePercent: 75, cveCount: 2, updatedAt: iso(-1),
  },
  {
    id: WORKAROUND_FIX_ID, displayId: 'FIX-0A1B2C3D', title: 'Disable SMBv1', fixType: 'WORKAROUND', severity: 'HIGH',
    ecosystem: 'WINDOWS', status: 'PROPOSED', sources: ['ANALYST'], applicableAssets: 0, remediatedAssets: 0, coveragePercent: null, cveCount: 1, updatedAt: iso(-2),
  },
];

const detailFor = (fix) => ({
  ...fix,
  description: fix.fixType === 'PATCH' ? 'Monthly security rollup (fixture).' : 'Turn off the SMBv1 server protocol until the patch is deployed (fixture).',
  origin: fix.fixType === 'PATCH' ? 'PATCH_TOOL' : 'ANALYST',
  editable: fix.fixType !== 'PATCH',
  owner: null, proposedBy: fix.fixType === 'PATCH' ? null : 'analyst-1', approvedBy: null, approvedAt: null, reviewDueAt: null,
  installationInstructions: fix.fixType === 'PATCH' ? null : 'Set-SmbServerConfiguration -EnableSMB1Protocol $false',
  rollbackInstructions: null, knownLimitations: null, requiresReboot: fix.fixType === 'PATCH' ? true : null, estimatedDowntimeMinutes: null, version: 0,
  cves: [{ cveId: 'CVE-2017-0144', source: fix.fixType === 'PATCH' ? 'SCCM' : 'ANALYST', confidence: 'HIGH', severity: 'HIGH', inKev: true }],
  patchSources: fix.fixType === 'PATCH'
    ? [{ provider: 'SCCM', externalId: '16819244', kbArticle: 'KB5034441', bulletinId: null, vendor: 'Microsoft', product: 'Windows Server 2022',
      classification: 'Security Updates', vendorSeverity: 'Critical', releaseDate: iso(-14), superseded: false, infoUrl: null, lastSeenAt: iso(-1) }]
    : [],
  control: fix.fixType === 'PATCH' ? null : { controlType: null, scopeDescription: null, verificationMethod: null, residualRisk: 'LOW' },
  assetTotal: fix.fixType === 'PATCH' ? 1 : 0,
  assets: fix.fixType === 'PATCH'
    ? [{ assetId: 'asset-web-01', assetName: 'web-01', assetIdentifier: 'web-01.corp.example', provider: 'SCCM', status: 'INSTALLED',
      deploymentName: 'October patching', scheduledAt: iso(-5), deadlineAt: iso(-3), installedAt: iso(-4), errorCode: null, lastReportedAt: iso(-1) }]
    : [],
  createdAt: iso(-14),
});

const bucket = (key, count, total) => ({ key, count, percent: total ? Math.round((count * 100) / total) : 0 });

const inView = (view) => (view === 'patches' ? fixes.filter((fix) => fix.fixType === 'PATCH')
  : view === 'workarounds' ? fixes.filter((fix) => fix.fixType === 'WORKAROUND')
  : view === 'compensating-controls' ? []
  : fixes);

function summary(view) {
  const items = inView(view);
  const count = (severity) => items.filter((fix) => fix.severity === severity).length;
  return {
    totalFixes: items.length, criticalSeverity: count('CRITICAL'), highPriority: count('CRITICAL') + count('HIGH'), ecosystemsCovered: items.length ? 1 : 0,
    severityDistribution: ['CRITICAL', 'HIGH'].map((severity) => bucket(severity, count(severity), items.length)),
    ecosystems: items.length ? [bucket('WINDOWS', items.length, items.length)] : [],
  };
}

const context = (params) => ({
  cveId: params.get('cveId'), assetId: params.get('assetId'),
  fixes: [{ fixId: PRIMARY_FIX_ID, displayId: 'KB5034441', title: fixes[0].title, fixType: 'PATCH', status: 'ACTIVE', severity: 'CRITICAL',
    cveIds: ['CVE-2017-0144'], assetStatus: params.get('assetId') ? 'MISSING' : null, assetProvider: params.get('assetId') ? 'SCCM' : null,
    scheduledAt: null, deadlineAt: null, installedAt: null, coveragePercent: 75 }],
});

const emptyFacets = { providers: [], accounts: [], regions: [], resourceTypes: [], states: [] };

/** Returns a Playwright fulfil object for Fix Intelligence and Cloud Resources requests, or undefined. */
export function fixFixtureFor(rawUrl, method = 'GET') {
  const url = new URL(rawUrl);
  const path = url.pathname.replace(/^\/api/, '');
  if (path === '/cloud-resources') return ok({ items: [], page: 0, size: 50, totalItems: 0, totalPages: 0, facets: emptyFacets });
  if (!path.startsWith('/fix-intelligence/') || method !== 'GET') return undefined;
  if (path === '/fix-intelligence/summary') return ok(summary(url.searchParams.get('view') ?? 'all'));
  if (path === '/fix-intelligence/context') return ok(context(url.searchParams));
  if (path === '/fix-intelligence/fixes') {
    const items = inView(url.searchParams.get('view') ?? 'all');
    return ok({ items, page: 0, size: 50, totalItems: items.length, totalPages: items.length ? 1 : 0 });
  }
  const detail = path.match(/^\/fix-intelligence\/fixes\/([^/]+)$/);
  if (detail) {
    const fix = fixes.find((candidate) => candidate.id === decodeURIComponent(detail[1]));
    return fix ? ok(detailFor(fix)) : notFound;
  }
  return undefined;
}
