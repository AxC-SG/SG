// Shared /api fixture routing for the UI 2.0 browser scripts (capture.mjs, findings-journey.mjs,
// cve-journey.mjs, inventory-journey.mjs, governance-journey.mjs). Resolution order: CVE workflow,
// Inventory, Governance, Findings, then generic fallbacks.
// Every response is synthetic; no backend, token or customer data is involved.
import { NOT_FOUND, findingsFixtureFor } from './findings-fixtures.mjs';
import { createCveFixtureState, cveFixtureFor } from './cve-fixtures.mjs';
import { inventoryFixtureFor } from './inventory-fixtures.mjs';
import { governanceFixtureFor } from './governance-fixtures.mjs';

export const actor = {
  creator: false,
  principal: 'fixture.analyst@example.test',
  userId: 'fixture-analyst',
  tenantId: '00000000-0000-0000-0000-000000000001',
  tenantName: 'Fixture Tenant',
  roles: ['TENANT_ADMIN', 'SECURITY_ANALYST'],
  allowedTenants: [],
  platformScope: false,
  actingAsPlatformOwner: false,
  entitlements: { 'ai.security': true },
};

const emptyPage = { items: [], content: [], page: 0, size: 25, totalItems: 0, totalElements: 0, totalPages: 0, nextCursor: null };

const vulnRepoDashboard = {
  summaryCards: Object.fromEntries([
    'trackedCount', 'trackedAddedLastWeek', 'applicableCount', 'applicableAddedLastWeek', 'impactedInvestigationDoneCount',
    'impactedAddedLastWeek', 'remediationCveCount', 'needsAttentionCount', 'criticalCount', 'exploitCount', 'exploitCoveragePercent',
    'impactedCriticalCount', 'impactedHighCount', 'impactedMediumCount', 'impactedLowCount', 'impactedKevCount', 'kevAddedLastWeek',
    'criticalUninvestigatedCount', 'kevReinvestigationCount',
  ].map((key) => [key, 0])),
  severityBreakdown: [],
  resolutionStatus: { unresolvedCount: 0, resolvedCount: 0, inProgressCount: 0, acceptedRiskCount: 0 },
  criticalUnresolved: [],
};

export function fixtureFor(url, actorOverride = actor) {
  const { pathname } = new URL(url);
  const findingsFixture = findingsFixtureFor(url);
  if (findingsFixture !== undefined) return findingsFixture;
  if (pathname.endsWith('/api/me')) return actorOverride;
  if (pathname.endsWith('/api/auth/csrf')) return { token: 'fixture' };
  if (pathname.includes('/risk-policy')) return {};
  if (pathname.endsWith('/vuln-repo/dashboard')) return vulnRepoDashboard;
  if (/summary|distribution|stats|dashboard|health|overview|count/i.test(pathname)) return {};
  return emptyPage;
}

/** Answers every /api request on the context from fixtures; `onRequest` sees each request. */
export async function routeFixtures(context, { actorOverride = actor, onRequest, cveState = createCveFixtureState() } = {}) {
  await context.route((url) => url.pathname.startsWith('/api/'), (route) => {
    const request = route.request();
    onRequest?.(request);
    const cve = cveFixtureFor(request.url(), request.method(), cveState);
    if (cve !== undefined) return route.fulfill(cve);
    const inventory = inventoryFixtureFor(request.url(), request.method());
    if (inventory !== undefined) return route.fulfill(inventory);
    const governance = governanceFixtureFor(request.url(), request.method(), request.postData());
    if (governance !== undefined) return route.fulfill(governance);
    const body = fixtureFor(request.url(), actorOverride);
    return body === NOT_FOUND
      ? route.fulfill({ status: 404, json: { message: 'Not found (fixture)' } })
      : route.fulfill({ json: body });
  });
}
