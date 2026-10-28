// Shared /api fixture routing for the UI 2.0 browser scripts (capture.mjs, findings-journey.mjs,
// cve-journey.mjs, inventory-journey.mjs, governance-journey.mjs, connect-journey.mjs, experience-journey.mjs).
// Resolution order: CVE workflow, Connectors and configuration (connect-fixtures.mjs), Inventory,
// Governance, remaining experience (experience-fixtures.mjs: dashboards, campaigns, operations,
// auth entry), Findings, then generic fallbacks. Connect runs before Inventory so /bom/sources and provider-scoped
// /ai-security/runs get connector data; unscoped /ai-security/runs falls through to Inventory.
// Every response is synthetic; no backend, token or customer data is involved.
import { NOT_FOUND, findingsFixtureFor } from './findings-fixtures.mjs';
import { createCveFixtureState, cveFixtureFor } from './cve-fixtures.mjs';
import { inventoryFixtureFor } from './inventory-fixtures.mjs';
import { governanceFixtureFor } from './governance-fixtures.mjs';
import { connectFixtureFor } from './connect-fixtures.mjs';
import { experienceFixtureFor } from './experience-fixtures.mjs';
import { fixFixtureFor } from './fix-fixtures.mjs';

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

// Endpoints the generic fallbacks below answer on purpose: pages that render an empty state
// from `{}` or an empty page. Any other request reaching the fallback has no fixture, so the
// script's result would not reflect real data; it is recorded and fails the run.
// Each entry was reviewed against a full journeys + sweep run.
const EXPECTED_FALLBACKS = [
  // experience-journey only checks that /operations/quality redirects to the inventory quality
  // tab; that tab's issue list renders its empty state.
  /^GET \/api\/operations\/quality\/issues$/,
  // route-sweep renders /vuln-repo/vulnerabilities as the platform owner to check presentation
  // only; the platform-wide list renders empty. Journeys cover the tenant list with fixtures.
  /^GET \/api\/platform\/vuln-repo\/vulnerabilities$/,
];

const unexpectedApi = new Set();

/** `METHOD /api/path` for each /api request that reached a fallback without being expected. */
export function unexpectedApiRequests() {
  return [...unexpectedApi].sort();
}

/** Prints unexpected /api requests and marks the process failed when there are any. */
export function failOnUnexpectedApi() {
  const unexpected = unexpectedApiRequests();
  for (const request of unexpected) console.log(`UNEXPECTED API ${request}`);
  if (unexpected.length) process.exitCode = 1;
}

function fallback(pathname, method, body) {
  if (!EXPECTED_FALLBACKS.some((pattern) => pattern.test(`${method} ${pathname}`))) unexpectedApi.add(`${method} ${pathname}`);
  return body;
}

export function fixtureFor(url, actorOverride = actor, method = 'GET') {
  const { pathname } = new URL(url);
  const findingsFixture = findingsFixtureFor(url);
  if (findingsFixture !== undefined) return findingsFixture;
  if (pathname.endsWith('/api/me')) return actorOverride;
  if (pathname.endsWith('/api/auth/csrf')) return { token: 'fixture' };
  if (pathname.endsWith('/vuln-repo/dashboard')) return vulnRepoDashboard;
  if (/summary|distribution|stats|dashboard|health|overview|count/i.test(pathname)) return fallback(pathname, method, {});
  return fallback(pathname, method, emptyPage);
}

/** Answers every /api request on the context from fixtures; `onRequest` sees each request. */
export async function routeFixtures(context, { actorOverride = actor, onRequest, cveState = createCveFixtureState() } = {}) {
  await context.route((url) => url.pathname.startsWith('/api/'), (route) => {
    const request = route.request();
    onRequest?.(request);
    const cve = cveFixtureFor(request.url(), request.method(), cveState);
    if (cve !== undefined) return route.fulfill(cve);
    const connect = connectFixtureFor(request.url(), request.method(), request.postData());
    if (connect !== undefined) return route.fulfill(connect);
    const inventory = inventoryFixtureFor(request.url(), request.method());
    if (inventory !== undefined) return route.fulfill(inventory);
    const governance = governanceFixtureFor(request.url(), request.method(), request.postData());
    if (governance !== undefined) return route.fulfill(governance);
    const experience = experienceFixtureFor(request.url(), request.method(), request.postData());
    if (experience !== undefined) return route.fulfill(experience);
    const fix = fixFixtureFor(request.url(), request.method());
    if (fix !== undefined) return route.fulfill(fix);
    const body = fixtureFor(request.url(), actorOverride, request.method());
    return body === NOT_FOUND
      ? route.fulfill({ status: 404, json: { message: 'Not found (fixture)' } })
      : route.fulfill({ json: body });
  });
}
