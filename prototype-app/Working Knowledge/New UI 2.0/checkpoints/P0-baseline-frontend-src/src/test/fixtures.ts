import type { Finding, FindingFilterValues, FindingPage } from '../features/findings/types';
import type { RiskPolicy } from '../features/configurations/types';
import { DEFAULT_FINDINGS_SCORE_CONFIG_JSON } from '../features/configurations/defaults';

/**
 * Page-test fixture builders. Centralised so a single test doesn't have to
 * repeat the 30-field {@link RiskPolicy} or 25-field {@link Finding} object
 * just to render a page.
 *
 * <p>Each builder returns a complete, valid object using realistic defaults.
 * Pass an `overrides` object to change only the fields the test cares about.
 */

export function buildFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: '11111111-1111-1111-1111-111111111111',
    displayId: 'F-001',
    componentId: 'cmp-1',
    assetName: 'web-prod-01',
    assetIdentifier: 'web-prod-01.example.com',
    assetType: 'HOST',
    packageName: 'openssl',
    packageVersion: '1.1.1k',
    vulnerabilityId: 'CVE-2026-1234',
    source: 'NVD',
    creationSource: 'AUTOMATIC',
    severity: 'CRITICAL',
    inKev: true,
    epss: 0.42,
    riskScore: 9.1,
    confidenceScore: 0.95,
    matchedBy: 'CPE',
    evidence: '{}',
    firstObservedAt: '2026-04-01T00:00:00Z',
    lastObservedAt: '2026-04-25T00:00:00Z',
    decisionState: 'AFFECTED',
    status: 'OPEN',
    updatedAt: '2026-04-25T00:00:00Z',
    ...overrides,
  };
}

export function defaultRiskPolicy(overrides: Partial<RiskPolicy> = {}): RiskPolicy {
  return {
    criticalThreshold: 9,
    highThreshold: 7,
    criticalSlaDays: 7,
    highSlaDays: 14,
    mediumSlaDays: 30,
    lowSlaDays: 60,
    assetCriticalSlaMultiplier: 0.5,
    assetHighSlaMultiplier: 0.75,
    assetMediumSlaMultiplier: 1,
    assetLowSlaMultiplier: 1.25,
    autoCloseEnabled: false,
    autoCloseAfterDays: 30,
    autoCloseRequiredConsecutiveMisses: 2,
    autoCloseNotObservedEnabled: true,
    autoCloseComponentRemovedEnabled: true,
    autoCloseAssetRetiredEnabled: true,
    autoCloseSourceDisabledEnabled: false,
    autoCloseDuplicateEnabled: true,
    autoCloseRunIntervalDays: 1,
    findingGenerationMode: 'AUTO',
    findingsScoreConfig: DEFAULT_FINDINGS_SCORE_CONFIG_JSON,
    triageExploitabilityWeight: 1,
    triageBlastRadiusWeight: 1,
    triageEolRiskWeight: 1,
    triageSlaBreachWeight: 1,
    triageMissingOwnerBoost: 1,
    triagePatchGapBoost: 1,
    ...overrides,
  };
}

export function defaultFindingFilterValues(
  overrides: Partial<FindingFilterValues> = {}
): FindingFilterValues {
  return {
    severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'],
    statuses: ['OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED'],
    decisionStates: ['AFFECTED', 'NOT_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION', 'NEEDS_REVIEW'],
    matchMethods: ['CPE', 'PURL'],
    vexStatuses: [],
    vexFreshness: [],
    vexProviders: [],
    owners: [],
    supportGroups: [],
    assignedTo: [],
    ownershipSources: [],
    ...overrides,
  };
}

/** Wraps a list of items in the standard paginated envelope used by `Page<T>` endpoints. */
export function pageOf<T>(items: T[], size = 25): {
  items: T[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
} {
  return { items, page: 0, size, totalItems: items.length, totalPages: items.length === 0 ? 0 : 1 };
}

export function findingPageOf(items: Finding[], size = 25): FindingPage {
  return pageOf(items, size);
}
