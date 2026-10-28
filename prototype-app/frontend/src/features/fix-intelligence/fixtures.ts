import type { ActorContext } from '../auth/types';
import type { FixDetail, FixListItem, FixListPage, FixSummary } from './types';

export const TENANT_ADMIN: ActorContext = {
  creator: false,
  principal: 'admin@example.test',
  userId: 'admin-1',
  tenantId: 'tenant-1',
  tenantName: 'Customer One',
  roles: ['TENANT_ADMIN']
};

export const ANALYST: ActorContext = { ...TENANT_ADMIN, userId: 'analyst-1', roles: ['SECURITY_ANALYST'] };
export const AUDITOR: ActorContext = { ...TENANT_ADMIN, userId: 'auditor-1', roles: ['READ_ONLY_AUDITOR'] };

export function summary(overrides: Partial<FixSummary> = {}): FixSummary {
  return {
    totalFixes: 0,
    criticalSeverity: 0,
    highPriority: 0,
    ecosystemsCovered: 0,
    severityDistribution: [],
    ecosystems: [],
    ...overrides
  };
}

export function listItem(overrides: Partial<FixListItem> = {}): FixListItem {
  return {
    id: 'fix-1',
    displayId: 'KB5034441',
    title: '2026-10 Cumulative Update',
    fixType: 'PATCH',
    severity: 'CRITICAL',
    ecosystem: 'WINDOWS',
    status: 'ACTIVE',
    sources: ['SCCM'],
    applicableAssets: 4,
    remediatedAssets: 3,
    coveragePercent: 75,
    cveCount: 2,
    updatedAt: '2026-10-20T10:00:00Z',
    ...overrides
  };
}

export function page(items: FixListItem[]): FixListPage {
  return { items, page: 0, size: 50, totalItems: items.length, totalPages: items.length ? 1 : 0 };
}

export function detail(overrides: Partial<FixDetail> = {}): FixDetail {
  return {
    id: 'fix-9',
    displayId: 'FIX-0A1B2C3D',
    title: 'Disable SMBv1',
    description: '<img src=x onerror=alert(1)>',
    fixType: 'WORKAROUND',
    severity: 'HIGH',
    ecosystem: 'WINDOWS',
    status: 'PROPOSED',
    origin: 'ANALYST',
    editable: true,
    owner: null,
    proposedBy: 'analyst-1',
    approvedBy: null,
    approvedAt: null,
    reviewDueAt: null,
    installationInstructions: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false',
    rollbackInstructions: null,
    knownLimitations: null,
    requiresReboot: null,
    estimatedDowntimeMinutes: null,
    version: 0,
    cves: [{ cveId: 'CVE-2017-0144', source: 'ANALYST', confidence: 'HIGH', severity: 'HIGH', inKev: true }],
    patchSources: [],
    control: { controlType: null, scopeDescription: null, verificationMethod: null, residualRisk: 'LOW' },
    applicableAssets: 0,
    remediatedAssets: 0,
    coveragePercent: null,
    assetTotal: 0,
    assets: [],
    createdAt: '2026-10-20T10:00:00Z',
    updatedAt: '2026-10-20T10:00:00Z',
    ...overrides
  };
}
