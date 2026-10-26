import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type {
  Finding,
  FindingBacklogHealth,
  FindingDistributions,
  FindingFilterValues,
  FindingProjectionStatus,
  FindingQueueDefinition,
  FindingPage,
  FindingSummary
} from '../features/findings/types';
import type { RiskPolicy } from '../features/configurations/types';
import { renderWithProviders } from '../test/test-utils';
import { FindingsPage } from './FindingsPage';

const ACTOR: ActorContext = {
  creator: false,
  principal: 'analyst@example.com',
  userId: 'user-1',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_SECURITY_ANALYST'],
};

function buildFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
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
    assignedTo: 'analyst@example.com',
    dueAt: '2026-05-15T00:00:00Z',
    evidence: '{}',
    firstObservedAt: '2026-04-01T00:00:00Z',
    lastObservedAt: '2026-04-25T00:00:00Z',
    decisionState: 'AFFECTED',
    status: 'OPEN',
    updatedAt: '2026-04-25T00:00:00Z',
    ...overrides,
  };
}

const FILTER_VALUES: FindingFilterValues = {
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
};

const RISK_POLICY: RiskPolicy = {
  criticalThreshold: 9, highThreshold: 7,
  criticalSlaDays: 7, highSlaDays: 14, mediumSlaDays: 30, lowSlaDays: 60,
  assetCriticalSlaMultiplier: 0.5, assetHighSlaMultiplier: 0.75,
  assetMediumSlaMultiplier: 1, assetLowSlaMultiplier: 1.25,
  autoCloseEnabled: false, autoCloseAfterDays: 30, findingGenerationMode: 'AUTO',
  autoCloseRequiredConsecutiveMisses: 2,
  autoCloseNotObservedEnabled: true,
  autoCloseComponentRemovedEnabled: true,
  autoCloseAssetRetiredEnabled: true,
  autoCloseSourceDisabledEnabled: false,
  autoCloseDuplicateEnabled: true,
  autoCloseRunIntervalDays: 1,
  triageExploitabilityWeight: 1, triageBlastRadiusWeight: 1, triageEolRiskWeight: 1,
  triageSlaBreachWeight: 1, triageMissingOwnerBoost: 1, triagePatchGapBoost: 1,
};

function pageOf(items: Finding[]): FindingPage {
  return { items, page: 0, size: 25, totalItems: items.length, totalPages: 1, nextCursor: null };
}

const FINDING_SUMMARY: FindingSummary = {
  openCount: 1,
  criticalOpenCount: 1,
  withIncidentCount: 0,
  unassignedOpenCount: 0,
  overdueOpenCount: 1,
  noSlaOpenCount: 0,
};

const FINDING_DISTRIBUTIONS: FindingDistributions = {
  severityCounts: [{ key: 'CRITICAL', count: 1 }],
  statusCounts: [{ key: 'OPEN', count: 1 }],
  topAssets: [{ assetName: 'web-prod-01', count: 1 }],
};

const FINDING_BACKLOG_HEALTH: FindingBacklogHealth = {
  overdue: 1,
  dueSoon: 0,
  onTrack: 0,
  noSla: 0,
};

const FINDING_PROJECTION_STATUS: FindingProjectionStatus = {
  lastComputedAt: '2026-06-05T10:15:30Z',
  findingCount: 12,
  sourceFindingCount: 12,
  stale: false,
  driftCount: 0,
  lastRebuildDurationMs: 241,
};

const FINDING_QUEUES: FindingQueueDefinition[] = [
  {
    id: null,
    key: 'all-findings',
    title: 'All Findings',
    description: 'Full findings backlog across the active tenant.',
    kind: 'BUILT_IN',
    ownerType: 'SYSTEM',
    editable: false,
    isDefault: false,
    matchingCount: 1,
    filter: {},
    summary: FINDING_SUMMARY,
  },
  {
    id: null,
    key: 'critical-open',
    title: 'Critical Open',
    description: 'Open findings currently scored at critical severity.',
    kind: 'BUILT_IN',
    ownerType: 'SYSTEM',
    editable: false,
    isDefault: false,
    matchingCount: 1,
    filter: { severity: ['CRITICAL'], status: ['OPEN'] },
    summary: FINDING_SUMMARY,
  },
  {
    id: 'queue-1',
    key: 'personal:queue-1',
    title: 'My Queue',
    description: 'Saved personal queue',
    kind: 'PERSONAL',
    ownerType: 'USER',
    editable: true,
    isDefault: true,
    matchingCount: 1,
    filter: { severity: ['CRITICAL'], status: ['OPEN'], assignedTo: 'analyst@example.com' },
    summary: FINDING_SUMMARY,
  },
];

function mockFindingsWorkspace() {
  const listFindings = vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
  const summary = vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
  const distributions = vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
  const backlog = vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
  vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
  vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
  vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
  return { listFindings, summary, distributions, backlog };
}

describe('FindingsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('preserves repeated deep-link filters and an explicit queue in the server request', async () => {
    const { listFindings } = mockFindingsWorkspace();
    renderWithProviders(<FindingsPage />, { route: '/findings?queue=all-findings&severity=HIGH&severity=CRITICAL&status=OPEN&creationSource=MANUAL&creationSource=invalid&vulnerabilityId=CVE-2026&packageName=openssl&assetName=web-prod&assetType=HOST&assetType=CONTAINER' });
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({
      queueKey: 'all-findings', severity: ['HIGH', 'CRITICAL'], status: ['OPEN'], creationSource: ['MANUAL'],
      vulnerabilityId: 'CVE-2026', packageName: 'openssl', assetName: 'web-prod', assetType: ['HOST', 'CONTAINER'], limit: 25,
    })));
  });

  it('combines column selections and removes only the chosen filter chip', async () => {
    const { listFindings } = mockFindingsWorkspace();
    renderWithProviders(<FindingsPage />, { route: '/findings?queue=all-findings' });
    await screen.findByText('F-001');
    fireEvent.click(screen.getByTitle('Filter Severity'));
    fireEvent.click(screen.getByRole('checkbox', { name: 'HIGH' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'CRITICAL' }));
    fireEvent.mouseDown(document.body);
    fireEvent.click(screen.getByTitle('Filter Status'));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Open' }));
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ severity: ['HIGH', 'CRITICAL'], status: ['OPEN'] })));
    fireEvent.mouseDown(document.body);
    const chip = screen.getByText('Severity: HIGH, CRITICAL').closest('.fpl-chip')!;
    fireEvent.click(within(chip as HTMLElement).getByRole('button', { name: 'Remove filter' }));
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ severity: undefined, status: ['OPEN'] })));
  });

  it('keeps the open column filter mounted and focused while its selection re-renders the page', async () => {
    const { listFindings } = mockFindingsWorkspace();
    renderWithProviders(<FindingsPage />, { route: '/findings?queue=all-findings' });
    await screen.findByText('F-001');
    fireEvent.click(screen.getByTitle('Filter Status'));
    const popover = document.querySelector('.fpl-col-filter-popover');
    const open = screen.getByRole('checkbox', { name: 'Open' });
    open.focus();
    fireEvent.click(open);
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ status: ['OPEN'] })));
    // A remounted popover drops clicks that span a re-render and loses keyboard focus.
    expect(document.querySelector('.fpl-col-filter-popover')).toBe(popover);
    expect(open).toBeInTheDocument();
    expect(open).toHaveFocus();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Resolved' }));
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ status: ['OPEN', 'RESOLVED'] })));
  });

  it('toggles a severity widget and clears status and SLA narrowing without changing queue totals', async () => {
    const spies = mockFindingsWorkspace();
    renderWithProviders(<FindingsPage />, { route: '/findings?queue=all-findings&status=OPEN' });
    await screen.findByText('F-001');
    const severityWidget = screen.getByText('Exposure by Severity').closest('.fpl-widget')!;
    const critical = (await within(severityWidget as HTMLElement).findByText('CRITICAL')).closest('.fpl-legend-row')!;
    fireEvent.click(critical);
    await waitFor(() => expect(spies.listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ severity: ['CRITICAL'], status: undefined, dueDateBand: undefined })));
    fireEvent.click(critical);
    await waitFor(() => expect(spies.listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ severity: undefined, status: undefined })));
    for (const spy of [spies.summary, spies.distributions, spies.backlog]) {
      expect(spy.mock.calls.every(([params]) => Object.keys(params ?? {}).every(key => key === 'queueKey'))).toBe(true);
    }
  });

  it('keeps finding ID and minimum risk filters local to the fetched page', async () => {
    const { listFindings } = mockFindingsWorkspace();
    renderWithProviders(<FindingsPage />);
    await screen.findByText('F-001');
    fireEvent.click(screen.getByTitle('Filter Finding ID'));
    fireEvent.change(screen.getByPlaceholderText('Search Finding ID…'), { target: { value: 'missing-id' } });
    expect(screen.queryByText('F-001')).not.toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('Search Finding ID…'), { target: { value: 'f-001' } });
    expect(screen.getByText('F-001')).toBeInTheDocument();
    fireEvent.mouseDown(document.body);
    fireEvent.click(screen.getByTitle('Filter Risk'));
    fireEvent.change(screen.getByPlaceholderText('Min risk score'), { target: { value: '9.5' } });
    expect(screen.queryByText('F-001')).not.toBeInTheDocument();
    expect(listFindings.mock.calls.every(([params]) => !('findingId' in (params ?? {})) && !('risk' in (params ?? {})))).toBe(true);
  });

  it('resets cursor paging when a server filter changes and keeps existing rows during refresh', async () => {
    const { listFindings } = mockFindingsWorkspace();
    vi.mocked(api.listFindingQueues).mockResolvedValue(FINDING_QUEUES.map(queue => ({ ...queue, isDefault: false })));
    listFindings.mockResolvedValue({ ...pageOf([buildFinding()]), totalItems: 50, totalPages: 2, nextCursor: 'cursor-page-2' });
    renderWithProviders(<FindingsPage />, { route: '/findings?queue=all-findings' });
    await screen.findByText('F-001');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Next →' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Next →' }));
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: 'cursor-page-2' })));
    let finish!: (value: FindingPage) => void;
    listFindings.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    fireEvent.click(screen.getByTitle('Filter CVE ID'));
    fireEvent.change(screen.getByPlaceholderText('Search CVE ID…'), { target: { value: 'CVE-2026' } });
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ vulnerabilityId: 'CVE-2026', cursor: undefined })));
    expect(screen.getByText('F-001')).toBeInTheDocument();
    finish(pageOf([buildFinding()]));
    await waitFor(() => expect(screen.getByRole('button', { name: '← Prev' })).toBeDisabled());
  });

  it('selects rows without navigating and leaves finding/CVE links outside selection', async () => {
    mockFindingsWorkspace();
    const openCve = vi.fn();
    renderWithProviders(<ActorContextState.Provider value={ACTOR}><FindingsPage onOpenCveWorkbench={openCve} /></ActorContextState.Provider>);
    const link = await screen.findByRole('link', { name: 'F-001' });
    fireEvent.click(link.closest('tr')!);
    expect(screen.getByRole('checkbox', { name: 'Select row' })).toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'CVE-2026-1234' }));
    expect(openCve).toHaveBeenCalledWith('CVE-2026-1234');
    expect(screen.getByRole('checkbox', { name: 'Select row' })).toBeChecked();
    expect(link).toHaveAttribute('href', '/findings/F-001');
    expect(screen.getByRole('button', { name: 'Resolve' })).toBeEnabled();
  });

  it('clears all ad-hoc filters while preserving the selected queue', async () => {
    const { listFindings } = mockFindingsWorkspace();
    renderWithProviders(<FindingsPage />, { route: '/findings?queue=critical-open&severity=CRITICAL&status=OPEN&assetType=HOST' });
    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ queueKey: 'critical-open', severity: undefined, status: undefined, assetType: undefined })));
  });

  it('preserves stored column preferences and read-only workflow gates', async () => {
    mockFindingsWorkspace();
    localStorage.setItem('findings-col-vis-v2', JSON.stringify(['findingId', 'cveId', 'severity']));
    renderWithProviders(<ActorContextState.Provider value={{ ...ACTOR, roles: ['ROLE_READ_ONLY_AUDITOR'] }}><FindingsPage /></ActorContextState.Provider>);
    await screen.findByText('F-001');
    expect(screen.queryByRole('columnheader', { name: 'Asset' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select row' }));
    expect(screen.getByRole('button', { name: 'Resolve' })).toBeDisabled();
  });

  it('renders the findings table with mocked data', async () => {
    const listFindingsSpy = vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    await screen.findByText('F-001');
    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument();
    expect(await screen.findByText(/Last updated/i)).toBeInTheDocument();
    expect(screen.queryByText(/Projection healthy/i)).not.toBeInTheDocument();
    expect(api.getFindingProjectionStatus).not.toHaveBeenCalled();
    // Asset name appears in both the row and the "Top Assets at Risk" widget
    expect(screen.getAllByText('web-prod-01').length).toBeGreaterThan(0);
    expect(screen.getByRole('columnheader', { name: /Finding ID/ })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /CVE ID/ })).toBeInTheDocument();
    expect(listFindingsSpy).toHaveBeenCalled();
  });

  it('shows the empty state when there are no findings and no active filter chips beyond defaults', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue({ ...FINDING_SUMMARY, openCount: 0, criticalOpenCount: 0, overdueOpenCount: 0 });
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue({ severityCounts: [], statusCounts: [], topAssets: [] });
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue({ overdue: 0, dueSoon: 0, onTrack: 0, noSla: 0 });
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    // No findings and no active chips → "No findings yet" onboarding state.
    await waitFor(() => {
      expect(screen.getByText(/No findings yet/i)).toBeInTheDocument();
    });
  });

  it('renders the SLA & Due Date widget header from the dashboard widgets row', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    await screen.findByText('F-001');
    expect(screen.getByText('Exposure by Severity')).toBeInTheDocument();
    expect(screen.getByText('Findings by Status')).toBeInTheDocument();
    expect(screen.getByText('SLA & Due Date')).toBeInTheDocument();
  });

  it('keeps queue-level widget totals while a key indicator filters only the list', async () => {
    const spies = mockFindingsWorkspace();

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    const unassignedCard = screen.getByText('Unassigned remediation').closest('.fpl-kpi-card');
    expect(unassignedCard).not.toBeNull();
    fireEvent.click(unassignedCard!);

    await waitFor(() => {
      expect(spies.listFindings).toHaveBeenCalledWith(expect.objectContaining({
        status: ['OPEN'],
        unassignedOnly: true,
      }));
    });
    for (const spy of [spies.summary, spies.distributions, spies.backlog]) {
      expect(spy.mock.calls.every(([params]) => !params?.unassignedOnly && !params?.dueDateBand)).toBe(true);
    }
  });

  it('loads full-dataset groups and applies a clicked group to the findings list', async () => {
    const { listFindings } = mockFindingsWorkspace();
    const groups = vi.spyOn(api, 'getFindingGroups').mockResolvedValue([{ key: 'CRITICAL', count: 90 }]);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: 'None' }));
    fireEvent.click(screen.getByRole('button', { name: 'Severity' }));

    await waitFor(() => {
      expect(groups).toHaveBeenCalledWith('severity', expect.objectContaining({ queueKey: expect.any(String) }));
    });
    const criticalGroup = await screen.findByRole('button', { name: /CRITICAL.*90/ });
    fireEvent.click(criticalGroup);

    await waitFor(() => {
      expect(listFindings).toHaveBeenCalledWith(expect.objectContaining({
        groupField: 'severity',
        groupValue: 'CRITICAL',
      }));
    });
  });

  it('passes the default queueKey through the findings queries', async () => {
    const listFindingsSpy = vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');

    await waitFor(() => {
      expect(listFindingsSpy).toHaveBeenCalledWith(expect.objectContaining({ queueKey: expect.any(String) }));
    });
  });

  it('saves the current view as a personal queue', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const createQueueSpy = vi.spyOn(api, 'createFindingQueue').mockResolvedValue(FINDING_QUEUES[2]!);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getAllByRole('button', { name: /Save Current View/i })[0]!);
    fireEvent.change(screen.getByPlaceholderText(/Queue title/i), { target: { value: 'Ops Queue' } });
    fireEvent.click(screen.getByRole('button', { name: /Save Queue/i }));

    await waitFor(() => {
      expect(createQueueSpy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Ops Queue' }));
    });
  });

  it('edits an existing personal queue', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const updateQueueSpy = vi.spyOn(api, 'updateFindingQueue').mockResolvedValue({
      ...FINDING_QUEUES[2]!,
      title: 'Ops Escalations',
      description: 'Updated queue scope',
      isDefault: false,
    });

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: /Edit Queue/i }));
    fireEvent.change(screen.getByPlaceholderText(/Queue title/i), { target: { value: 'Ops Escalations' } });
    fireEvent.change(screen.getByPlaceholderText(/Optional description/i), { target: { value: 'Updated queue scope' } });
    fireEvent.click(screen.getByRole('checkbox', { name: /Set as my default queue/i }));
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }));

    await waitFor(() => {
      expect(updateQueueSpy).toHaveBeenCalledWith('personal:queue-1', expect.objectContaining({
        title: 'Ops Escalations',
        description: 'Updated queue scope',
        setAsDefault: false,
      }));
    });
  });

  it('duplicates and sets a personal queue as default from the findings toolbar', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue([
      FINDING_QUEUES[0]!,
      FINDING_QUEUES[1]!,
      { ...FINDING_QUEUES[2]!, isDefault: false },
    ]);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const duplicateQueueSpy = vi.spyOn(api, 'duplicateFindingQueue').mockResolvedValue({
      ...FINDING_QUEUES[2]!,
      id: 'queue-2',
      key: 'personal:queue-2',
      title: 'My Queue Copy',
      isDefault: false,
    });
    const setDefaultQueueSpy = vi.spyOn(api, 'setDefaultFindingQueue').mockResolvedValue();

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: /Duplicate Queue/i }));
    fireEvent.click(screen.getByRole('button', { name: /Set Default/i }));

    await waitFor(() => {
      expect(duplicateQueueSpy).toHaveBeenCalledWith('personal:queue-1');
      expect(setDefaultQueueSpy).toHaveBeenCalledWith('personal:queue-1');
    });
  });

  it('deletes an existing personal queue after confirmation', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const deleteQueueSpy = vi.spyOn(api, 'deleteFindingQueue').mockResolvedValue();

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: /Delete Queue/i }));

    await waitFor(() => {
      expect(deleteQueueSpy).toHaveBeenCalledWith('personal:queue-1');
    });
  });

  it('defers and deletes selected findings through the bulk action flows', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const bulkUpdateSpy = vi.spyOn(api, 'bulkUpdateFindingWorkflow').mockResolvedValue({
      targeted: 1,
      updated: 1,
      failed: 0,
      message: 'Updated 1 finding',
    });
    const bulkDeleteSpy = vi.spyOn(api, 'bulkDeleteFindings').mockResolvedValue({
      deleted: 1,
      message: 'Deleted 1 finding',
    });

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('checkbox', { name: /Select row/i }));
    fireEvent.click(screen.getByTitle(/More actions/i));
    fireEvent.click(screen.getByRole('button', { name: /Defer/i }));
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'PENDING_PATCH' } });
    fireEvent.change(document.querySelector('.fd3-modal input[type="date"]') as HTMLInputElement, { target: { value: '2026-06-30' } });
    fireEvent.click(document.querySelector('.fd3-modal .btn-primary') as HTMLButtonElement);

    await waitFor(() => {
      expect(bulkUpdateSpy).toHaveBeenLastCalledWith(expect.objectContaining({
        findingIds: ['finding-1'],
        workflowStatus: 'SUPPRESSED',
        suppressionReason: 'PENDING_PATCH',
        suppressedUntil: '2026-06-30T00:00:00.000Z',
        actor: 'analyst@example.com',
      }));
    });

    fireEvent.click(screen.getByRole('checkbox', { name: /Select row/i }));
    fireEvent.click(screen.getByTitle(/More actions/i));
    fireEvent.click(screen.getByRole('button', { name: /^Delete$/i }));
    fireEvent.click(document.querySelector('.fd3-modal .btn-danger') as HTMLButtonElement);

    await waitFor(() => {
      expect(bulkDeleteSpy).toHaveBeenCalledWith(['finding-1']);
    });
  });

  it('creates a ServiceNow incident for the selected finding', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const createIncidentSpy = vi.spyOn(cveWorkbenchApi, 'createServiceNowIncident').mockResolvedValue([{
      incidentNumber: 'INC000200',
      sysId: 'sys-200',
      url: 'https://example.service-now.com/nav_to.do?uri=incident.do?sys_id=sys-200',
      status: 'created',
      message: 'Incident created successfully',
    }]);

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('checkbox', { name: /Select row/i }));
    fireEvent.click(screen.getByTitle(/More actions/i));
    fireEvent.click(screen.getByRole('button', { name: /\+ Create Incident/i }));
    fireEvent.change(screen.getByPlaceholderText(/username or email/i), { target: { value: 'resolver@example.com' } });
    fireEvent.change(screen.getByPlaceholderText(/Security Operations/i), { target: { value: 'Security Operations' } });
    fireEvent.change(screen.getByPlaceholderText(/Remediation context/i), { target: { value: 'Escalate to resolver team.' } });
    fireEvent.click(screen.getByRole('button', { name: /Create Incident/i }));

    await waitFor(() => {
      expect(createIncidentSpy).toHaveBeenCalledWith('CVE-2026-1234', expect.objectContaining({
        findingTitle: 'CVE-2026-1234 — Vulnerability Remediation',
        severity: 'CRITICAL',
        priority: '3',
        assignedTo: 'resolver@example.com',
        notes: 'Escalate to resolver team.',
        affectedAssets: [expect.objectContaining({
          assetName: 'web-prod-01',
          assetIdentifier: 'web-prod-01.example.com',
          assignmentGroup: 'Security Operations',
        })],
      }));
    });

    await waitFor(() => {
      expect(screen.getByText(/ServiceNow incident creation completed/i)).toBeInTheDocument();
    });
  });

});
