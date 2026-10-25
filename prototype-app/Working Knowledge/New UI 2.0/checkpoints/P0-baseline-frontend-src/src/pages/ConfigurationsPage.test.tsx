import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactElement } from 'react';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { pathForConfigurationsView } from '../app/routes';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { defaultRiskPolicy } from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { ConfigurationsPage } from './ConfigurationsPage';
import { cveWorkbenchApi } from '../features/cve-workbench/api';

const TENANT_ADMIN_CONTEXT: ActorContext = {
  creator: false,
  principal: 'admin@example.com',
  userId: 'user-admin',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_TENANT_ADMIN'],
};

describe('ConfigurationsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  function mockBaseApis() {
    vi.spyOn(api, 'getAuthContext').mockResolvedValue(TENANT_ADMIN_CONTEXT);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    vi.spyOn(api, 'listOwnershipRules').mockResolvedValue([]);
    vi.spyOn(api, 'listSuppressionRules').mockResolvedValue([]);
    vi.spyOn(api, 'listVulnerabilitySourceFilterConfigs').mockResolvedValue([]);
  }

  // ConfigurationsPage now reads its active section from the :configView route param
  // (section navigation lives in the primary sidebar rail — see App.tsx), so tests must
  // render it inside a matching <Routes><Route> for useParams() to resolve, and switch
  // sections via navigation instead of clicking the (now-removed) internal sidebar buttons.
  function withConfigRoute(ui: ReactElement) {
    return (
      <Routes>
        <Route path="/configurations/:configView?" element={ui} />
      </Routes>
    );
  }

  function renderConfigPage(options?: Parameters<typeof renderWithProviders>[1]) {
    return renderWithProviders(withConfigRoute(<ConfigurationsPage />), options);
  }

  function renderConfigPageAsTenantAdmin(options?: Parameters<typeof renderWithProviders>[1]) {
    return renderWithProviders(
      <ActorContextState.Provider value={TENANT_ADMIN_CONTEXT}>
        {withConfigRoute(<ConfigurationsPage />)}
      </ActorContextState.Provider>,
      options
    );
  }

  it('renders the SLA & Remediation tab by default', async () => {
    mockBaseApis();
    renderConfigPage({ route: '/configurations' });

    expect((await screen.findAllByText(/SLA & Remediation/i)).length).toBeGreaterThan(0);
  });

  it('renders SLA deadline inputs populated from the risk policy', async () => {
    mockBaseApis();
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(
      defaultRiskPolicy({ criticalSlaDays: 7, highSlaDays: 14, mediumSlaDays: 30, lowSlaDays: 60 })
    );

    renderConfigPage({ route: pathForConfigurationsView('sla') });

    await waitFor(() => {
      expect(api.getRiskPolicy).toHaveBeenCalled();
    });
  });

  it('renders section content when navigated to each configuration route', async () => {
    mockBaseApis();

    const triage = renderConfigPage({ route: pathForConfigurationsView('triage') });
    expect((await screen.findAllByText(/S\.AI Prioritization/i)).length).toBeGreaterThan(0);
    triage.unmount();

    const automation = renderConfigPage({ route: pathForConfigurationsView('automation') });
    expect((await screen.findAllByText(/Workflow Automation/i)).length).toBeGreaterThan(0);
    automation.unmount();

    const suppress = renderConfigPage({ route: pathForConfigurationsView('suppress') });
    expect((await screen.findAllByText(/Suppression Rules/i)).length).toBeGreaterThan(0);
    suppress.unmount();
  });

  it('renders triage tab content when navigated to', async () => {
    mockBaseApis();
    renderConfigPage({ route: pathForConfigurationsView('triage') });

    expect((await screen.findAllByText(/S\.AI Prioritization/i)).length).toBeGreaterThan(0);
  });

  it('renders execute now control in workflow automation', async () => {
    mockBaseApis();
    vi.spyOn(api, 'executeAutoCloseNow').mockResolvedValue({ updated: 0 });
    renderConfigPage({ route: pathForConfigurationsView('automation') });

    expect((await screen.findAllByText(/Execute now/i)).length).toBeGreaterThan(0);
  });

  it('renders default findings score rules out of the box', async () => {
    mockBaseApis();
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('findings-score') });

    expect((await screen.findAllByText(/^Vulnerability$/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/^CVSS Score$/i)).length).toBeGreaterThan(0);
  });

  it('renders the starter auto-finding rule out of the box', async () => {
    mockBaseApis();
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('auto-findings') });

    fireEvent.click(await screen.findByRole('button', { name: /Edit/i }));
    expect(await screen.findByText(/Critical and Applicable/i)).toBeInTheDocument();
    expect(await screen.findByRole('checkbox', { name: /Run investigation/i })).toBeInTheDocument();
    expect(await screen.findByRole('checkbox', { name: /Create findings/i })).toBeInTheDocument();
    expect(await screen.findByRole('checkbox', { name: /Create ServiceNow incident/i })).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: /Execute Now/i })).toBeInTheDocument();
  });

  it('hides software and asset scope when create findings is disabled', async () => {
    mockBaseApis();
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('auto-findings') });

    fireEvent.click(await screen.findByRole('button', { name: /Edit/i }));
    fireEvent.click(await screen.findByRole('checkbox', { name: /Create findings/i }));

    expect(screen.queryByText(/Software Scope/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Asset Scope/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Finding Creation/i)).not.toBeInTheDocument();
  });

  it('persists a reviewed investigation when the rule runs investigation', async () => {
    mockBaseApis();
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue({ content: [] } as never);
    vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue({
      items: [
        {
          externalId: 'CVE-2026-9999',
          severity: 'CRITICAL',
          cvssScore: 9.8,
          epssScore: 0.91,
          inKev: true,
          matchedSoftwareCount: 1,
        },
      ],
    } as never);
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue({
      summary: {
        externalId: 'CVE-2026-9999',
        title: 'Test CVE',
        description: 'Test description',
        severity: 'CRITICAL',
        cvssScore: 9.8,
        epssScore: 0.91,
        inKev: true,
        exploitAvailable: true,
        patchAvailable: true,
      },
      signals: {
        exploitAvailable: true,
        patchAvailable: true,
        patchVersions: '1.2.3',
      },
      investigations: [],
      assessments: [],
      matchedSoftware: [
        {
          componentId: 'component-1',
          assetId: 'asset-1',
          assetName: 'app-1',
          assetIdentifier: 'app-1',
          assetType: 'Application',
          packageName: 'test-package',
          version: '1.0.0',
          ecosystem: 'npm',
          analystDisposition: 'IMPACTED',
          eligibleForFinding: true,
        },
      ],
      vendorIntelligence: [],
      fixes: [],
    } as never);
    vi.spyOn(cveWorkbenchApi, 'runAgent').mockResolvedValue({
      resolved: [
        {
          id: 'resolved-1',
          software: 'test-package',
          vendor: 'vendor',
          version: '1.0.0',
          assets: [
            {
              componentId: 'component-1',
              assetId: 'asset-1',
              assetName: 'app-1',
              assetIdentifier: 'app-1',
              assetType: 'Application',
              packageName: 'test-package',
              version: '1.0.0',
              ecosystem: 'npm',
              isEol: false,
              eolDate: null,
              eolSupportEndDate: null,
            },
          ],
          lifecycle: 'Supported',
          endOfSupport: '',
          endOfLife: '',
          recommendedUpgrade: '',
        },
      ],
      totalAssets: 1,
      fpResults: [
        {
          id: 'fp-1',
          software: 'test-package',
          version: '1.0.0',
          falsePositive: false,
          notImpactedAssetCount: 0,
          vendorAdvisory: '',
          vendorGuidance: '',
          statusLabel: 'Applicable',
          statusDetail: 'Applicable',
          statusTone: 'na',
        },
      ],
      eolResults: [
        {
          id: 'eol-1',
          software: 'test-package',
          vendor: 'vendor',
          version: '1.0.0',
          lifecycle: 'Supported',
          endOfSupport: '',
          endOfLife: '',
          recommendedUpgrade: '',
        },
      ],
      taskMeta: {
        'review-asset-inventory': { producedBy: 'AGENT', confidence: 'HIGH', reasoning: 'ok' },
        'find-false-positive': { producedBy: 'AGENT', confidence: 'HIGH', reasoning: 'ok' },
        'end-of-life-analysis': { producedBy: 'AGENT', confidence: 'HIGH', reasoning: 'ok' },
      },
      completedTaskIds: ['review-asset-inventory', 'find-false-positive', 'end-of-life-analysis'],
      ranAt: new Date().toISOString(),
    } as never);
    vi.spyOn(cveWorkbenchApi, 'submitCveInvestigation').mockResolvedValue({
      id: 1,
      cveId: 'CVE-2026-9999',
      status: 'CLOSED',
      priority: 'CRITICAL',
    } as never);
    vi.spyOn(cveWorkbenchApi, 'generateFixRecords').mockResolvedValue([] as never);
    vi.spyOn(cveWorkbenchApi, 'saveRunbook').mockResolvedValue({
      id: 'runbook-1',
      cveExternalId: 'CVE-2026-9999',
      taskStates: [],
      logEntries: [],
      leadAnalyst: 'Automation',
      agentConfidence: {},
      agentSuggestions: {},
      createdAt: null,
      updatedAt: null,
    } as never);
    vi.spyOn(cveWorkbenchApi, 'generateInvestigationSummary').mockResolvedValue({
      title: 'summary',
      investigation: null,
      runbookResults: [],
      affectedAssets: [],
      falsePositiveRows: [],
      eolRows: [],
      solutionRows: [],
    } as never);
    vi.spyOn(cveWorkbenchApi, 'createServiceNowIncident').mockResolvedValue([
      {
        incidentNumber: 'INC000200',
        sysId: 'sys-200',
        url: 'https://example.service-now.com/nav_to.do?uri=incident.do?sys_id=sys-200',
        status: 'created',
        message: 'created',
      },
    ] as never);
    vi.spyOn(cveWorkbenchApi, 'createManualFindings').mockResolvedValue({
      message: 'created',
      createdCount: 1,
      reopenedCount: 0,
      alreadyOpenCount: 0,
    } as never);

    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('auto-findings') });

    fireEvent.click(await screen.findByRole('button', { name: /Edit/i }));
    fireEvent.click(await screen.findByRole('checkbox', { name: /Create ServiceNow incident/i }));
    fireEvent.click(await screen.findByRole('button', { name: /Save Changes/i }));
    fireEvent.click(await screen.findByRole('button', { name: /Execute Now/i }));

    await waitFor(() => {
      expect(cveWorkbenchApi.saveRunbook).toHaveBeenCalled();
      expect(cveWorkbenchApi.generateInvestigationSummary).toHaveBeenCalled();
      expect(cveWorkbenchApi.createServiceNowIncident).toHaveBeenCalled();
    });
  });

  it('calls getRiskPolicy on mount', async () => {
    mockBaseApis();
    renderConfigPage({ route: '/configurations' });

    await waitFor(() => {
      expect(api.getRiskPolicy).toHaveBeenCalledTimes(1);
    });
  });
});
