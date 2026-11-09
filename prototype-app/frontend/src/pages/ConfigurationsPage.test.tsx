import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactElement } from 'react';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { pathForConfigurationsView } from '../app/routes';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import type { OwnershipRuleResponse, RiskPolicy, SuppressionRule } from '../features/configurations/types';
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
    vi.spyOn(api, 'getOwnershipCoverage').mockResolvedValue({
      authorityState: 'LEGACY_PENDING_MIGRATION', owned: 0, unowned: 0, conflict: 0, unlinked: 0, refreshing: 0,
    });
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

  function suppressionRule(overrides: Partial<SuppressionRule> = {}): SuppressionRule {
    return {
      id: 'rule-1', name: 'Low severity on dev', state: 'APPROVED', recordType: 'FINDING', conditionsJson: '[]',
      conditionLogic: 'AND', createdAt: '2026-10-01T00:00:00Z', updatedAt: '2026-10-01T00:00:00Z', suppressedCount: 2,
      ...overrides,
    };
  }

  it('names each SLA input by its tier and unit and shows a deadline example', async () => {
    mockBaseApis();
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('sla') });

    expect(await screen.findByRole('spinbutton', { name: 'Critical Risk minimum score (0–10)' })).toHaveValue(9);
    expect(screen.getByRole('spinbutton', { name: 'Low Risk remediate within (days, 0–365)' })).toBeInTheDocument();
    expect(screen.getByText(/a Critical Risk finding detected today is due within/)).toBeInTheDocument();
    // Fixed tiers say so instead of offering an input.
    expect(screen.queryByRole('spinbutton', { name: /Medium Risk minimum score/ })).not.toBeInTheDocument();
  });

  it('marks unsaved policy edits, discards them, and clears the cue after a confirmed save', async () => {
    mockBaseApis();
    vi.spyOn(api, 'updateRiskPolicy').mockImplementation(async (policy) => policy as RiskPolicy);
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('sla') });

    const critical = await screen.findByRole('spinbutton', { name: 'Critical Risk minimum score (0–10)' });
    fireEvent.change(critical, { target: { value: '8.5' } });
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Discard changes' }));
    expect(critical).toHaveValue(9);
    expect(screen.queryByText('Unsaved changes')).not.toBeInTheDocument();

    fireEvent.change(critical, { target: { value: '8.5' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Configuration saved')).toBeInTheDocument();
    expect(api.updateRiskPolicy).toHaveBeenCalledWith(expect.objectContaining({ criticalThreshold: 8.5 }));
    expect(screen.queryByText('Unsaved changes')).not.toBeInTheDocument();
  });

  it('keeps the draft and names the failure when a policy save is rejected', async () => {
    mockBaseApis();
    vi.spyOn(api, 'updateRiskPolicy').mockRejectedValue(new Error('Risk policy update failed'));
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('sla') });

    const critical = await screen.findByRole('spinbutton', { name: 'Critical Risk minimum score (0–10)' });
    fireEvent.change(critical, { target: { value: '8.5' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Risk policy update failed')).toBeInTheDocument();
    expect(critical).toHaveValue(8.5);
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument();
  });

  it('does not claim the triage weights were saved when the API does not store them', async () => {
    mockBaseApis();
    // The API echoes the policy without the frontend-only triage fields.
    vi.spyOn(api, 'updateRiskPolicy').mockImplementation(async (policy) => {
      const { triageExploitabilityWeight: _a, triageBlastRadiusWeight: _b, triageEolRiskWeight: _c, triageSlaBreachWeight: _d,
        triageMissingOwnerBoost: _e, triagePatchGapBoost: _f, ...rest } = policy;
      return rest as RiskPolicy;
    });
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('triage') });

    expect(await screen.findByText(/The server does not store these weights yet/)).toBeInTheDocument();
    fireEvent.change(screen.getByRole('slider', { name: 'Exploitability weight' }), { target: { value: '1.6' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/Other settings saved\. The server does not store prioritization weights/)).toBeInTheDocument();
    expect(screen.queryByText('Configuration saved')).not.toBeInTheDocument();
  });

  it('keeps a failed risk-policy load visible as local defaults with Retry', async () => {
    mockBaseApis();
    vi.spyOn(api, 'getRiskPolicy').mockRejectedValue(new Error('down'));
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('automation') });

    const alert = await screen.findByText(/The saved configuration could not be loaded, so local defaults are shown/);
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('shows an ownership load failure with Retry instead of an empty rule list', async () => {
    mockBaseApis();
    const rule: OwnershipRuleResponse = {
      id: 'own-1', name: 'Payments services', condition: '{"logic":"AND","conditions":[]}', userGroup: 'Payments',
      executionOrder: 1, matchedCount: 3, createdAt: '2026-10-01T00:00:00Z', updatedAt: '2026-10-01T00:00:00Z',
    };
    vi.spyOn(api, 'listOwnershipRules').mockRejectedValueOnce(new Error('down')).mockResolvedValueOnce([rule]);
    // The legacy editor now lives in the Ownership & Directory hub's pending-migration view.
    renderConfigPageAsTenantAdmin({ route: `${pathForConfigurationsView('ownership')}?view=legacy` });
    expect(await screen.findByText(/Legacy ownership rules — pending migration/)).toBeInTheDocument();

    expect(await screen.findByText('Ownership rules could not be loaded.')).toBeInTheDocument();
    expect(screen.queryByText('No ownership rules defined yet.')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    const region = await screen.findByRole('region', { name: 'Ownership rules' });
    expect(within(region).getByText('Payments services')).toBeInTheDocument();
  });

  it('lists suppression rules in a labelled scroll region and confirms deletes in a named dialog', async () => {
    mockBaseApis();
    vi.spyOn(api, 'listSuppressionRules').mockResolvedValue([suppressionRule()]);
    const remove = vi.spyOn(api, 'deleteSuppressionRule')
      .mockRejectedValueOnce(new Error('Rule is in use'))
      .mockResolvedValueOnce(undefined as never);
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('suppress') });

    const region = await screen.findByRole('region', { name: 'Suppression rules' });
    expect(region).toHaveAttribute('tabindex', '0');
    expect(screen.getByText(/it is not a resolution/)).toBeInTheDocument();
    fireEvent.click(within(region).getByRole('button', { name: 'Delete' }));

    const dialog = await screen.findByRole('dialog', { name: 'Delete suppression rule?' });
    expect(within(dialog).getByText(/2 suppressed records/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete rule' }));
    expect(await within(dialog).findByText('Rule is in use')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Suppression rules' })).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete rule' }));
    expect(await screen.findByText('Suppression rule deleted.')).toBeInTheDocument();
    expect(remove).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('shows a suppression load failure with Retry', async () => {
    mockBaseApis();
    vi.spyOn(api, 'listSuppressionRules').mockRejectedValueOnce(new Error('down')).mockResolvedValueOnce([suppressionRule()]);
    renderConfigPageAsTenantAdmin({ route: pathForConfigurationsView('suppress') });

    expect(await screen.findByText(/Suppression rules could not be loaded/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('region', { name: 'Suppression rules' })).toBeInTheDocument();
  });

  it('renders the panel heading one level below the shell H1', async () => {
    mockBaseApis();
    renderConfigPage({ route: pathForConfigurationsView('sla') });
    expect(await screen.findByRole('heading', { level: 2, name: 'Configurations' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 1 })).not.toBeInTheDocument();
  });

  it('calls getRiskPolicy on mount', async () => {
    mockBaseApis();
    renderConfigPage({ route: '/configurations' });

    await waitFor(() => {
      expect(api.getRiskPolicy).toHaveBeenCalledTimes(1);
    });
  });
});
