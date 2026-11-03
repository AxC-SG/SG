import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import type React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, type CbomRuleConfiguration } from '../../api/client';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { CampaignLinkedFindings } from '../campaigns/CampaignLinkedFindings';
import { CbomRulesPanel } from './CbomRulesPanel';
import { CryptoRemediationPanel } from './CryptoRemediationPanel';
import type { CryptoEffectiveness, CryptoRemediationQueue } from './types';

const ADMIN: ActorContext = { creator: false, principal: 'admin@example.com', userId: 'admin-1', tenantId: 't-1', tenantName: 'Acme', roles: ['ROLE_TENANT_ADMIN'] };
const AUDITOR: ActorContext = { ...ADMIN, roles: ['ROLE_READ_ONLY_AUDITOR'] };

function renderAs(actor: ActorContext, element: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><ActorContextState.Provider value={actor}>{element}</ActorContextState.Provider></MemoryRouter>
    </QueryClientProvider>,
  );
}

const QUEUE: CryptoRemediationQueue = {
  observedAt: '2026-11-03T00:00:00Z',
  verificationQueue: [{ findingId: 'f-1', displayId: 'F-1', title: 'RSA key too small', severity: 'HIGH', status: 'OPEN', assignedTo: null,
    ownerGroup: null, dueAt: null, workflowSubstate: 'VERIFICATION_REQUESTED', verificationStatus: 'REQUESTED', targetState: 'RSA-3072',
    verificationRequestedAt: '2026-11-02T00:00:00Z', overdue: false }],
  overdue: [{ findingId: 'f-2', displayId: 'F-2', title: 'TLS 1.0 enabled', severity: 'CRITICAL', status: 'OPEN', assignedTo: 'bob',
    ownerGroup: null, dueAt: '2026-10-01T00:00:00Z', workflowSubstate: null, verificationStatus: 'NOT_REQUIRED', targetState: null,
    verificationRequestedAt: null, overdue: true }],
  slaBySeverity: [{ severity: 'CRITICAL', open: 1, overdue: 1, dueWithin7Days: 0, unassigned: 0 }],
};
const EFFECTIVENESS: CryptoEffectiveness = {
  days: 90, from: '2026-08-05', to: '2026-11-03', opened: 10, closed: 4, verifiedClosures: 3, reopened: 1, verificationsAccepted: 3,
  verificationsRejected: 1, verificationAcceptanceRate: 0.75, closuresByReason: { VERIFIED_REASSESSMENT: 3 },
  bySeverity: [{ severity: 'HIGH', closed: 4, meanDaysToClose: 12.5, closedWithinSla: 0.5 }],
};
const RULES: CbomRuleConfiguration = {
  packageId: 'scoutgrid-baseline', versionPolicy: 'FOLLOW_LATEST', pinnedVersion: null, parameters: { minimumRsaBits: 2048 }, version: 1,
  updatedBy: 'system', effectiveVersion: '1.0.0', pinState: 'UPGRADE_AVAILABLE', remediation: 'A newer rule package is available.',
  availableVersions: [{ version: '1.0.0', title: 'Baseline', digest: 'sha256:x', evaluatorMajor: 1, rolloutStage: 'GENERAL', deprecatedAt: null,
    retiresAt: null, pinnable: true, tenantStatus: 'EFFECTIVE' }],
  history: [{ id: 'h-1', action: 'ROLLOUT_UPGRADE', fromVersion: null, toVersion: '1.0.0', versionPolicy: 'FOLLOW_LATEST', actor: 'system',
    reason: 'Rollout stage GENERAL', impactJson: null, createdAt: '2026-11-01T00:00:00Z' }],
};

describe('crypto remediation panels', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('shows queues, SLA and effectiveness and creates a campaign from selected findings', async () => {
    vi.spyOn(api, 'getCryptoRemediationQueue').mockResolvedValue(QUEUE);
    vi.spyOn(api, 'getCryptoRemediationEffectiveness').mockResolvedValue(EFFECTIVENESS);
    const create = vi.spyOn(api, 'createCampaignFromFindings').mockResolvedValue({ summary: { id: 'c-1', name: 'Q1 crypto' } });
    const { container } = renderAs(ADMIN, <CryptoRemediationPanel canManage />);

    expect(await screen.findByText('Awaiting verification (1)')).toBeInTheDocument();
    expect(screen.getByText('RSA-3072')).toBeInTheDocument();
    expect(screen.getByText(/\(overdue\)/)).toBeInTheDocument();
    expect(await screen.findByText(/75% \(3 accepted, 1 rejected\)/)).toBeInTheDocument();
    const audit = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(audit.violations.map((v) => v.id)).toEqual([]);

    fireEvent.click(screen.getByLabelText('Select F-1'));
    fireEvent.click(screen.getByLabelText('Select F-2'));
    fireEvent.click(screen.getByRole('button', { name: 'Create campaign from 2 selected' }));
    const dialog = screen.getByRole('dialog', { name: 'Create remediation campaign' });
    fireEvent.change(within(dialog).getByLabelText('Campaign name'), { target: { value: 'Q1 crypto' } });
    fireEvent.change(within(dialog).getByLabelText('Assign to (optional)'), { target: { value: 'alice' } });
    expect(within(dialog).getByRole('button', { name: 'Create campaign' })).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('Due date'), { target: { value: '2027-01-31' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create campaign' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
      name: 'Q1 crypto', findingIds: ['f-1', 'f-2'], assignedTo: 'alice', dueAt: '2027-01-31T23:59:59.000Z',
    })));
    expect(await screen.findByRole('link', { name: 'Q1 crypto' })).toHaveAttribute('href', '/vuln-repo/campaigns/c-1');
  });

  it('requires an impact preview of the exact draft before a tenant admin can activate rules', async () => {
    vi.spyOn(api, 'getCbomRuleConfiguration').mockResolvedValue(RULES);
    const preview = vi.spyOn(api, 'previewCbomRuleConfiguration').mockResolvedValue({
      activeComponents: 9, projectedRsaFindings: 2, projectedExpiringCertificateFindings: 1, safetyBounds: ['minimumRsaBits=2048..16384'],
      fromVersion: '1.0.0', toVersion: '1.0.0', addedRules: [], removedRules: [], changedRuleModes: [],
      changedParameters: { minimumRsaBits: [2048, 3072] }, currentRsaFindings: 0, currentExpiringCertificateFindings: 1,
    });
    const update = vi.spyOn(api, 'updateCbomRuleConfiguration').mockResolvedValue(RULES);
    renderAs(ADMIN, <CbomRulesPanel />);

    expect(await screen.findByText('A newer rule package is available.')).toBeInTheDocument();
    expect(screen.getByText(/Rollout upgrade/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Minimum rsa bits'), { target: { value: '3072' } });
    fireEvent.change(screen.getByLabelText('Reason for the change'), { target: { value: 'Raise baseline' } });
    const activate = screen.getByRole('button', { name: 'Activate configuration' });
    expect(activate).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Preview impact' }));
    expect(await screen.findByText(/RSA key-size findings 0 → 2/)).toBeInTheDocument();
    expect(screen.getByText(/minimumRsaBits 2048 → 3072/)).toBeInTheDocument();
    expect(preview).toHaveBeenCalledWith(expect.objectContaining({ parameters: { minimumRsaBits: 3072 } }));
    fireEvent.change(screen.getByLabelText('Minimum rsa bits'), { target: { value: '4096' } });
    expect(activate).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Preview impact' }));
    await waitFor(() => expect(activate).not.toBeDisabled());
    fireEvent.click(activate);
    await waitFor(() => expect(update).toHaveBeenCalledWith(expect.objectContaining({
      versionPolicy: 'FOLLOW_LATEST', parameters: { minimumRsaBits: 4096 }, reason: 'Raise baseline',
    })));
  });

  it('shows rule configuration read-only to non-administrators', async () => {
    vi.spyOn(api, 'getCbomRuleConfiguration').mockResolvedValue(RULES);
    renderAs(AUDITOR, <CbomRulesPanel />);
    expect(await screen.findByText('Only a tenant administrator can change the rule configuration.')).toBeInTheDocument();
    expect(screen.getByLabelText('Minimum rsa bits')).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Activate configuration' })).not.toBeInTheDocument();
  });

  it('lists findings linked to a campaign and stays hidden when there are none', async () => {
    const list = vi.spyOn(api, 'listCampaignFindings').mockResolvedValueOnce([{
      findingId: 'f-1', displayId: 'F-1', title: 'RSA key too small', findingKind: 'CRYPTO', severity: 'HIGH', status: 'OPEN',
      assignedTo: 'alice', ownerGroup: null, dueAt: '2027-01-31T00:00:00Z', verificationStatus: 'REQUESTED', addedAt: '2026-11-03T00:00:00Z',
    }]);
    renderAs(ADMIN, <CampaignLinkedFindings campaignId="c-1" />);
    expect(await screen.findByText('Linked findings (1, 1 open)')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'F-1' })).toHaveAttribute('href', '/findings/f-1');
    expect(list).toHaveBeenCalledWith('c-1');
  });
});
