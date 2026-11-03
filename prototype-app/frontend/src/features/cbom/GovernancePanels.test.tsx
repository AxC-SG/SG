import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import type React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { CbomGatePoliciesPanel } from './CbomGatePoliciesPanel';
import { CbomPortfolioPanel } from './CbomPortfolioPanel';

const ADMIN: ActorContext = { creator: false, principal: 'admin@example.com', userId: 'admin-1', tenantId: 't-1', tenantName: 'Acme', roles: ['ROLE_TENANT_ADMIN'] };
const ANALYST: ActorContext = { ...ADMIN, roles: ['ROLE_SECURITY_ANALYST'] };

function renderAs(actor: ActorContext, element: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><ActorContextState.Provider value={actor}>{element}</ActorContextState.Provider></MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('CBOM governance panels', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('lets a tenant admin edit an environment gate policy with its version', async () => {
    vi.spyOn(api, 'listCbomGatePolicies').mockResolvedValue([{ environment: 'production', failOnSeverities: ['CRITICAL', 'HIGH'],
      minimumCompleteness: 0.8, blockOnInvalid: true, updatedBy: 'admin', updatedAt: '2026-11-01T00:00:00Z', version: 4, configured: true }]);
    const save = vi.spyOn(api, 'saveCbomGatePolicy').mockResolvedValue({} as never);
    renderAs(ADMIN, <CbomGatePoliciesPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Edit production gate policy' }));
    fireEvent.click(screen.getByLabelText('High'));
    fireEvent.change(screen.getByLabelText('Minimum completeness (0–1)'), { target: { value: '0.9' } });
    fireEvent.click(screen.getByRole('button', { name: 'Update policy' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith('production',
      { failOnSeverities: ['CRITICAL'], minimumCompleteness: 0.9, blockOnInvalid: true, version: 4 }));
    expect(await screen.findByRole('status')).toHaveTextContent('Gate policy for production saved.');
  });

  it('explains the default gate and is read-only for analysts', async () => {
    vi.spyOn(api, 'listCbomGatePolicies').mockResolvedValue([]);
    renderAs(ANALYST, <CbomGatePoliciesPanel />);
    expect(await screen.findByText(/pipelines use the default/)).toBeInTheDocument();
    expect(screen.getByText('Only a tenant administrator can change gate policies.')).toBeInTheDocument();
  });

  it('shows PQC progress, plans a campaign and rolls the portfolio up by the chosen group', async () => {
    vi.spyOn(api, 'getCbomPqcProgress').mockResolvedValue({ openQuantumVulnerable: 5, inCampaigns: 2, notInCampaign: 3, campaigns: [{
      campaignId: 'c-1', name: 'PQC wave 1', status: 'ACTIVE', dueAt: '2027-06-30T00:00:00Z', createdBy: 'admin', findings: 4,
      open: 2, resolved: 2, overdue: 0, percentComplete: 0.5, owners: ['pqc-team'] }] });
    const portfolio = vi.spyOn(api, 'getCbomPortfolio').mockResolvedValue({ groupBy: 'department', groups: [{ group: 'Payments', assets: 3,
      components: 40, openCritical: 1, openHigh: 2, openMedium: 0, openLow: 0, quantumVulnerable: 5, openCryptoFindings: 8,
      overdueCryptoFindings: 1, averagePostureScore: 6.2 }] });
    const create = vi.spyOn(api, 'createCbomPqcCampaign').mockResolvedValue({ summary: { id: 'c-2', name: 'PQC wave 2' } });
    const { container } = renderAs(ADMIN, <CbomPortfolioPanel canManage />);

    expect(await screen.findByText(/5 open quantum-vulnerable findings: 2 in migration campaigns, 3 not yet planned/)).toBeInTheDocument();
    expect(screen.getByText('50% (2 of 4)')).toBeInTheDocument();
    expect(await screen.findByText('Payments')).toBeInTheDocument();
    const audit = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(audit.violations.map((v) => v.id)).toEqual([]);
    fireEvent.change(screen.getByLabelText('Group by'), { target: { value: 'environment' } });
    await waitFor(() => expect(portfolio).toHaveBeenLastCalledWith('environment'));

    fireEvent.click(screen.getByRole('button', { name: 'Plan a PQC migration campaign' }));
    const dialog = screen.getByRole('dialog', { name: 'Plan a PQC migration campaign' });
    fireEvent.change(within(dialog).getByLabelText('Campaign name'), { target: { value: 'PQC wave 2' } });
    fireEvent.change(within(dialog).getByLabelText('Migration due date'), { target: { value: '2027-12-31' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create campaign' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith({ name: 'PQC wave 2', dueAt: '2027-12-31T23:59:59.000Z', assignedTo: undefined, environment: undefined }));
    expect(await screen.findByRole('link', { name: 'PQC wave 2' })).toHaveAttribute('href', '/vuln-repo/campaigns/c-2');
  });
});
