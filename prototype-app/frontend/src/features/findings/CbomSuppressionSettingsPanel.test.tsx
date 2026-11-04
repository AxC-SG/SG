import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { CbomSuppressionSettingsPanel } from './CbomSuppressionSettingsPanel';

const ADMIN: ActorContext = {
  creator: false,
  principal: 'admin@example.com',
  userId: 'admin-1',
  tenantId: 'tenant-1',
  tenantName: 'Acme',
  roles: ['ROLE_TENANT_ADMIN'],
};

const SETTINGS = {
  tenantId: 'tenant-1',
  requireDistinctSuppressionApprover: true,
  suppressionRequestDeadlineDays: 14,
  lowSuppressionMaxDays: 365,
  mediumSuppressionMaxDays: 180,
  highSuppressionMaxDays: 90,
  criticalSuppressionMaxDays: 30,
  updatedBy: 'admin-1',
  updatedAt: '2026-11-02T00:00:00Z',
  version: 1,
};

function renderPanel(actor: ActorContext = ADMIN) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ActorContextState.Provider value={actor}>
        <CbomSuppressionSettingsPanel />
      </ActorContextState.Provider>
    </QueryClientProvider>
  );
}

describe('CbomSuppressionSettingsPanel', () => {
  afterEach(() => vi.restoreAllMocks());

  it('lets a tenant admin shorten and save tenant suppression limits', async () => {
    vi.spyOn(api, 'getCbomSuppressionSettings').mockResolvedValue(SETTINGS);
    const update = vi.spyOn(api, 'updateCbomSuppressionSettings').mockResolvedValue({ ...SETTINGS, highSuppressionMaxDays: 45 });
    renderPanel();

    fireEvent.change(await screen.findByLabelText('High maximum (days)'), { target: { value: '45' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));

    await waitFor(() => expect(update).toHaveBeenCalledWith(expect.objectContaining({ highSuppressionMaxDays: 45 })));
    expect(await screen.findByText('Suppression policy saved.')).toBeInTheDocument();
  });

  it('does not expose tenant policy controls to analysts', () => {
    const get = vi.spyOn(api, 'getCbomSuppressionSettings');
    const { container } = renderPanel({ ...ADMIN, roles: ['ROLE_SECURITY_ANALYST'] });
    expect(container).toBeEmptyDOMElement();
    expect(get).not.toHaveBeenCalled();
  });
});
