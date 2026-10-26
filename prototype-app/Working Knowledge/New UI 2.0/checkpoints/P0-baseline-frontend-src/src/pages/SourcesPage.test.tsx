import { fireEvent, screen, waitFor } from '@testing-library/react';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { SourcesPage } from './SourcesPage';

const PLATFORM_OWNER: ActorContext = {
  creator: true,
  principal: 'owner@example.com',
  userId: 'owner-1',
  tenantId: null,
  tenantName: null,
  roles: ['PLATFORM_OWNER'],
  platformScope: true,
  actingAsPlatformOwner: false,
  allowedTenants: [],
};

describe('SourcesPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does not enter a refetch loop on source drill-down pages', async () => {
    const listSyncRunsSpy = vi.spyOn(api, 'listSyncRuns').mockResolvedValue([]);
    const getSourceFilterConfigSpy = vi.spyOn(api, 'getVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'nvd',
      configured: true,
      isVulnerable: false,
      hasKev: false,
      knownRansomwareCampaignUse: false
    });

    const view = renderWithProviders(
      <SourcesPage
        focusSource="nvd"
        showQueue={false}
      />
    );

    await screen.findByRole('button', { name: 'Save Filters' });
    await waitFor(() => {
      expect(listSyncRunsSpy).toHaveBeenCalledTimes(1);
      expect(getSourceFilterConfigSpy).toHaveBeenCalledTimes(1);
    });

    view.rerender(
      <SourcesPage
        focusSource="nvd"
        showQueue={false}
        refreshSignal={1}
      />
    );

    await waitFor(() => {
      expect(listSyncRunsSpy).toHaveBeenCalledTimes(2);
      expect(getSourceFilterConfigSpy).toHaveBeenCalledTimes(2);
    });
  });

  it('shows clearer queued sync feedback for platform-triggered source actions', async () => {
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([]);
    vi.spyOn(api, 'saveVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'kev',
      configured: true,
      isVulnerable: false,
      hasKev: false,
      knownRansomwareCampaignUse: false,
    });
    vi.spyOn(api, 'syncKev').mockResolvedValue({
      runId: 'run-123',
      status: 'QUEUED',
      message: 'Waiting for worker capacity.'
    });

    renderWithProviders(
      <ActorContextState.Provider value={PLATFORM_OWNER}>
        <SourcesPage focusSource="kev" />
      </ActorContextState.Provider>
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Run KEV Sync' }));

    await waitFor(() => {
      expect(screen.getByText(/KEV Sync queued\. Run run-123 is waiting to start\./i)).toBeInTheDocument();
    });
  });
});
