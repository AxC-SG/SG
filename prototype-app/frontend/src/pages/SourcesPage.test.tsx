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
    sessionStorage.clear();
    localStorage.clear();
  });

  it('discards legacy keys and submits a new key without writing browser storage', async () => {
    const storageKey = 'scoutai-nvd-full-sync-api-key';
    sessionStorage.setItem(storageKey, 'legacy-secret');
    const write = vi.spyOn(Storage.prototype, 'setItem');
    const read = vi.spyOn(Storage.prototype, 'getItem');
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([]);
    vi.spyOn(api, 'getVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'nvd', configured: true, isVulnerable: false, hasKev: false, knownRansomwareCampaignUse: false,
    });
    vi.spyOn(api, 'saveVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'nvd', configured: true, isVulnerable: false, hasKev: false, knownRansomwareCampaignUse: false,
    });
    const sync = vi.spyOn(api, 'syncNvdFull').mockResolvedValue({ runId: 'nvd-run', status: 'QUEUED', message: 'Queued' });
    const renderPage = () => renderWithProviders(
      <ActorContextState.Provider value={PLATFORM_OWNER}><SourcesPage focusSource="nvd" /></ActorContextState.Provider>
    );
    const view = renderPage();
    const input = await screen.findByLabelText('NVD API Key');
    expect(input).toHaveValue('');
    expect(read).not.toHaveBeenCalledWith(storageKey);
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    fireEvent.click(screen.getByRole('checkbox', { name: /I understand the runtime/ }));
    fireEvent.change(input, { target: { value: '   ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run NVD Full Sync' }));
    expect(sync).not.toHaveBeenCalled();
    expect(screen.getByText('An NVD API key is required for the full corpus sync.')).toBeInTheDocument();
    fireEvent.change(input, { target: { value: '  new-secret  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run NVD Full Sync' }));
    await waitFor(() => expect(sync).toHaveBeenCalledWith({ apiKey: 'new-secret' }));
    expect(write.mock.calls.some(([, value]) => String(value).includes('new-secret'))).toBe(false);
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    expect(localStorage.getItem(storageKey)).toBeNull();
    view.unmount();
    renderPage();
    expect(await screen.findByLabelText('NVD API Key')).toHaveValue('');
  });

  it('allows entering a temporary key when browser storage is unavailable', async () => {
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => { throw new Error('Storage blocked'); });
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([]);
    vi.spyOn(api, 'getVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'nvd', configured: true, isVulnerable: false, hasKev: false, knownRansomwareCampaignUse: false,
    });
    vi.spyOn(api, 'saveVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'nvd', configured: true, isVulnerable: false, hasKev: false, knownRansomwareCampaignUse: false,
    });
    const sync = vi.spyOn(api, 'syncNvdFull').mockRejectedValue(new Error('NVD unavailable'));
    renderWithProviders(<ActorContextState.Provider value={PLATFORM_OWNER}><SourcesPage focusSource="nvd" /></ActorContextState.Provider>);
    const input = await screen.findByLabelText('NVD API Key');
    fireEvent.change(input, { target: { value: 'temporary-secret' } });
    fireEvent.click(screen.getByRole('checkbox', { name: /I understand the runtime/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Run NVD Full Sync' }));
    await waitFor(() => expect(sync).toHaveBeenCalledWith({ apiKey: 'temporary-secret' }));
    expect(await screen.findByText(/NVD Full Sync failed: NVD unavailable/)).toBeInTheDocument();
    expect(input).toHaveValue('temporary-secret');
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

  it('says run history could not be loaded instead of "No sync run recorded yet"', async () => {
    vi.spyOn(api, 'listSyncRuns').mockRejectedValue(new Error('runs offline'));
    vi.spyOn(api, 'getVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'nvd', configured: true, isVulnerable: false, hasKev: false, knownRansomwareCampaignUse: false
    });

    renderWithProviders(<SourcesPage focusSource="nvd" showQueue={false} />);

    expect((await screen.findAllByText(/Run history could not be loaded\./)).length).toBeGreaterThan(0);
    expect(screen.queryByText(/No sync run recorded yet/)).not.toBeInTheDocument();
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
