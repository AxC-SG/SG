import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { fixIntelligenceApi } from '../features/fix-intelligence/api';
import { ANALYST, TENANT_ADMIN } from '../features/fix-intelligence/fixtures';
import type { PatchConnectorConfig, PatchProvider } from '../features/fix-intelligence/types';
import { renderWithProviders } from '../test/test-utils';
import { PatchConnectorPage } from './PatchConnectorPage';

function config(overrides: Partial<PatchConnectorConfig> = {}): PatchConnectorConfig {
  return {
    id: null,
    provider: 'TANIUM',
    displayName: 'Tanium Cloud',
    configured: false,
    hasSecret: false,
    baseUrl: null,
    directoryId: null,
    clientId: null,
    username: null,
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440,
    lastTestStatus: null,
    lastTestMessage: null,
    lastTestedAt: null,
    lastSyncAt: null,
    ...overrides
  };
}

function renderPage(provider: PatchProvider, actor: ActorContext = TENANT_ADMIN) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <PatchConnectorPage provider={provider} />
    </ActorContextState.Provider>
  );
}

describe('PatchConnectorPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('saves Tanium settings and sends the token only when typed', async () => {
    vi.spyOn(fixIntelligenceApi, 'getPatchConnector').mockResolvedValue(config({ configured: true, hasSecret: true, baseUrl: 'https://acme-api.cloud.tanium.com' }));
    const save = vi.spyOn(fixIntelligenceApi, 'savePatchConnector').mockResolvedValue(config({ configured: true }));
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    renderPage('tanium');

    expect(await screen.findByDisplayValue('https://acme-api.cloud.tanium.com')).toBeInTheDocument();
    expect(screen.getByText(/Saved — leave blank/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Save Configuration' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith('tanium', expect.not.objectContaining({ secret: expect.anything() })));

    fireEvent.change(screen.getByPlaceholderText('Leave blank to keep the saved value'), { target: { value: 'token-123' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save Configuration' }));
    await waitFor(() => expect(save).toHaveBeenLastCalledWith('tanium', expect.objectContaining({ secret: 'token-123' })));
    expect(log).not.toHaveBeenCalled();
  });

  it('shows Intune directory fields and the per-check test result', async () => {
    vi.spyOn(fixIntelligenceApi, 'getPatchConnector').mockResolvedValue(config({ provider: 'INTUNE', configured: true }));
    vi.spyOn(fixIntelligenceApi, 'testPatchConnector').mockResolvedValue({
      status: 'SUCCESS_WITH_WARNINGS',
      message: 'Devices readable.',
      checks: [{ name: 'Managed devices', passed: true, required: true, detail: null },
        { name: 'Update profiles', passed: false, required: false, detail: '403' }],
      testedAt: '2026-10-28T10:00:00Z'
    });
    renderPage('intune');
    expect(await screen.findByText('Directory (tenant) ID')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Test Connection' }));
    expect(await screen.findByText(/Update profiles/)).toHaveTextContent('(optional)');
  });

  it('SCCM has no credential fields and queues a sync', async () => {
    vi.spyOn(fixIntelligenceApi, 'getPatchConnector').mockResolvedValue(config({ provider: 'SCCM', configured: true }));
    const sync = vi.spyOn(fixIntelligenceApi, 'syncPatchConnector').mockResolvedValue({ runId: 'run-1' } as Awaited<ReturnType<typeof fixIntelligenceApi.syncPatchConnector>>);
    const { container } = renderPage('sccm');
    expect(await screen.findByText(/already configured on the SCCM\/MECM inventory connector/)).toBeInTheDocument();
    expect(container.querySelector('input[type="password"]')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Sync Now' }));
    await waitFor(() => expect(sync).toHaveBeenCalledWith('sccm'));
    expect(await screen.findByText(/Patch sync queued/)).toBeInTheDocument();
  });

  it('is read-only for analysts', async () => {
    vi.spyOn(fixIntelligenceApi, 'getPatchConnector').mockResolvedValue(config({ provider: 'BIGFIX' }));
    renderPage('bigfix', ANALYST);
    expect(await screen.findByText(/Only tenant or inventory administrators/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save Configuration' })).not.toBeInTheDocument();
  });

  it('surfaces a save error', async () => {
    vi.spyOn(fixIntelligenceApi, 'getPatchConnector').mockResolvedValue(config({ provider: 'BIGFIX' }));
    vi.spyOn(fixIntelligenceApi, 'savePatchConnector').mockRejectedValue(new Error('Host is not on the BigFix allowlist'));
    renderPage('bigfix');
    fireEvent.click(await screen.findByRole('button', { name: 'Save Configuration' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('allowlist');
  });
});
