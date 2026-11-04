import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, type BomIngestKey, type BomInventoryItem } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { BomApiPanel } from './BomApiPanel';

function actor(roles: string[]): ActorContext {
  return {
    creator: false, principal: 'admin@example.test', userId: 'u-1', tenantId: 't-1', tenantName: 'Acme', roles,
  } as ActorContext;
}

function key(overrides: Partial<BomIngestKey> = {}): BomIngestKey {
  return {
    id: 'key-1', name: 'payments prod', keyPrefix: 'a1b2c3d4e5f60718', state: 'ACTIVE', createdBy: 'admin@example.test',
    createdAt: '2026-10-01T10:00:00Z', expiresAt: null, lastUsedAt: null, revokedAt: null, ...overrides,
  };
}

function inventoryItem(overrides: Partial<BomInventoryItem> = {}): BomInventoryItem {
  return {
    id: 'bom-1', assetId: 'asset-1', bomType: 'SBOM', format: 'CYCLONEDX', formatVersion: '1.5', specFamily: 'CYCLONEDX',
    documentFormat: 'JSON', serialNumber: 'urn:uuid:1', supplier: '', sourceMethod: 'API', sourceType: 'API',
    sourceSystem: 'github-actions', sourceUrl: '', supportLevel: 'CURRENT', supported: true, componentCount: 42,
    evidenceCount: 0, vulnerabilityLinkCount: 0, correlatedComponentCount: 0, status: 'ACTIVE',
    ingestedAt: '2026-10-30T10:00:00Z', ingestedBy: 'ingest-key:a1b2', sourceLabel: 'build:1042', sourceReference: 'acme/payments',
    ...overrides,
  };
}

function renderPanel(roles = ['TENANT_ADMIN']) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor(roles)}>
      <BomApiPanel bomType="SBOM" />
    </ActorContextState.Provider>,
  );
}

describe('BomApiPanel', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows the key once after creation and never lists the full token', async () => {
    vi.spyOn(api, 'listBomIngestKeys').mockResolvedValue([]);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([]);
    const create = vi.spyOn(api, 'createBomIngestKey').mockResolvedValue({
      key: key(), token: 'sgk_a1b2c3d4e5f60718_' + 'f'.repeat(64),
    });

    renderPanel();
    fireEvent.change(await screen.findByLabelText('Key name'), { target: { value: 'payments prod' } });
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: '30' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create key' }));

    expect(await screen.findByText(/Copy this key now/)).toBeInTheDocument();
    expect(screen.getByText(/sgk_a1b2c3d4e5f60718_f{64}/)).toBeInTheDocument();
    expect(create).toHaveBeenCalledWith({ name: 'payments prod', expiresInDays: 30 });

    fireEvent.click(screen.getByRole('button', { name: 'I have stored it' }));
    await waitFor(() => expect(screen.queryByText(/Copy this key now/)).not.toBeInTheDocument());
    expect(screen.queryByText(/f{64}/)).not.toBeInTheDocument();
  });

  it('lists existing keys by prefix and revokes an active one', async () => {
    const list = vi.spyOn(api, 'listBomIngestKeys').mockResolvedValue([
      key(), key({ id: 'key-2', name: 'old key', state: 'REVOKED', keyPrefix: '0011223344556677' }),
    ]);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([]);
    const revoke = vi.spyOn(api, 'revokeBomIngestKey').mockResolvedValue(undefined);

    renderPanel();
    expect(await screen.findByText('payments prod')).toBeInTheDocument();
    expect(screen.getByText('sgk_a1b2c3d4e5f60718…')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revoke old key' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Revoke payments prod' }));
    await waitFor(() => expect(revoke).toHaveBeenCalledWith('key-1'));
    await waitFor(() => expect(list.mock.calls.length).toBeGreaterThan(1));
  });

  it('lets an inventory admin see keys but not create or revoke them', async () => {
    vi.spyOn(api, 'listBomIngestKeys').mockResolvedValue([key()]);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([]);

    renderPanel(['INVENTORY_ADMIN']);

    expect(await screen.findByText('payments prod')).toBeInTheDocument();
    expect(screen.getByText(/Only a tenant administrator can create or revoke ingest keys/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create key' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revoke payments prod' })).not.toBeInTheDocument();
  });

  it('reports a failed key load with a retry', async () => {
    const list = vi.spyOn(api, 'listBomIngestKeys')
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValue([key()]);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([]);

    renderPanel();
    expect(await screen.findByText('Ingest keys could not be loaded.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry ingest keys' }));
    expect(await screen.findByText('payments prod')).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
  });

  it('shows only pipeline pushes, with build and correlator', async () => {
    vi.spyOn(api, 'listBomIngestKeys').mockResolvedValue([]);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([
      inventoryItem(),
      inventoryItem({ id: 'bom-2', sourceType: 'UPLOAD', sourceSystem: 'bom-upload', sourceLabel: 'manual.json', sourceReference: null }),
    ]);

    renderPanel();
    const table = await screen.findByRole('table');
    const rows = await screen.findAllByRole('row');
    expect(table).toBeInTheDocument();
    const pushRows = rows.filter((row) => within(row).queryByText('github-actions'));
    expect(pushRows).toHaveLength(1);
    expect(within(pushRows[0]).getByText('1042')).toBeInTheDocument();
    expect(within(pushRows[0]).getByText('acme/payments')).toBeInTheDocument();
    expect(within(pushRows[0]).getByText('42')).toBeInTheDocument();
    expect(screen.queryByText('bom-upload')).not.toBeInTheDocument();
  });

  it('switches the copy-ready snippet between pipeline systems', async () => {
    vi.spyOn(api, 'listBomIngestKeys').mockResolvedValue([]);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([]);

    renderPanel();
    const snippet = await screen.findByLabelText('curl snippet');
    expect(snippet).toHaveTextContent('bom/ingest?bomType=SBOM');

    fireEvent.click(screen.getByRole('tab', { name: 'GitLab CI' }));
    expect(screen.getByLabelText('GitLab CI snippet')).toHaveTextContent('$CI_PIPELINE_ID');
  });
});
