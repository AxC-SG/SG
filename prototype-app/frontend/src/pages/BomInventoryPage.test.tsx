import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { BomInventoryPage } from './BomInventoryPage';

const EMPTY_DASHBOARD = {
  documentCount: 0,
  componentCount: 0,
  evidenceCount: 0,
  correlatedComponentCount: 0,
  vulnerabilityLinkCount: 0,
  activeWorkflowCount: 0,
  openRemediationCount: 0,
  sourceSystemCount: 0,
  bomTypes: [],
  specFamilies: [],
  sourceSystems: [],
  workflowStatuses: [],
};

const BOM_ITEM = {
  id: 'bom-1',
  assetId: 'asset-1',
  bomType: 'SBOM',
  serialNumber: 'urn:uuid:example',
  supplier: 'Example Supplier',
  sourceSystem: 'github',
  sourceMethod: 'UPLOAD',
  sourceType: 'github',
  sourceUrl: 'https://example.com/bom.json',
  format: 'CycloneDX',
  formatVersion: '1.5',
  specFamily: 'cyclonedx',
  documentFormat: 'json',
  supportLevel: 'current',
  supported: true,
  componentCount: 12,
  evidenceCount: 18,
  correlatedComponentCount: 2,
  vulnerabilityLinkCount: 3,
  status: 'ACTIVE',
  ingestedAt: '2026-01-01T00:00:00Z',
  ingestedBy: 'tester',
};

describe('BomInventoryPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows loading state while bom inventory is fetching', () => {
    vi.spyOn(api, 'getBomDashboard').mockResolvedValue(EMPTY_DASHBOARD);
    vi.spyOn(api, 'listBomInventory').mockReturnValue(new Promise(() => {}));
    renderWithProviders(<BomInventoryPage />);
    expect(screen.getByText('Loading…')).toBeInTheDocument();
  });

  it('renders freshness status when bom inventory data loads', async () => {
    vi.spyOn(api, 'getBomDashboard').mockResolvedValue(EMPTY_DASHBOARD);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([BOM_ITEM]);
    renderWithProviders(<BomInventoryPage />);
    await waitFor(() => expect(screen.getByText('BOM Inventory')).toBeInTheDocument());
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('reports a failed inventory with retry instead of the no-records state', async () => {
    vi.spyOn(api, 'getBomDashboard').mockResolvedValue(EMPTY_DASHBOARD);
    const list = vi.spyOn(api, 'listBomInventory').mockRejectedValueOnce(new Error('Inventory unavailable')).mockResolvedValue([BOM_ITEM]);
    renderWithProviders(<BomInventoryPage />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Inventory unavailable');
    expect(screen.queryByText(/No BOM records ingested yet/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry BOM inventory' }));
    expect(await screen.findByText('Example Supplier')).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
  });

  it('confirms removal in one named dialog that stays open with the error when removal fails', async () => {
    vi.spyOn(api, 'getBomDashboard').mockResolvedValue(EMPTY_DASHBOARD);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([BOM_ITEM]);
    const remove = vi.spyOn(api, 'deleteBom').mockRejectedValueOnce(new Error('Removal blocked')).mockResolvedValue(undefined as never);
    renderWithProviders(<BomInventoryPage />);

    fireEvent.click(await screen.findByRole('button', { name: 'Remove BOM record Example Supplier' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove BOM record?' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Removal blocked');
    expect(screen.getByRole('dialog', { name: 'Remove BOM record?' })).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(remove).toHaveBeenCalledTimes(2);
  });

  it('shows a CBOM\'s cryptographic assets in its detail instead of the empty component table', async () => {
    const cbom = { ...BOM_ITEM, id: 'bom-c', bomType: 'CBOM', supplier: 'Crypto Supplier', componentCount: 9 };
    vi.spyOn(api, 'getBomDashboard').mockResolvedValue(EMPTY_DASHBOARD);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([cbom]);
    vi.spyOn(api, 'getBomLineage').mockResolvedValue([]);
    vi.spyOn(api, 'getBomDetail').mockResolvedValue({
      ...cbom,
      sourceReference: '',
      checksumSha256: '',
      inspection: { format: 'CycloneDX', formatVersion: '1.6', specFamily: 'cyclonedx', documentFormat: 'json', supportLevel: 'current', supported: true, warnings: [] },
      workflowSummary: [],
      components: [],
    } as never);
    const assets = vi.spyOn(api, 'listCbomAssetsForBom').mockResolvedValue([]);
    renderWithProviders(<BomInventoryPage />);

    fireEvent.click(await screen.findByRole('button', { name: 'View BOM detail for Crypto Supplier' }));
    expect(await screen.findByText('Cryptographic assets (0)')).toBeInTheDocument();
    expect(screen.queryByText('No components recorded.')).not.toBeInTheDocument();
    expect(assets).toHaveBeenCalledWith('bom-c');
  });

  it('switches to the tenant cryptographic posture and inventory views', async () => {
    vi.spyOn(api, 'getBomDashboard').mockResolvedValue(EMPTY_DASHBOARD);
    vi.spyOn(api, 'listBomInventory').mockResolvedValue([BOM_ITEM]);
    const overview = vi.spyOn(api, 'getCbomOverview').mockRejectedValue(new Error('down'));
    vi.spyOn(api, 'getCbomTrends').mockResolvedValue({ days: 90, points: [] });
    const inventory = vi.spyOn(api, 'listCbomInventory').mockResolvedValue({ items: [], page: 0, size: 50, total: 0, totalCapped: false, hasNext: false });
    renderWithProviders(<BomInventoryPage />);

    fireEvent.click(await screen.findByRole('button', { name: 'Cryptographic posture' }));
    expect(await screen.findByText('Cryptographic posture could not be loaded.')).toBeInTheDocument();
    expect(overview).toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Cryptographic inventory' }));
    expect(await screen.findByText(/No CBOM has reported cryptographic assets yet/)).toBeInTheDocument();
    expect(inventory).toHaveBeenCalledWith({}, 0, 50);
    fireEvent.click(screen.getByRole('button', { name: 'Documents' }));
    expect(await screen.findByRole('button', { name: 'Cryptographic posture' })).toHaveAttribute('aria-pressed', 'false');
  });
});
