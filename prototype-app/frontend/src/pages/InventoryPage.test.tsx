import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { InventoryPage } from './InventoryPage';

const EMPTY_BOM_EVIDENCE = {
  documentCount: 0,
  componentCount: 0,
  evidenceCount: 0,
  vulnerabilityLinkCount: 0,
  componentsInWorkflow: 0,
  documents: [],
  components: [],
};

function buildAsset(overrides = {}) {
  return {
    id: 'asset-1',
    name: 'web-prod-01',
    type: 'HOST',
    identifier: 'web-prod-01.example.com',
    businessCriticality: 'medium',
    state: 'online',
    ...overrides,
  };
}

function buildHostDetail() {
  return {
    host: {
      assetId: 'asset-1',
      ciId: 'ci-1',
      name: 'web-prod-01',
      identifier: 'web-prod-01.example.com',
      sysId: 'sys-1',
      aliasCount: 0,
      installedSoftwareCount: 0,
      openFindingCount: 0,
      totalFindingCount: 0,
      unresolvedReviewCount: 0,
    },
    aliases: [],
    software: [],
    findings: [],
    applicableCves: [],
    bomEvidence: EMPTY_BOM_EVIDENCE,
  };
}

describe('InventoryPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows loading state while assets are fetching', () => {
    vi.spyOn(api, 'listAssets').mockReturnValue(new Promise(() => {}));
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    expect(screen.getByText('Loading host inventory…')).toBeInTheDocument();
  });

  it('renders the Hosts page title after data loads', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([buildAsset()]);
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    await waitFor(() => expect(screen.getByText('Hosts')).toBeInTheDocument());
  });

  it('renders the Host inventory section heading', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([buildAsset()]);
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    await waitFor(() =>
      expect(screen.getByText('Host inventory')).toBeInTheDocument()
    );
  });

  it('shows error banner when assets fetch fails', async () => {
    vi.spyOn(api, 'listAssets').mockRejectedValue(new Error('Assets unavailable'));
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    await waitFor(() =>
      expect(
        screen.getByText(/Failed to load hosts inventory: Assets unavailable/i)
      ).toBeInTheDocument()
    );
  });

  it('renders the Host Exposure widget title after data loads', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([buildAsset()]);
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    await waitFor(() =>
      expect(screen.getByText('Host Exposure')).toBeInTheDocument()
    );
  });

  it('renders an asset row with host name when data is returned', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([buildAsset()]);
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    // host name appears in both the widget bar and the table row
    await waitFor(() =>
      expect(screen.getAllByText('web-prod-01').length).toBeGreaterThanOrEqual(1)
    );
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('shows the resolved owner team instead of raw CMDB owner fields once inventory ownership is canonical', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([
      buildAsset({
        ownerTeam: 'Legacy Ops',
        ownership: {
          objectId: 'asset-1',
          authorityDomain: 'CORE',
          authorityState: 'CANONICAL',
          ownerTeamId: 'team-1',
          ownerTeamName: 'Payments',
          ownershipStatus: 'OWNED',
        },
      }),
      buildAsset({
        id: 'asset-2',
        name: 'web-prod-02',
        identifier: 'web-prod-02.example.com',
        ownerTeam: 'Legacy Ops',
        ownership: {
          objectId: 'asset-2',
          authorityDomain: 'CORE',
          authorityState: 'CANONICAL',
          ownershipStatus: 'UNOWNED',
        },
      }),
    ]);
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    expect(await screen.findByRole('cell', { name: 'Payments' })).toBeInTheDocument();
    expect(screen.getByRole('cell', { name: 'Unowned' })).toBeInTheDocument();
    expect(screen.queryByRole('cell', { name: 'Legacy Ops' })).not.toBeInTheDocument();
  });

  it('keeps the legacy owner display while ownership is pending migration', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([buildAsset({ ownerTeam: 'Legacy Ops', ownership: null })]);
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    expect(await screen.findByRole('cell', { name: 'Legacy Ops' })).toBeInTheDocument();
  });

  it('shows the empty inventory state when no hosts are returned instead of loading forever', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    renderWithProviders(<InventoryPage selectedView="hosts" />);
    expect(screen.getByText('Loading host inventory…')).toBeInTheDocument();
    expect(await screen.findByText('No hosts discovered yet')).toBeInTheDocument();
    expect(screen.queryByText('Loading host inventory…')).not.toBeInTheDocument();
  });

  it('does not present a failed load as an empty inventory and offers retry', async () => {
    const list = vi.spyOn(api, 'listAssets').mockRejectedValueOnce(new Error('Assets unavailable')).mockResolvedValue([buildAsset()]);
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<InventoryPage selectedView="hosts" />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load hosts inventory: Assets unavailable');
    expect(screen.queryByText('No hosts discovered yet')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  });

  it('links each host name to host detail with a return path', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([buildAsset()]);
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<InventoryPage selectedView="hosts" />, { route: '/inventory/hosts' });
    const link = await screen.findByRole('link', { name: 'web-prod-01' });
    expect(link.getAttribute('href')).toMatch(/^\/inventory\/hosts\/[^?]+\?returnTo=%2Finventory%2Fhosts$/);
  });
});
