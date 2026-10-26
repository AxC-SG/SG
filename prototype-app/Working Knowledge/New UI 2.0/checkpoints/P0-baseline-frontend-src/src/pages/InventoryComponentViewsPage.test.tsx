import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { InventoryComponentViewsPage } from './InventoryComponentViewsPage';

const EMPTY_FILTER_VALUES = {
  assetTypes: [],
  componentStatuses: [],
  sourceSystems: [],
  ecosystems: [],
};

const EMPTY_PAGE = { items: [], page: 0, size: 25, totalItems: 0, totalPages: 0 };

function buildComponentRecord(overrides = {}) {
  return {
    id: 'cmp-1',
    assetId: 'asset-1',
    assetName: 'web-prod-01',
    assetIdentifier: 'web-prod-01.example.com',
    assetType: 'HOST' as const,
    componentStatus: 'ACTIVE' as const,
    ecosystem: 'npm',
    packageName: 'lodash',
    version: '4.17.15',
    purl: 'pkg:npm/lodash@4.17.15',
    cveCount: 0,
    impactedCveCount: 0,
    cveIds: [],
    lastObservedAt: '2026-01-01T00:00:00Z',
    needsReview: false,
    reviewItemCount: 0,
    reviewMissingVersion: false,
    reviewUnmappedSoftware: false,
    reviewLowConfidenceAlias: false,
    reviewDiscoveryModel: false,
    ...overrides,
  };
}

describe('InventoryComponentViewsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders the Container Images title for the container-images view', async () => {
    vi.spyOn(api, 'listInventoryComponents').mockResolvedValue(EMPTY_PAGE);
    vi.spyOn(api, 'listInventoryComponentFilters').mockResolvedValue(EMPTY_FILTER_VALUES);
    renderWithProviders(<InventoryComponentViewsPage selectedView="container-images" />);
    await waitFor(() =>
      expect(screen.getByText('Container Images')).toBeInTheDocument()
    );
  });

  it('renders the SBOMs title for the sbom view', async () => {
    vi.spyOn(api, 'listInventoryComponents').mockResolvedValue(EMPTY_PAGE);
    vi.spyOn(api, 'listInventoryComponentFilters').mockResolvedValue(EMPTY_FILTER_VALUES);
    renderWithProviders(<InventoryComponentViewsPage selectedView="sbom" />);
    await waitFor(() => expect(screen.getByText('SBOMs')).toBeInTheDocument());
  });

  it('shows loading state while inventory is fetching', () => {
    vi.spyOn(api, 'listInventoryComponents').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'listInventoryComponentFilters').mockResolvedValue(EMPTY_FILTER_VALUES);
    renderWithProviders(<InventoryComponentViewsPage selectedView="hosts" />);
    expect(screen.getByText('Loading inventory records...')).toBeInTheDocument();
  });

  it('shows empty state when no records are returned', async () => {
    vi.spyOn(api, 'listInventoryComponents').mockResolvedValue(EMPTY_PAGE);
    vi.spyOn(api, 'listInventoryComponentFilters').mockResolvedValue(EMPTY_FILTER_VALUES);
    renderWithProviders(<InventoryComponentViewsPage selectedView="hosts" />);
    await waitFor(() =>
      expect(screen.getByText(/no inventory records found/i)).toBeInTheDocument()
    );
  });

  it('renders a component row when data is returned', async () => {
    vi.spyOn(api, 'listInventoryComponents').mockResolvedValue({
      items: [buildComponentRecord()],
      page: 0,
      size: 25,
      totalItems: 1,
      totalPages: 1,
    });
    vi.spyOn(api, 'listInventoryComponentFilters').mockResolvedValue(EMPTY_FILTER_VALUES);
    renderWithProviders(<InventoryComponentViewsPage selectedView="hosts" />);
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());
    expect(screen.getByText('lodash')).toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('renders summary stats when data is present', async () => {
    vi.spyOn(api, 'listInventoryComponents').mockResolvedValue({
      items: [buildComponentRecord()],
      page: 0,
      size: 25,
      totalItems: 1,
      totalPages: 1,
    });
    vi.spyOn(api, 'listInventoryComponentFilters').mockResolvedValue(EMPTY_FILTER_VALUES);
    renderWithProviders(<InventoryComponentViewsPage selectedView="hosts" />);
    await waitFor(() =>
      expect(screen.getByText('web-prod-01')).toBeInTheDocument()
    );
  });

  it('shows error message when inventory fetch fails', async () => {
    vi.spyOn(api, 'listInventoryComponents').mockRejectedValue(new Error('Server error'));
    vi.spyOn(api, 'listInventoryComponentFilters').mockResolvedValue(EMPTY_FILTER_VALUES);
    renderWithProviders(<InventoryComponentViewsPage selectedView="hosts" />);
    await waitFor(() =>
      expect(screen.getByText(/Failed to load inventory/i)).toBeInTheDocument()
    );
  });
});
