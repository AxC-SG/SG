import { screen, waitFor } from '@testing-library/react';
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
});
