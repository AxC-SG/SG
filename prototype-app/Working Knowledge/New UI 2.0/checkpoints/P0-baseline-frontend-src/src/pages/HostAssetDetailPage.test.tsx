import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { HostAssetDetailPage } from './HostAssetDetailPage';

const EMPTY_BOM_EVIDENCE = {
  documentCount: 0,
  componentCount: 0,
  evidenceCount: 0,
  vulnerabilityLinkCount: 0,
  componentsInWorkflow: 0,
  documents: [],
  components: [],
};

function buildHostDetail(overrides = {}) {
  return {
    host: {
      assetId: 'asset-1',
      ciId: 'ci-1',
      name: 'web-prod-01',
      identifier: 'web-prod-01.example.com',
      sysId: 'sys-1',
      aliasCount: 0,
      installedSoftwareCount: 3,
      openFindingCount: 1,
      totalFindingCount: 1,
      unresolvedReviewCount: 0,
      ...overrides,
    },
    aliases: [],
    software: [],
    findings: [],
    applicableCves: [],
    bomEvidence: EMPTY_BOM_EVIDENCE,
  };
}

describe('HostAssetDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows loading state while host detail is fetching', () => {
    vi.spyOn(api, 'getHostAssetDetail').mockReturnValue(new Promise(() => {}));
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    expect(screen.getByText('Loading host detail...')).toBeInTheDocument();
  });

  it('renders host name after detail loads', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() =>
      expect(screen.getByText('web-prod-01')).toBeInTheDocument()
    );
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('renders host identifier below host name', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() =>
      expect(screen.getByText('web-prod-01.example.com')).toBeInTheDocument()
    );
  });

  it('shows error notice when host detail fetch fails', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockRejectedValue(new Error('Asset not found'));
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() =>
      expect(screen.getByText('Asset not found')).toBeInTheDocument()
    );
  });

  it('renders the Ownership section label after data loads', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() =>
      expect(screen.getByText('Ownership')).toBeInTheDocument()
    );
  });

  it('does not show loading when no assetId is provided', () => {
    renderWithProviders(<HostAssetDetailPage />);
    expect(screen.queryByText('Loading host detail...')).not.toBeInTheDocument();
  });

  it('renders finding id, package, owner, and other detail columns on the Created findings tab', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue({
      ...buildHostDetail(),
      findings: [
        {
          id: 'finding-1',
          displayId: 'F-0C965093EDAE',
          vulnerabilityId: 'CVE-2022-32114',
          packageName: 'chrome',
          packageVersion: '90.0.4430.212',
          severity: 'CRITICAL',
          status: 'OPEN',
          decisionState: 'AFFECTED',
          riskScore: 8.2,
          confidenceScore: 0.9,
          assignedTo: undefined,
          ownerGroup: undefined,
          creationSource: 'AUTOMATIC',
          lastObservedAt: '2024-01-01T00:00:00Z',
        },
      ],
    });
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /Created findings/ }));

    expect(await screen.findByText('F-0C965093EDAE')).toBeInTheDocument();
    expect(screen.getByText('CVE-2022-32114')).toBeInTheDocument();
    expect(screen.getByText('chrome')).toBeInTheDocument();
    expect(screen.getByText('90.0.4430.212')).toBeInTheDocument();
    expect(screen.getByText('Unassigned')).toBeInTheDocument();
    expect(screen.getByText('No ownership source')).toBeInTheDocument();
    expect(screen.getByText('Automatic')).toBeInTheDocument();
  });

  it('filters the Installed software tab to only records needing review when the attention card is clicked', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue({
      ...buildHostDetail({ unresolvedReviewCount: 1 }),
      software: [
        {
          id: 'sw-clean',
          displayName: 'Clean Package',
          activeInstall: true,
          unlicensedInstall: false,
          needsVersionReview: false,
          needsIdentityReview: false,
          needsDiscoveryModelReview: false,
          sourceSystem: 'sbom',
        },
        {
          id: 'sw-needs-review',
          displayName: 'Needs Review Package',
          activeInstall: true,
          unlicensedInstall: false,
          needsVersionReview: true,
          needsIdentityReview: false,
          needsDiscoveryModelReview: false,
          sourceSystem: 'sbom',
        },
      ],
    });
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());

    expect(screen.getByText('Clean Package')).toBeInTheDocument();
    expect(screen.getByText('Needs Review Package')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Inventory records need review/ }));

    expect(screen.getByText('Showing software needing review only (1 item)')).toBeInTheDocument();
    expect(screen.getByText('Needs Review Package')).toBeInTheDocument();
    expect(screen.queryByText('Clean Package')).not.toBeInTheDocument();
  });
});
