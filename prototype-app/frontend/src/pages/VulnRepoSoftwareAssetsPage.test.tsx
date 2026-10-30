import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { VulnRepoSoftwareAssetsPage } from './VulnRepoSoftwareAssetsPage';

const SW_ID = 'sw-identity-1';
const BASE_PATH = '/vuln-repo/software-assets';

function renderPage(search = `?softwareIdentityId=${SW_ID}&software=lodash`) {
  return renderWithProviders(<VulnRepoSoftwareAssetsPage />, {
    initialEntries: [{ pathname: BASE_PATH, search }],
  });
}

function buildDetail(assetOverrides = {}) {
  return {
    softwareIdentityId: SW_ID,
    displayName: 'lodash',
    impactedAssetCount: 1,
    assets: [
      {
        assetId: 'asset-1',
        assetName: 'web-prod-01',
        assetIdentifier: 'web-prod-01.example.com',
        assetType: 'HOST',
        componentId: 'cmp-1',
        version: '4.17.15',
        sourceSystem: 'sbom',
        openCveCount: 2,
        openFindingCount: 1,
        lastObservedAt: '2026-01-01T00:00:00Z',
        ...assetOverrides,
      },
    ],
  };
}

describe('VulnRepoSoftwareAssetsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows error when softwareIdentityId is missing', () => {
    renderPage('?software=lodash');
    expect(screen.getByRole('alert')).toHaveTextContent('Software identity is required.');
  });

  it('shows loading state while data is fetching', () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByText('Loading impacted assets...')).toBeInTheDocument();
  });

  it('shows error message when the query fails', async () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockRejectedValue(new Error('Network error'));
    renderPage();
    await waitFor(() => expect(screen.getByText('Network error')).toBeInTheDocument());
  });

  it('shows empty state when no assets are returned', async () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockResolvedValue({
      softwareIdentityId: SW_ID,
      displayName: 'lodash',
      impactedAssetCount: 0,
      assets: [],
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText('No assets were found for this software identity.')).toBeInTheDocument()
    );
  });

  it('renders asset name when data is returned', async () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockResolvedValue(buildDetail());
    renderPage();
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());
  });

  it('renders asset identifier below asset name', async () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockResolvedValue(buildDetail());
    renderPage();
    await waitFor(() =>
      expect(screen.getByText('web-prod-01.example.com')).toBeInTheDocument()
    );
  });

  it('shows displayName as the page heading when data loads', async () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockResolvedValue(buildDetail());
    renderPage();
    await waitFor(() => expect(screen.getByText('lodash')).toBeInTheDocument());
  });

  it('renders the Back to Dashboard button', () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByRole('button', { name: /back to dashboard/i })).toBeInTheDocument();
  });

  it('shows open CVEs count as a link when count is greater than zero', async () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockResolvedValue(buildDetail());
    renderPage();
    const link = await screen.findByRole('link', { name: '2' });
    expect(link.getAttribute('href')).toMatch(/^\/vuln-repo\/host-assets\/asset-1\?returnTo=.+#applicable-cves$/);
    expect(screen.getByRole('link', { name: 'web-prod-01' }).getAttribute('href')).not.toContain('#');
  });

  it('offers retry when the query fails', async () => {
    const load = vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockRejectedValueOnce(new Error('Network error')).mockResolvedValue(buildDetail());
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Network error');
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('web-prod-01')).toBeInTheDocument();
    expect(screen.getByText('1 asset is currently associated with this software identity in the repository scope.')).toBeInTheDocument();
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('shows zero as plain text when openCveCount is 0', async () => {
    vi.spyOn(api, 'getVulnRepoSoftwareAssets').mockResolvedValue(
      buildDetail({ openCveCount: 0, openFindingCount: 0 })
    );
    renderPage();
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());
    expect(screen.queryByRole('link', { name: '0' })).not.toBeInTheDocument();
  });
});
