import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { SoftwareIdentitiesPage } from './SoftwareIdentitiesPage';

const EMPTY_PAGE = {
  content: [],
  number: 0,
  size: 25,
  totalElements: 0,
  totalPages: 0,
};

const EMPTY_FUNNEL = {
  recordsFound: 0,
  uniqueSoftware: 0,
  softwareWithVulnerabilities: 0,
  softwareWithFindings: 0,
  sourceCount: 0,
};

function buildIdentity(overrides = {}) {
  return {
    id: 'si-1',
    displayName: 'lodash',
    canonicalKey: 'npm/lodash',
    normalizedKey: 'npm:lodash',
    assetTypes: ['HOST'],
    ecosystems: ['npm'],
    sourceSystems: ['sbom'],
    mappingConfirmed: false,
    needsEolMapping: false,
    assetCount: 1,
    componentCount: 2,
    versionCount: 1,
    eolComponentCount: 0,
    nearEolComponentCount: 0,
    unknownEolComponentCount: 0,
    openFindingCount: 0,
    criticalFindingCount: 0,
    highFindingCount: 0,
    openVulnerabilityCount: 0,
    ...overrides,
  };
}

describe('SoftwareIdentitiesPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows loading state while identities are fetching', () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    expect(screen.getByText('Loading software identities…')).toBeInTheDocument();
  });

  it('renders the Software Identities page title after data loads', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue(EMPTY_PAGE);
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    await waitFor(() =>
      expect(screen.getByText('Software Identities')).toBeInTheDocument()
    );
  });

  it('shows the Deployed software identities section heading', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue(EMPTY_PAGE);
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    await waitFor(() =>
      expect(screen.getByText('Deployed software identities')).toBeInTheDocument()
    );
  });

  it('shows empty state when no identities are returned', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue(EMPTY_PAGE);
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    await waitFor(() =>
      expect(
        screen.getByText('No deployed software identities matched the current search.')
      ).toBeInTheDocument()
    );
  });

  it('renders an identity row when data is returned', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue({
      ...EMPTY_PAGE,
      content: [buildIdentity()],
      totalElements: 1,
      totalPages: 1,
    });
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    await waitFor(() => expect(screen.getByText('lodash')).toBeInTheDocument());
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('shows error banner when identities query fails', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockRejectedValue(new Error('Network failure'));
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    await waitFor(() =>
      expect(
        screen.getByText(/Failed to load software identities: Network failure/i)
      ).toBeInTheDocument()
    );
  });

  it('renders the Software Exposure widget card', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue(EMPTY_PAGE);
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    await waitFor(() =>
      expect(screen.getByText('Software Exposure')).toBeInTheDocument()
    );
  });

  it('renders the Lifecycle Status widget card', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue(EMPTY_PAGE);
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    await waitFor(() =>
      expect(screen.getByText('Lifecycle Status')).toBeInTheDocument()
    );
  });

  it('shows identity vendor when present', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue({
      ...EMPTY_PAGE,
      content: [buildIdentity({ vendor: 'Lodash' })],
      totalElements: 1,
      totalPages: 1,
    });
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    renderWithProviders(<SoftwareIdentitiesPage />);
    await waitFor(() => expect(screen.getByText('Lodash')).toBeInTheDocument());
  });

  it('opens the CVE exposure list as a named dialog with retry and real asset links', async () => {
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue({
      ...EMPTY_PAGE,
      content: [buildIdentity({ openVulnerabilityCount: 3 })],
      totalElements: 1,
      totalPages: 1,
    });
    vi.spyOn(api, 'getSoftwareIdentityFunnel').mockResolvedValue(EMPTY_FUNNEL);
    const detail = vi.spyOn(api, 'getSoftwareIdentityDetail')
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValue({
        assets: [{
          componentId: 'c-1', assetId: 'host-1', assetName: 'web-prod-01', assetIdentifier: 'web-prod-01.local',
          version: '4.17.20', assetType: 'HOST', openVulnerabilityCount: 3, openFindingCount: 1,
          isEol: false, eolDaysRemaining: null, eolDate: null,
        }],
      } as unknown as Awaited<ReturnType<typeof api.getSoftwareIdentityDetail>>);
    renderWithProviders(<SoftwareIdentitiesPage />, { route: '/inventory/software-identities' });

    const row = (await screen.findByRole('link', { name: 'lodash' })).closest('tr') as HTMLElement;
    expect(screen.getByRole('link', { name: 'lodash' })).toHaveAttribute('href', '/inventory/software-identities/si-1');
    fireEvent.click(within(row).getByRole('button', { name: '3' }));

    const dialog = await screen.findByRole('dialog', { name: 'CVE Exposure — lodash' });
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Assets for this software identity could not be loaded.');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Retry' }));
    const assetLink = await within(dialog).findByRole('link', { name: 'web-prod-01' });
    expect(assetLink.getAttribute('href')).toMatch(/^\/inventory\/hosts\/host-1\?returnTo=/);
    expect(detail).toHaveBeenCalledTimes(2);

    fireEvent.click(within(dialog).getByRole('button', { name: 'Close panel' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
