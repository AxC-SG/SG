import { screen, waitFor } from '@testing-library/react';
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
});
