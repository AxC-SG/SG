import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { renderWithProviders } from '../test/test-utils';
import { SoftwareIdentityDetailPage } from './SoftwareIdentityDetailPage';

const EMPTY_CVE_PAGE = {
  summary: {
    reviewQueueCount: 0,
    applicableCount: 0,
    impactedCount: 0,
    underInvestigationCount: 0,
    resolvedCount: 0,
  },
  items: [],
  page: 0,
  size: 100,
  totalItems: 0,
  totalPages: 0,
};

const EMPTY_METADATA = {
  softwareIdentityId: 'si-1',
  owner: '',
  licensed: '',
  licenseType: '',
  supportGroup: '',
  recommendation: '',
};

const EMPTY_BOM_EVIDENCE = {
  documentCount: 0,
  componentCount: 0,
  evidenceCount: 0,
  vulnerabilityLinkCount: 0,
  componentsInWorkflow: 0,
  documents: [],
  components: [],
};

function buildDetail(overrides = {}) {
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
    assetCount: 2,
    componentCount: 2,
    versionCount: 1,
    eolComponentCount: 0,
    nearEolComponentCount: 0,
    unknownEolComponentCount: 0,
    openFindingCount: 0,
    openVulnerabilityCount: 0,
    bomEvidence: EMPTY_BOM_EVIDENCE,
    versions: [],
    assets: [],
    ...overrides,
  };
}

function mockSupportingQueries() {
  vi.spyOn(api, 'getSoftwareIdentityMetadata').mockResolvedValue(EMPTY_METADATA);
  vi.spyOn(cveWorkbenchApi, 'listVulnRepoVulnerabilities').mockResolvedValue(EMPTY_CVE_PAGE);
}

describe('SoftwareIdentityDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows loading state while detail is fetching', () => {
    vi.spyOn(api, 'getSoftwareIdentityDetail').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'getSoftwareIdentityMetadata').mockReturnValue(new Promise(() => {}));
    vi.spyOn(cveWorkbenchApi, 'listVulnRepoVulnerabilities').mockReturnValue(new Promise(() => {}));
    renderWithProviders(<SoftwareIdentityDetailPage softwareIdentityId="si-1" />);
    expect(screen.getByText('Loading software identity...')).toBeInTheDocument();
  });

  it('shows error message when detail fetch fails', async () => {
    vi.spyOn(api, 'getSoftwareIdentityDetail').mockRejectedValue(new Error('Not authorized'));
    mockSupportingQueries();
    renderWithProviders(<SoftwareIdentityDetailPage softwareIdentityId="si-1" />);
    await waitFor(() =>
      expect(screen.getByText('Not authorized')).toBeInTheDocument()
    );
  });

  it('shows not-found message when detail resolves null', async () => {
    vi.spyOn(api, 'getSoftwareIdentityDetail').mockResolvedValue(null as never);
    mockSupportingQueries();
    renderWithProviders(<SoftwareIdentityDetailPage softwareIdentityId="si-1" />);
    await waitFor(() =>
      expect(screen.getByText('Software identity was not found.')).toBeInTheDocument()
    );
  });

  it('renders the software displayName as the title after detail loads', async () => {
    vi.spyOn(api, 'getSoftwareIdentityDetail').mockResolvedValue(buildDetail());
    mockSupportingQueries();
    renderWithProviders(<SoftwareIdentityDetailPage softwareIdentityId="si-1" />);
    await waitFor(() =>
      expect(screen.getByText('lodash')).toBeInTheDocument()
    );
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('renders vendor/product as title when both are present', async () => {
    vi.spyOn(api, 'getSoftwareIdentityDetail').mockResolvedValue(
      buildDetail({ vendor: 'Lodash Corp', product: 'lodash' })
    );
    vi.spyOn(api, 'getSoftwareIdentityMetadata').mockResolvedValue(EMPTY_METADATA);
    vi.spyOn(cveWorkbenchApi, 'listVulnRepoVulnerabilities').mockResolvedValue(EMPTY_CVE_PAGE);
    vi.spyOn(api, 'listFindings').mockResolvedValue({ items: [], page: 0, size: 200, totalItems: 0, totalPages: 0 });
    vi.spyOn(cveWorkbenchApi, 'getFixRecordsBySoftware').mockResolvedValue([]);
    renderWithProviders(<SoftwareIdentityDetailPage softwareIdentityId="si-1" />);
    await waitFor(() =>
      expect(screen.getByText('Lodash Corp')).toBeInTheDocument()
    );
  });

  it('renders the Ownership and Publisher section heading', async () => {
    vi.spyOn(api, 'getSoftwareIdentityDetail').mockResolvedValue(buildDetail());
    mockSupportingQueries();
    renderWithProviders(<SoftwareIdentityDetailPage softwareIdentityId="si-1" />);
    await waitFor(() =>
      expect(screen.getByText('Ownership and Publisher')).toBeInTheDocument()
    );
  });
});
