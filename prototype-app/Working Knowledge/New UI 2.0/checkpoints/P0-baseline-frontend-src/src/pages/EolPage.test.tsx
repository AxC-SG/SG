import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { EolProductCatalog, EolSummary, PackageEolStatus } from '../features/eol/types';
import { renderWithProviders } from '../test/test-utils';
import { EolPage } from './EolPage';

function buildEolSummary(overrides: Partial<EolSummary> = {}): EolSummary {
  return {
    totalTracked: 200,
    eolCount: 15,
    nearEolCount: 22,
    supportedCount: 158,
    unknownCount: 5,
    ...overrides,
  };
}

function buildPackageStatus(overrides: Partial<PackageEolStatus> = {}): PackageEolStatus {
  return {
    packageName: 'openssl',
    ecosystem: 'deb',
    assetCount: 3,
    isEol: true,
    eolDate: '2023-09-11',
    eolDaysRemaining: -600,
    ...overrides,
  };
}

function buildProduct(overrides: Partial<EolProductCatalog> = {}): EolProductCatalog {
  return {
    slug: 'opensuse',
    displayName: 'OpenSUSE',
    cpeVendor: 'opensuse',
    cpeProduct: 'opensuse',
    releaseCount: 4,
    ...overrides,
  };
}

describe('EolPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders EOL summary counts', async () => {
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary({ eolCount: 15, nearEolCount: 22 }));
    vi.spyOn(api, 'getEolPackageStatuses').mockResolvedValue({ content: [], totalElements: 0, totalPages: 0, number: 0, size: 25 } as never);
    vi.spyOn(api, 'listEolProducts').mockResolvedValue([]);

    renderWithProviders(<EolPage />);

    expect(await screen.findByText('15')).toBeInTheDocument();
    expect(await screen.findByText('22')).toBeInTheDocument();
  });

  it('calls getEolPackageStatuses and renders the at-risk tab', async () => {
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary({ eolCount: 15 }));
    vi.spyOn(api, 'getEolPackageStatuses').mockResolvedValue({
      content: [buildPackageStatus({ packageName: 'openssl' })],
      totalElements: 1, totalPages: 1, number: 0, size: 25,
    } as never);
    vi.spyOn(api, 'listEolProducts').mockResolvedValue([]);

    renderWithProviders(<EolPage />);

    await waitFor(() => {
      expect(api.getEolPackageStatuses).toHaveBeenCalled();
    });
    expect(await screen.findByText('15')).toBeInTheDocument();
  });

  it('renders EOL catalog tab products', async () => {
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary());
    vi.spyOn(api, 'getEolPackageStatuses').mockResolvedValue({
      content: [], totalElements: 0, totalPages: 0, number: 0, size: 25,
    } as never);
    vi.spyOn(api, 'listEolProducts').mockResolvedValue([
      buildProduct({ slug: 'opensuse', displayName: 'OpenSUSE' }),
      buildProduct({ slug: 'nodejs', displayName: 'Node.js' }),
    ]);

    renderWithProviders(<EolPage />);

    await waitFor(() => {
      expect(screen.queryByText(/loading/i)).not.toBeInTheDocument();
    });

    const catalogTab = screen.getByRole('button', { name: /catalog/i });
    catalogTab.click();

    expect(await screen.findByText('OpenSUSE')).toBeInTheDocument();
    expect(await screen.findByText('Node.js')).toBeInTheDocument();
  });

  it('shows empty state when no at-risk packages exist', async () => {
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary({ eolCount: 0, nearEolCount: 0 }));
    vi.spyOn(api, 'getEolPackageStatuses').mockResolvedValue({
      content: [], totalElements: 0, totalPages: 0, number: 0, size: 25,
    } as never);
    vi.spyOn(api, 'listEolProducts').mockResolvedValue([]);

    renderWithProviders(<EolPage />);

    await waitFor(() => {
      expect(api.getEolPackageStatuses).toHaveBeenCalled();
    });
  });
});
