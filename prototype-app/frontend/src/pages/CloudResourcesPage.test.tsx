import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { CloudResourcePage } from '../features/connect/types';
import { renderWithProviders } from '../test/test-utils';
import { CloudResourcesPage } from './CloudResourcesPage';

function page(overrides: Partial<CloudResourcePage> = {}): CloudResourcePage {
  return {
    items: [
      { id: 'a-1', name: 'gcp-web', identifier: '//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/1',
        assetType: 'HOST', state: 'ACTIVE', provider: 'gcp', accountId: 'acme-prod', region: 'us-central1',
        availabilityZone: 'us-central1-a', resourceType: 'COMPUTE_INSTANCE', instanceType: 'e2-medium',
        network: 'default', labels: { env: 'prod' }, lastSeenAt: '2026-10-27T00:00:00Z' },
      { id: 'a-2', name: 'acme-logs', identifier: '//storage.googleapis.com/acme-logs', assetType: 'CLOUD_RESOURCE',
        state: 'INACTIVE', provider: 'gcp', accountId: 'acme-prod', region: 'us', resourceType: 'STORAGE_BUCKET', labels: {} }
    ],
    page: 0,
    size: 50,
    totalItems: 2,
    totalPages: 1,
    facets: {
      providers: [{ value: 'gcp', count: 2 }, { value: 'aws', count: 1 }],
      accounts: [{ value: 'acme-prod', count: 2 }],
      regions: [{ value: 'us-central1', count: 1 }],
      resourceTypes: [{ value: 'COMPUTE_INSTANCE', count: 1 }, { value: 'STORAGE_BUCKET', count: 1 }],
      states: [{ value: 'ACTIVE', count: 1 }, { value: 'INACTIVE', count: 1 }]
    },
    ...overrides
  };
}

describe('CloudResourcesPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('lists cloud resources with provider labels and links VMs to host detail', async () => {
    vi.spyOn(api, 'listCloudResources').mockResolvedValue(page());
    renderWithProviders(<CloudResourcesPage />);

    expect(await screen.findByRole('link', { name: 'gcp-web' })).toHaveAttribute('href', expect.stringContaining('/inventory/hosts/a-1'));
    expect(screen.getByText('acme-logs')).toBeInTheDocument();
    expect(screen.getAllByText('Google Cloud').length).toBeGreaterThan(0);
    expect(screen.getByText('Storage Bucket')).toBeInTheDocument();
  });

  it('filters by provider and resets to the first page', async () => {
    const list = vi.spyOn(api, 'listCloudResources').mockResolvedValue(page());
    renderWithProviders(<CloudResourcesPage />);

    await screen.findByRole('option', { name: 'Google Cloud (2)' });
    fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'gcp' } });

    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ provider: 'gcp', page: 0 })));
  });

  it('shows labels and the full resource id in the details row', async () => {
    vi.spyOn(api, 'listCloudResources').mockResolvedValue(page());
    renderWithProviders(<CloudResourcesPage />);

    fireEvent.click(await screen.findByRole('button', { name: 'Details for gcp-web' }));

    expect(screen.getByText(/env=prod/)).toBeInTheDocument();
    expect(screen.getByText('//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/1')).toBeInTheDocument();
  });

  it('explains how to discover resources when there are none', async () => {
    vi.spyOn(api, 'listCloudResources').mockResolvedValue(page({ items: [], totalItems: 0, totalPages: 0 }));
    renderWithProviders(<CloudResourcesPage />);

    expect(await screen.findByText(/Connect AWS or GCP/)).toBeInTheDocument();
  });
});
