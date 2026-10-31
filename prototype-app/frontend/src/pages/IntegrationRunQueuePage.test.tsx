import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { IntegrationRunQueuePage } from './IntegrationRunQueuePage';

describe('IntegrationRunQueuePage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('reports a failed load as an error with retry rather than "no runs recorded"', async () => {
    const runs = vi.spyOn(api, 'listSyncRuns').mockRejectedValueOnce(new Error('runs offline')).mockResolvedValue([]);

    renderWithProviders(<IntegrationRunQueuePage />);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Integration runs could not be loaded: runs offline');
    expect(screen.queryByText('No integration runs recorded yet.')).not.toBeInTheDocument();
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No integration runs recorded yet.')).toBeInTheDocument();
    expect(runs).toHaveBeenCalledTimes(2);
  });

  it('labels a partial run with the same warning convention as inventory run history', async () => {
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([{
      id: 'nvd-run', syncType: 'NVD_DELTA', runDomain: 'VULN_INTEL', runClass: 'INGESTION', status: 'PARTIAL',
      recordsFetched: 10, recordsInserted: 8, recordsUpdated: 0, recordsFailed: 2,
      startedAt: '2026-07-29T09:00:00Z', completedAt: '2026-07-29T09:01:00Z',
    }]);

    renderWithProviders(<IntegrationRunQueuePage />);

    expect(await screen.findByText('Partial')).toHaveClass('status-pill', 'status-warning');
  });
});
