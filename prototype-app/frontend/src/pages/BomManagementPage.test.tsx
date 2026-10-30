import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { BomManagementPage } from './BomManagementPage';

describe('BomManagementPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('reports a failed saved-pipeline list with retry instead of "no saved pipelines"', async () => {
    vi.spyOn(api, 'listBomSources').mockResolvedValue([]);
    const list = vi.spyOn(api, 'listGithubSbomSources').mockRejectedValueOnce(new Error('offline')).mockResolvedValue([]);

    renderWithProviders(<BomManagementPage title="BOM Management" caption="" includeGithubSources />);

    const alert = await screen.findByText(/Saved pipelines could not be loaded\./);
    expect(screen.queryByText(/No saved pipelines yet/)).not.toBeInTheDocument();
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText(/No saved pipelines yet/)).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
  });
});
