import { afterEach, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { SccmConnectorPage } from './SccmConnectorPage';

afterEach(() => vi.restoreAllMocks());

it('shows pilot containment without save, test or sync actions', async () => {
  vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getSccmCmdbConfig>>);
  renderWithProviders(<SccmConnectorPage />);
  expect(await screen.findByRole('status')).toHaveTextContent('SCCM live JDBC is disabled');
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
});
