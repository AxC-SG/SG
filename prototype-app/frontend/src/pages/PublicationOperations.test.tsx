import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { intelligenceApi } from '../features/intelligence/api';
import { renderWithProviders } from '../test/test-utils';
import { PublicationOperations } from './PublicationOperations';
import { IntelligenceImportProfiles } from './IntelligenceImportProfiles';
afterEach(() => vi.restoreAllMocks());
it('does not invent a percentage for unknown totals and sends pause', async () => {
  vi.spyOn(intelligenceApi, 'progress').mockResolvedValue({ status: 'RUNNING', phase: 'CORRELATING', processed: 100, total: null, heartbeat_at: null, started_at: null, checkpoint: null, attempt_count: 1, events: [{ id: '1', level: 'WARNING', message: 'Missing score', created_at: '2026-11-19T00:00:00Z' }] });
  const control = vi.spyOn(intelligenceApi, 'control').mockResolvedValue({});
  renderWithProviders(<PublicationOperations candidateId="candidate" />);
  expect(await screen.findByText(/Total unknown/)).toBeInTheDocument();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(screen.getByText(/Missing score/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Pause' }));
  await waitFor(() => expect(control).toHaveBeenCalledWith('candidate', 'PAUSE'));
});
it('shows known totals and only resume/cancel for paused jobs', async () => {
  vi.spyOn(intelligenceApi, 'progress').mockResolvedValue({ status: 'PAUSED', phase: 'NORMALIZING', processed: 25, total: 100, heartbeat_at: null, started_at: null, checkpoint: 25, attempt_count: 1, events: [] });
  renderWithProviders(<PublicationOperations candidateId="candidate" />);
  expect(await screen.findByText(/25.0%/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Resume' })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Pause' })).not.toBeInTheDocument();
});
it('requires source selection and rejects reversed profile ranges', async () => {
  vi.spyOn(intelligenceApi, 'profiles').mockResolvedValue([]);
  renderWithProviders(<IntelligenceImportProfiles />);
  fireEvent.change(screen.getByLabelText('Profile name'), { target: { value: 'Historical' } });
  expect(screen.getByRole('button', { name: 'Save import profile' })).toBeDisabled();
  fireEvent.click(screen.getByLabelText('NVD'));
  fireEvent.change(screen.getByLabelText('Publication year from'), { target: { value: '2025' } });
  fireEvent.change(screen.getByLabelText('Publication year to'), { target: { value: '2020' } });
  expect(screen.getByRole('button', { name: 'Save import profile' })).toBeDisabled();
});
