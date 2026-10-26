import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { intelligenceApi, type Candidate } from '../features/intelligence/api';
import { renderWithProviders } from '../test/test-utils';
import { IntelligenceReviewPanel } from './IntelligenceReviewPanel';

const ready: Candidate = { id: 'candidate-1', status: 'READY', base_release_id: null, digest: 'a'.repeat(64), selected_run_ids: ['run-1'], expanded_run_ids: ['run-0', 'run-1'], normalization_policy: 'sg-normalization-1', quality_report: { canonical_records: 1, exclusions: 1 }, error_code: null, published_release_id: null };
describe('reviewed intelligence publication', () => {
  beforeEach(() => {
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([
      { id: 'run-1', syncType: 'NVD', status: 'completed', recordsFetched: 1, recordsInserted: 0, recordsUpdated: 1, recordsFailed: 0, startedAt: '2026-10-22T00:00:00Z', runDomain: 'VULN_INTEL', runClass: 'INGESTION' },
      { id: 'failed', syncType: 'GHSA', status: 'failed', recordsFetched: 1, recordsInserted: 0, recordsUpdated: 0, recordsFailed: 1, startedAt: '2026-10-22T00:00:00Z', runDomain: 'VULN_INTEL', runClass: 'INGESTION' },
    ]);
    vi.spyOn(intelligenceApi, 'create').mockResolvedValue({ ...ready, status: 'BUILDING' });
    vi.spyOn(intelligenceApi, 'candidate').mockResolvedValue(ready);
    vi.spyOn(intelligenceApi, 'records').mockResolvedValue([{ id: 1, kind: 'OBSERVATION', external_id: 'CVE-2026-1234', source_system: 'nvd', validation: 'VALID', payload: { versionStart: '1.0' } }]);
    vi.spyOn(intelligenceApi, 'releases').mockResolvedValue([]);
    vi.spyOn(intelligenceApi, 'publish').mockResolvedValue({ status: 'PENDING' });
  });
  afterEach(() => vi.restoreAllMocks());
  it('shows expanded checkpoints and requires review of the exact candidate before approval', async () => {
    renderWithProviders(<IntelligenceReviewPanel />);
    expect(screen.queryByLabelText(/GHSA/)).not.toBeInTheDocument();
    fireEvent.click(await screen.findByLabelText(/NVD/));
    fireEvent.click(screen.getByRole('button', { name: 'Build review candidate' }));
    expect(await screen.findByText('Candidate · READY')).toBeInTheDocument();
    expect(screen.getByText('Selected runs: 1 · Expanded runs: 2')).toBeInTheDocument();
    expect(await screen.findByText('CVE-2026-1234')).toBeInTheDocument();
    const approve = screen.getByRole('button', { name: 'Approve and publish' });
    expect(approve).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I reviewed the expanded selection/));
    fireEvent.click(approve);
    await waitFor(() => expect(intelligenceApi.publish).toHaveBeenCalledWith(ready, expect.any(String)));
    expect(intelligenceApi.create).toHaveBeenCalledWith(['run-1']);
  });
  it('includes completed staging repairs and excludes EOL from review selection', async () => {
    vi.mocked(api.listSyncRuns).mockResolvedValueOnce(['NVD_TARGET_REPAIR', 'VEX_ASSERTION_REPAIR', 'VEX_ROLLOUT_BACKFILL', 'EOL_DATE_SWEEP'].map((syncType) => ({
      id: syncType, syncType, status: 'completed', recordsFetched: 1, recordsInserted: 0, recordsUpdated: 1, recordsFailed: 0,
      startedAt: '2026-10-22T00:00:00Z', runDomain: 'PROCESSING', runClass: 'REPAIR',
    })));
    renderWithProviders(<IntelligenceReviewPanel />);
    fireEvent.click(await screen.findByLabelText(/NVD_TARGET_REPAIR/));
    expect(screen.getByLabelText(/VEX_ASSERTION_REPAIR/)).toBeInTheDocument();
    expect(screen.getByLabelText(/VEX_ROLLOUT_BACKFILL/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/EOL_DATE_SWEEP/)).not.toBeInTheDocument();
    expect(api.listSyncRuns).toHaveBeenCalledWith({ category: 'vulnerability', limit: 200 });
    fireEvent.click(screen.getByRole('button', { name: 'Build review candidate' }));
    await waitFor(() => expect(intelligenceApi.create).toHaveBeenCalledWith(['NVD_TARGET_REPAIR']));
  });
  it('keeps stale approval errors visible for a rebuild', async () => {
    vi.mocked(intelligenceApi.publish).mockRejectedValue(new Error('Candidate base release changed; rebuild and review'));
    renderWithProviders(<IntelligenceReviewPanel />);
    fireEvent.click(await screen.findByLabelText(/NVD/));
    fireEvent.click(screen.getByRole('button', { name: 'Build review candidate' }));
    fireEvent.click(await screen.findByLabelText(/I reviewed the expanded selection/));
    fireEvent.click(screen.getByRole('button', { name: 'Approve and publish' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Candidate base release changed');
  });
});
