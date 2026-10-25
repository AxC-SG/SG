import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { AiBaselineSection } from './AiBaselineSection';

const observation = { digestKind: 'PROMPT', comparisonOutcome: 'UNAPPROVED', sourceRunId: 'run-1', observedAt: '2026-10-12T00:00:00Z', stale: false };
describe('asset baseline approval', () => {
  beforeEach(() => {
    vi.spyOn(api, 'getAiBaselines').mockResolvedValue([]);
    vi.spyOn(api, 'getAiBaselineObservations').mockResolvedValue([observation]);
    vi.spyOn(api, 'getAiBaselineHistory').mockResolvedValue([]);
  });
  afterEach(() => vi.restoreAllMocks());
  it('approves by observation reference', async () => {
    vi.mocked(api.getAiBaselineObservations).mockResolvedValue([{ ...observation, changedFields: ['guardrailId'], observationVersion: 'source-v2' }]);
    const approve = vi.spyOn(api, 'approveAiBaselineObservation').mockResolvedValue({ artifactId: 'asset', digestKind: 'PROMPT', approvalStatus: 'APPROVED', approvedBy: 'analyst', approvedAt: observation.observedAt, sourceRunId: 'run-1' });
    renderWithProviders(<AiBaselineSection artifactId="asset" canApprove component="Support" version="v1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve current observation' }));
    await waitFor(() => expect(approve).toHaveBeenCalledWith('asset', { ...observation, changedFields: ['guardrailId'], observationVersion: 'source-v2' }, false));
    expect(screen.getByText('Source run: run-1')).toBeInTheDocument();
    expect(screen.getByText('Observed differences: guardrailId')).toBeInTheDocument();
    expect(screen.getByText('Observation version: source-v2')).toBeInTheDocument();
  });
  it('does not offer write actions to unauthorized users', async () => {
    renderWithProviders(<AiBaselineSection artifactId="asset" canApprove={false} component="Support" version="v1" />);
    await screen.findByText('Approval required');
    expect(screen.queryByRole('button', { name: 'Approve current observation' })).not.toBeInTheDocument();
  });
  it('permits revoking a legacy approval when its observation is unavailable', async () => {
    vi.mocked(api.getAiBaselines).mockResolvedValue([{ artifactId: 'asset', digestKind: 'PROMPT', approvalStatus: 'APPROVED', approvedBy: 'analyst', approvedAt: observation.observedAt, sourceRunId: null }]);
    vi.mocked(api.getAiBaselineObservations).mockResolvedValue([]);
    const revoke = vi.spyOn(api, 'revokeAiBaseline').mockResolvedValue({ artifactId: 'asset', digestKind: 'PROMPT', approvalStatus: 'REVOKED', approvedBy: 'analyst', approvedAt: observation.observedAt, sourceRunId: null });
    renderWithProviders(<AiBaselineSection artifactId="asset" canApprove component="Support" version="v1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(revoke).toHaveBeenCalledWith('asset', 'PROMPT'));
    expect(screen.getByText('Unknown: current observation unavailable')).toBeInTheDocument();
  });
  it('blocks stale approval and permits revocation', async () => {
    vi.mocked(api.getAiBaselines).mockResolvedValue([{ artifactId: 'asset', digestKind: 'PROMPT', approvalStatus: 'APPROVED', approvedBy: 'analyst', approvedAt: observation.observedAt, sourceRunId: 'run-1' }]);
    vi.mocked(api.getAiBaselineObservations).mockResolvedValue([{ ...observation, stale: true }]);
    const revoke = vi.spyOn(api, 'revokeAiBaseline').mockResolvedValue({ artifactId: 'asset', digestKind: 'PROMPT', approvalStatus: 'REVOKED', approvedBy: 'analyst', approvedAt: observation.observedAt, sourceRunId: 'run-1' });
    renderWithProviders(<AiBaselineSection artifactId="asset" canApprove component="Support" version="v1" />);
    expect(await screen.findByRole('button', { name: 'Reapprove current observation' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(revoke).toHaveBeenCalledWith('asset', 'PROMPT'));
  });
});
