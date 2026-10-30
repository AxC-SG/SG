import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { AiExposuresPage } from './AiExposuresPage';

describe('AiExposuresPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('renders hypothesis state separately from validated findings', async () => {
    vi.spyOn(api, 'listAiGridExposures').mockResolvedValue({
      nextCursor: null,
      items: [{
        id: 'exposure-1', correlationId: 'R2_EXTERNAL_SENSITIVE_ACCESS', correlationVersion: '2.0.0',
        title: 'Externally reachable AI path to sensitive data', severity: 'CRITICAL',
        state: 'EXPOSURE_HYPOTHESIS', status: 'OPEN', confidence: 0.6,
        rootCauseArtifactId: 'artifact-1', firstObservedAt: '2026-08-01T00:00:00Z',
        lastObservedAt: '2026-08-02T00:00:00Z', findingId: null, affectedSystems: 1,
        impact: 'Potential sensitive-data access', rootCause: 'Authentication requires validation',
        breakpoint: 'Require strong authentication', confidenceMethod: 'HYPOTHESIS_PROXY',
      }],
    });

    renderWithProviders(<AiExposuresPage />);

    expect(await screen.findByText('Externally reachable AI path to sensitive data')).toBeInTheDocument();
    expect(screen.getByText('EXPOSURE HYPOTHESIS')).toBeInTheDocument();
    expect(screen.getByText('60%')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Externally reachable AI path to sensitive data' }))
      .toHaveAttribute('href', '/findings/ai/exposures/exposure-1');
  });

  it('reports a failed exposure list with retry instead of an empty table', async () => {
    const list = vi.spyOn(api, 'listAiGridExposures')
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValue({ nextCursor: null, items: [] });
    vi.spyOn(api, 'listAiExposurePriorities').mockResolvedValue([]);

    renderWithProviders(<AiExposuresPage />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Exposures could not be loaded.');
    expect(screen.queryByText('No exposure paths observed.')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry exposures' }));
    expect(await screen.findByText('No exposure paths observed.')).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
  });
});
