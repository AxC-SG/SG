import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '../../test/test-utils';
import { fixIntelligenceApi } from './api';
import { FixContextPanel } from './FixContextPanel';

describe('FixContextPanel', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lists fixes with the asset deployment state', async () => {
    const context = vi.spyOn(fixIntelligenceApi, 'context').mockResolvedValue({
      cveId: 'CVE-2024-20666',
      assetId: 'asset-1',
      fixes: [{
        fixId: 'fix-1', displayId: 'KB5034441', title: '2026-10 Cumulative Update', fixType: 'PATCH', status: 'ACTIVE',
        severity: 'CRITICAL', cveIds: ['CVE-2024-20666'], assetStatus: 'SCHEDULED', assetProvider: 'SCCM',
        scheduledAt: '2026-11-01T02:00:00Z', deadlineAt: null, installedAt: null, coveragePercent: 40
      }]
    });
    renderWithProviders(<FixContextPanel cveId="CVE-2024-20666" assetId="asset-1" />);

    expect(await screen.findByRole('link', { name: '2026-10 Cumulative Update' })).toHaveAttribute('href', '/fix-intelligence/details/fix-1');
    expect(screen.getByText(/^Scheduled/)).toHaveAttribute('title', 'Reported by SCCM');
    expect(screen.getByText(/does not change finding status/)).toBeInTheDocument();
    expect(context).toHaveBeenCalledWith({ cveId: 'CVE-2024-20666', assetId: 'asset-1' });
  });

  it('says so when no fix is recorded', async () => {
    vi.spyOn(fixIntelligenceApi, 'context').mockResolvedValue({ cveId: null, assetId: 'asset-1', fixes: [] });
    renderWithProviders(<FixContextPanel assetId="asset-1" />);
    expect(await screen.findByText(/recorded for this asset/)).toBeInTheDocument();
  });

  it('renders nothing without a CVE or asset', () => {
    const context = vi.spyOn(fixIntelligenceApi, 'context');
    const { container } = renderWithProviders(<FixContextPanel />);
    expect(container).toBeEmptyDOMElement();
    expect(context).not.toHaveBeenCalled();
  });

  it('can recover remediation options after a service failure', async () => {
    vi.spyOn(fixIntelligenceApi, 'context').mockRejectedValueOnce(new Error('Unavailable'))
      .mockResolvedValue({ cveId: null, assetId: 'asset-1', fixes: [] });
    renderWithProviders(<FixContextPanel assetId="asset-1" />);
    expect(await screen.findByRole('alert')).toHaveTextContent('unavailable right now');
    fireEvent.click(screen.getByRole('button', { name: 'Retry remediation options' }));
    expect(await screen.findByText(/recorded for this asset/)).toBeInTheDocument();
  });
});
