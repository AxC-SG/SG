import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, type ApplicationRiskSummary, type BomComponentDetail, type BomComponentSummaryItem } from '../../api/client';
import { cveWorkbenchApi } from '../cve-workbench/api';
import { renderWithProviders } from '../../test/test-utils';
import { BomComponentDetailPanel } from './BomComponentDetailPanel';

const SEED = {
  componentId: 'comp-1',
  packageName: 'left-pad',
  version: '1.0.0',
  purl: 'pkg:npm/left-pad@1.0.0',
  ecosystem: 'npm',
  license: 'MIT',
  assetId: 'asset-1',
  assetName: 'kanra-mobile',
  bomTypes: ['SBOM'],
  bomEvidenceState: 'SUPPORTED',
  isEol: false,
  eolDate: null,
  criticalCveCount: 1,
  highCveCount: 0,
  mediumCveCount: 0,
  lowCveCount: 0,
  totalCveCount: 1,
  correlationState: 'APPLICABLE',
  riskLevel: 'HIGH',
  findingCount: 0,
  criticalFindingCount: 0,
  highFindingCount: 0,
} as BomComponentSummaryItem;

const DETAIL = {
  ...SEED,
  packageGroup: null,
  scope: null,
  normalizedName: null,
  eolSlug: null,
  eolCycle: null,
  eolSupportEndDate: null,
  supportPhase: null,
  eolCheckedAt: null,
  ingestedAt: '2026-08-01T00:00:00Z',
  lastObservedAt: '2026-08-01T00:00:00Z',
  assetIdentifier: 'kanra-mobile',
  assetType: 'APPLICATION',
  cves: [{
    cveId: 'cve-1', externalId: 'CVE-2026-0001', severity: 'CRITICAL', title: 'Prototype pollution',
    applicabilityState: 'APPLICABLE', epssScore: 0.1, cvssScore: 9.8,
  }],
  eolReleases: [],
} as BomComponentDetail;

const APP = {
  assetId: 'asset-1', assetName: 'kanra-mobile', assetIdentifier: 'kanra-mobile', businessCriticality: 'HIGH',
  bomTypes: ['SBOM'], totalComponents: 1, vulnerableComponents: 1, eolComponents: 0, criticalCveCount: 1,
  highCveCount: 0, mediumCveCount: 0, lowCveCount: 0, totalCveCount: 1, riskScore: 80, riskLevel: 'HIGH',
  lastIngestedAt: null,
} as unknown as ApplicationRiskSummary;

describe('BomComponentDetailPanel', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('offers retry when component details fail and links CVEs to their detail', async () => {
    const load = vi.spyOn(api, 'getBomComponentDetail').mockRejectedValueOnce(new Error('boom')).mockResolvedValue(DETAIL);

    renderWithProviders(<BomComponentDetailPanel componentId="comp-1" seed={SEED} onClose={() => {}} />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load component details.');
    fireEvent.click(screen.getByRole('button', { name: 'Retry component details' }));
    fireEvent.click(await screen.findByRole('button', { name: /^Vulnerabilities/ }));
    expect(screen.getByRole('link', { name: 'CVE-2026-0001' })).toHaveAttribute('href', '/vuln-repo/org-cves/CVE-2026-0001');
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('creates findings from a named dialog that keeps input on failure and reports the result', async () => {
    vi.spyOn(api, 'getBomComponentDetail').mockResolvedValue(DETAIL);
    vi.spyOn(api, 'getApplicationRisk').mockResolvedValue([APP]);
    const create = vi.spyOn(cveWorkbenchApi, 'createManualFindings')
      .mockRejectedValueOnce(new Error('Finding creation failed'))
      .mockResolvedValue({ createdCount: 1, reopenedCount: 0, alreadyOpenCount: 0 } as Awaited<ReturnType<typeof cveWorkbenchApi.createManualFindings>>);

    renderWithProviders(<BomComponentDetailPanel componentId="comp-1" seed={SEED} onClose={() => {}} />);

    fireEvent.click(await screen.findByRole('button', { name: /^Applications/ }));
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select kanra-mobile' }));
    fireEvent.click(screen.getByRole('button', { name: 'Create Findings for 1 app' }));

    const dialog = await screen.findByRole('dialog', { name: 'Create Findings' });
    fireEvent.change(within(dialog).getByLabelText('Finding title'), { target: { value: 'Patch left-pad' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create Findings (1)' }));

    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Finding creation failed');
    expect(within(dialog).getByLabelText('Finding title')).toHaveValue('Patch left-pad');

    fireEvent.click(within(dialog).getByRole('button', { name: 'Create Findings (1)' }));
    expect(await screen.findByText('Created or reopened 1 finding(s).')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(create).toHaveBeenCalledTimes(2);
  });
});
