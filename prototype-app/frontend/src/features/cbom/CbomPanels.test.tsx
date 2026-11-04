import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, type CbomAssessment } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { CbomDiffPanel } from './CbomDiffPanel';
import { CbomInventoryPanel } from './CbomInventoryPanel';
import { CbomOverviewPanel } from './CbomOverviewPanel';
import { CbomReportsPanel } from './CbomReportsPanel';
import type { CbomComponentDetail, CbomInventoryPage, CbomOverview, CbomReport, CbomSemanticDiff } from './types';

const OVERVIEW: CbomOverview = {
  observedAt: '2026-11-03T00:00:00Z',
  risk: { openCritical: 2, openHigh: 5, openMedium: 1, openLow: 0, averagePostureScore: 6.5, assetsWithCriticalOrHigh: 3, productionAssetsWithCriticalOrHigh: 1 },
  assurance: { activeArtifacts: 4, assessedArtifacts: 3, assessmentCoverage: 0.75, averageConfidence: 0.9, averageCompleteness: null, claimsByAssurance: { DECLARED: 12, UNKNOWN: 2 } },
  remediation: { open: 7, overdue: 2, slaCompliance: null, suppressed: 1, suppressionsExpiringIn30Days: 1, resolvedLast30Days: 4 },
  rotation: { expired: 1, expiringIn30Days: 2, expiringIn60Days: 3, expiringIn90Days: 4 },
  pqc: { quantumVulnerableFindings: 6, quantumVulnerableComponents: 5 },
  productionAssetsAtRisk: [{ assetId: 'a-1', name: 'checkout', environment: 'production', critical: 2, high: 1 }],
  componentsByType: { ALGORITHM: 10, CERTIFICATE: 2 },
  cryptoExposureNote: 'CRYPTO findings do not change Exposure CVE counts.',
};

const ITEM = {
  id: 'c-1', name: 'RSA signer', assetType: 'ALGORITHM', primitive: 'rsa', keySize: 1024, curve: null, protocolVersion: null,
  storageLocation: 'hsm', notAfter: null, riskScore: 8.2, assetId: 'a-1', assetName: 'checkout', environment: 'production',
  sourceBomId: 'bom-1', sourceDocument: 'checkout.cdx.json', openFindings: 1, highestSeverity: 'HIGH', evidenceState: 'SUPPORTED',
};

const PAGE: CbomInventoryPage = { items: [ITEM], page: 0, size: 50, total: 1, totalCapped: false, hasNext: false };

const DETAIL: CbomComponentDetail = {
  component: ITEM,
  properties: { bomRef: 'crypto/rsa' },
  provenance: {
    bomId: 'bom-1', documentName: 'checkout.cdx.json', serialNumber: 'urn:uuid:1', checksumSha256: 'abc', sourceType: 'API',
    sourceMethod: 'PUSH', sourceLabel: null, bomStatus: 'ACTIVE', ingestedAt: '2026-11-01T00:00:00Z', assessmentRunId: 'run-1',
    rulePackage: 'scoutgrid-baseline@1.0.0', rulePackageDigest: 'sha256:x', evaluatorVersion: '1.0', assessedAt: '2026-11-01T00:01:00Z',
  },
  claims: [{ claimPath: '/cryptoProperties/0/primitive', assuranceLevel: 'DECLARED', evidenceState: 'SUPPORTED', explanation: 'Cryptographic primitive is declared.' }],
  findings: [{
    id: 'f-1', ruleId: 'CBOM-RSA-SMALL-KEY', ruleVersion: '1', severity: 'HIGH', riskClass: 'KEY_MANAGEMENT', title: 'RSA key size below 2048 bits',
    detail: 'Below baseline.', evidence: null, recommendation: 'Rotate to RSA-3072.', status: 'OPEN', evidenceState: 'SUPPORTED',
    firstSeenAt: null, lastSeenAt: null,
    canonical: { id: 'cf-1', displayId: 'F-42', status: 'OPEN', assignedTo: 'alice', dueAt: null, suppressedUntil: null },
  }],
  relationships: [{ direction: 'OUTBOUND', relationshipType: 'DEPENDS_ON', otherType: 'COMPONENT', otherId: 'c-2', otherName: 'SHA-256', evidenceKind: 'DECLARED' }],
};

const DIFF: CbomSemanticDiff = {
  bomId: 'bom-2', baselineBomId: 'bom-1', baselineSource: 'PREDECESSOR', currentStatus: 'ACTIVE',
  componentSummary: { CHANGED: 1, NOT_OBSERVED: 1 },
  findingSummary: { REMEDIATED: 1, NOT_OBSERVED: 1, ACCEPTED_RISK: 1 },
  componentChanges: [{ changeType: 'CHANGED', identity: 'bom-ref:rsa', name: 'RSA signer', assetType: 'ALGORITHM', baselineComponentId: 'c-0',
    currentComponentId: 'c-1', fields: [{ field: 'keySize', category: 'ALGORITHM', before: '1024', after: '3072' }], riskBefore: 8, riskAfter: 2 }],
  assuranceChanges: [],
  findingOutcomes: [{ outcome: 'REMEDIATED', identity: 'bom-ref:rsa', componentName: 'RSA signer', ruleId: 'CBOM-RSA-SMALL-KEY',
    title: 'RSA key size below 2048 bits', severityBefore: 'HIGH', severityAfter: null, baselineFindingId: 'f-0', currentFindingId: null, canonicalStatus: null }],
  ambiguous: [{ identity: 'natural:x', baselineMatches: 2, currentMatches: 1 }],
  posture: { openBefore: 3, openAfter: 1, riskBefore: 10, riskAfter: 4 },
};

const RUN = { id: 'run-1', bomId: 'bom-1', status: 'SUCCEEDED' } as CbomAssessment;
const READY: CbomReport = {
  id: 'r-1', bomId: 'bom-1', assessmentRunId: 'run-1', format: 'HTML', status: 'READY', regeneratedFrom: null, requestedBy: 'alice',
  schemaVersion: '1.1', checksumSha256: 'f'.repeat(64), filename: 'cbom.html', sizeBytes: 100, errorMessage: null,
  createdAt: '2026-11-02T00:00:00Z', completedAt: '2026-11-02T00:00:01Z', expiresAt: '2027-01-31T00:00:00Z', downloadCount: 0,
  lastDownloadedAt: null, signatureStatus: 'UNSIGNED',
};

async function expectNoAxeViolations(container: HTMLElement) {
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  expect(result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(' ')).join(', ')}`)).toEqual([]);
}

describe('CBOM visibility panels', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('shows the executive overview with unavailable ratios instead of invented zeros', async () => {
    vi.spyOn(api, 'getCbomOverview').mockResolvedValue(OVERVIEW);
    vi.spyOn(api, 'getCbomTrends').mockResolvedValue({ days: 90, points: [] });
    const { container } = renderWithProviders(<CbomOverviewPanel />);

    expect(await screen.findByText('Production assets at risk')).toBeInTheDocument();
    expect(screen.getByText('75%')).toBeInTheDocument();
    expect(screen.getByText('checkout')).toBeInTheDocument();
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    expect(screen.getByText(/do not change Exposure CVE counts/)).toBeInTheDocument();
    expect(await screen.findByText(/Daily posture snapshots start after the first nightly run/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('filters the inventory server-side and opens the evidence drawer with provenance and the canonical finding', async () => {
    const list = vi.spyOn(api, 'listCbomInventory').mockResolvedValue(PAGE);
    vi.spyOn(api, 'getCbomComponentDetail').mockResolvedValue(DETAIL);
    const { container } = renderWithProviders(<CbomInventoryPanel />);

    expect(await screen.findByRole('button', { name: 'Open evidence for RSA signer' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
    fireEvent.change(screen.getByLabelText('Asset type'), { target: { value: 'ALGORITHM' } });
    fireEvent.change(screen.getByLabelText('Open finding severity'), { target: { value: 'HIGH' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ assetType: 'ALGORITHM', severity: 'HIGH' }, 0, 50));

    fireEvent.click(screen.getByRole('button', { name: 'Open evidence for RSA signer' }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText('scoutgrid-baseline@1.0.0')).toBeInTheDocument();
    expect(within(dialog).getByText('Assurance: Declared')).toBeInTheDocument();
    expect(within(dialog).getAllByText('Evidence: Supported').length).toBeGreaterThan(0);
    expect(within(dialog).getByRole('link', { name: 'F-42' })).toHaveAttribute('href', '/findings/cf-1');
    expect(within(dialog).getByText(/Rotate to RSA-3072/)).toBeInTheDocument();
  });

  it('says when filters match nothing and offers to clear them', async () => {
    vi.spyOn(api, 'listCbomInventory').mockResolvedValue({ ...PAGE, items: [], total: 0 });
    renderWithProviders(<CbomInventoryPanel initialFilters={{ assetType: 'CERTIFICATE' }} />);
    expect(await screen.findByText('No cryptographic assets match these filters.')).toBeInTheDocument();
  });

  it('keeps remediation, omission and accepted risk distinct in the semantic diff', async () => {
    vi.spyOn(api, 'getCbomSemanticDiff').mockResolvedValue(DIFF);
    const { container } = renderWithProviders(<CbomDiffPanel bomId="bom-2" />);

    expect(await screen.findByText('Remediated: 1')).toBeInTheDocument();
    expect(screen.getByText('Not observed: 1')).toBeInTheDocument();
    expect(screen.getByText('Accepted risk: 1')).toBeInTheDocument();
    expect(screen.getByText(/this is not proof of remediation/)).toBeInTheDocument();
    expect(screen.getByText('keySize: 1024 → 3072')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('their changes are not guessed');
    await expectNoAxeViolations(container);
  });

  it('explains that a first version has nothing to compare', async () => {
    vi.spyOn(api, 'getCbomSemanticDiff').mockResolvedValue({ ...DIFF, baselineBomId: null, baselineSource: 'NONE' });
    renderWithProviders(<CbomDiffPanel bomId="bom-1" />);
    expect(await screen.findByText(/first version of this CBOM/)).toBeInTheDocument();
  });

  it('requests reports with an idempotency key, labels them unsigned and downloads ready ones', async () => {
    vi.spyOn(api, 'listCbomAssessments').mockResolvedValue([RUN]);
    vi.spyOn(api, 'listCbomReports').mockResolvedValue([READY]);
    const request = vi.spyOn(api, 'requestCbomReport').mockResolvedValue({ ...READY, id: 'r-2', status: 'QUEUED' });
    const download = vi.spyOn(api, 'downloadCbomReport').mockResolvedValue({ filename: 'cbom.html', blob: new Blob(['x']), checksum: 'f'.repeat(64) });
    const createUrl = vi.fn(() => 'blob:report');
    Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: vi.fn() });
    const { container } = renderWithProviders(<CbomReportsPanel bomId="bom-1" />);

    expect(await screen.findByText(/Unsigned report — checksum verifies content consistency, not authenticity/)).toBeInTheDocument();
    expect(await screen.findByText('f'.repeat(64))).toBeInTheDocument();
    await expectNoAxeViolations(container);

    fireEvent.click(screen.getByRole('button', { name: 'Generate HTML report' }));
    await waitFor(() => expect(request).toHaveBeenCalledWith('bom-1', 'run-1', 'HTML', expect.stringMatching(/^report-/)));
    expect(await screen.findByRole('status')).toHaveTextContent('HTML report requested.');

    fireEvent.click(screen.getByRole('button', { name: /^Download HTML report/ }));
    await waitFor(() => expect(download).toHaveBeenCalledWith('bom-1', 'r-1'));
    expect(createUrl).toHaveBeenCalled();
  });

  it('disables report generation until a successful assessment exists and surfaces failures', async () => {
    vi.spyOn(api, 'listCbomAssessments').mockResolvedValue([]);
    vi.spyOn(api, 'listCbomReports').mockRejectedValue(new Error('boom'));
    renderWithProviders(<CbomReportsPanel bomId="bom-1" />);
    expect(await screen.findByText('Reports need a successful assessment of this CBOM.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Generate HTML report' })).toBeDisabled();
    expect(await screen.findByText('Reports could not be loaded.')).toBeInTheDocument();
  });
});
