import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { CbomBlastRadius } from './CbomBlastRadius';
import { CbomContradictionsPanel } from './CbomContradictionsPanel';
import type { CbomBlastRadius as BlastRadius, CbomContradiction } from './types';

const RADIUS: BlastRadius = {
  componentId: 'c-aes',
  graph: {
    depth: 3, truncated: false,
    nodes: [
      { type: 'COMPONENT', id: 'c-aes', distance: 0, label: 'AES-GCM', kind: 'ALGORITHM', openFindings: 0, highestSeverity: null },
      { type: 'COMPONENT', id: 'c-key', distance: 1, label: 'Credential key', kind: 'RELATED_CRYPTO_MATERIAL', openFindings: 2, highestSeverity: 'HIGH' },
      { type: 'ASSET', id: 'a-1', distance: 2, label: 'checkout', kind: 'APPLICATION', openFindings: 0, highestSeverity: null },
    ],
    edges: [
      { id: 'e-1', sourceType: 'COMPONENT', sourceId: 'c-key', targetType: 'COMPONENT', targetId: 'c-aes', relationshipType: 'USES_ALGORITHM',
        evidenceKind: 'DECLARED', confidence: null, evidenceSummary: null, validUntil: null, stale: false },
      { id: 'e-2', sourceType: 'ASSET', sourceId: 'a-1', targetType: 'COMPONENT', targetId: 'c-key', relationshipType: 'APPLICATION_USES',
        evidenceKind: 'DECLARED', confidence: null, evidenceSummary: null, validUntil: '2026-01-01T00:00:00Z', stale: true },
    ],
  },
  applications: [{ assetId: 'a-1', name: 'checkout', environment: 'production', distance: 2 }],
  affectedComponents: 2, openFindings: 2, openFindingsBySeverity: { HIGH: 2 },
};

const CONTRADICTION: CbomContradiction = {
  id: 'x-1', assetId: 'a-1', assetName: 'checkout', identity: 'bom-ref:crypto/aes', claim: 'primitive', componentAId: 'c-a',
  documentA: 'ci.cdx.json', valueA: 'ae', componentBId: 'c-b', documentB: 'scan.cdx.json', valueB: 'des', status: 'OPEN',
  detectedAt: '2026-11-03T00:00:00Z', reviewedBy: null, reviewedAt: null, reviewNote: null, version: 3,
};

describe('CBOM relationship panels', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('summarises the blast radius in text alongside the graph, including stale evidence', async () => {
    vi.spyOn(api, 'getCbomBlastRadius').mockResolvedValue(RADIUS);
    const { container } = renderWithProviders(<CbomBlastRadius componentId="c-aes" />);
    expect(await screen.findByText(/reaches 1 application and 2 cryptographic assets with 2 open findings \(High 2\)/)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /3 nodes and 2 relationships/ })).toBeInTheDocument();
    expect(screen.getByText('checkout (production) · 2 hops')).toBeInTheDocument();
    const keyLinks = screen.getAllByRole('link', { name: 'Credential key' });
    expect(keyLinks).toHaveLength(2);
    keyLinks.forEach((link) => expect(link).toHaveAttribute('href', '/inventory/bom-components/cbom/c-key'));
    expect(screen.queryByRole('link', { name: 'AES-GCM' })).not.toBeInTheDocument();
    expect(screen.getByText(/\(stale evidence\)/)).toBeInTheDocument();
    const audit = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(audit.violations.map((v) => v.id)).toEqual([]);
  });

  it('reviews a contradiction with the loaded version and keeps the dialog open on failure', async () => {
    vi.spyOn(api, 'listCbomContradictions').mockResolvedValue([CONTRADICTION]);
    const review = vi.spyOn(api, 'reviewCbomContradiction').mockRejectedValueOnce(new Error('Reload and review again'))
      .mockResolvedValue({ ...CONTRADICTION, status: 'ACCEPTED_B' });
    renderWithProviders(<CbomContradictionsPanel canReview />);

    fireEvent.click(await screen.findByRole('button', { name: 'Review primitive contradiction for bom-ref:crypto/aes' }));
    const dialog = screen.getByRole('dialog', { name: 'Review contradictory evidence' });
    fireEvent.click(within(dialog).getByLabelText(/des \(scan.cdx.json\)/));
    expect(within(dialog).getByRole('button', { name: 'Save review' })).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('Evidence for the decision'), { target: { value: 'Scanner saw DES in prod' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save review' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Reload and review again');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save review' }));
    await waitFor(() => expect(review).toHaveBeenLastCalledWith('x-1', { decision: 'ACCEPTED_B', note: 'Scanner saw DES in prod', version: 3 }));
  });

  it('stays hidden with no open contradictions and is read-only without review rights', async () => {
    const list = vi.spyOn(api, 'listCbomContradictions').mockResolvedValueOnce([]);
    const { container, unmount } = renderWithProviders(<CbomContradictionsPanel canReview />);
    await waitFor(() => expect(list).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
    unmount();
    list.mockResolvedValueOnce([CONTRADICTION]);
    renderWithProviders(<CbomContradictionsPanel canReview={false} />);
    expect(await screen.findByText('Contradictory evidence (1)')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Review/ })).not.toBeInTheDocument();
  });
});
