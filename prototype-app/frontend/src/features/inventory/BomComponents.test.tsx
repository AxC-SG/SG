import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, type BomComponentSummaryItem } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { BomComponents } from './BomComponents';

function buildComponent(overrides: Partial<BomComponentSummaryItem> = {}): BomComponentSummaryItem {
  return {
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
    criticalCveCount: 0,
    highCveCount: 0,
    mediumCveCount: 0,
    lowCveCount: 0,
    totalCveCount: 0,
    correlationState: 'UNCHECKED',
    riskLevel: 'NONE',
    findingCount: 0,
    criticalFindingCount: 0,
    highFindingCount: 0,
    ...overrides,
  };
}

describe('BomComponents', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('regression: a widget card click clears a stale ecosystem facet filter instead of being silently intersected with it', async () => {
    // Regression coverage: clicking a top KPI card only set `widgetFilter`, leaving
    // `ecosystemFilter` (set independently via the Ecosystem Breakdown panel) active. Once an
    // ecosystem facet was selected, every subsequent widget-card click got silently AND-ed with
    // it, so the table never changed and the cards appeared unresponsive ("not opening the list").
    vi.spyOn(api, 'listBomComponents').mockResolvedValue([
      buildComponent({ componentId: 'comp-1', packageName: 'left-pad', ecosystem: 'npm', bomTypes: ['SBOM'] }),
      buildComponent({ componentId: 'comp-2', packageName: 'gpt-4.1-mini', ecosystem: 'generic', bomTypes: ['AI_BOM'] }),
    ]);

    renderWithProviders(<BomComponents />);
    await screen.findByText('left-pad');

    // Select the GENERIC ecosystem facet — narrows the table to the one generic/AI_BOM row.
    // (Text content is lowercase "generic"; uppercase display is CSS text-transform only.
    // Scope to the Ecosystem Breakdown panel since "generic" also appears as a table cell pill.)
    const ecosystemPanel = (await screen.findByText('Ecosystem Breakdown')).closest('.panel') as HTMLElement;
    fireEvent.click(within(ecosystemPanel).getByText('generic'));
    await waitFor(() => {
      expect(screen.queryByText('left-pad')).not.toBeInTheDocument();
      expect(screen.getByText('gpt-4.1-mini')).toBeInTheDocument();
    });

    // Clicking "Inventory Components" must clear the stale ecosystem facet and show everything.
    const inventoryLabel = await screen.findByText('Inventory Components');
    fireEvent.click(inventoryLabel.closest('.panel') as HTMLElement);
    await waitFor(() => {
      expect(screen.getByText('left-pad')).toBeInTheDocument();
      expect(screen.getByText('gpt-4.1-mini')).toBeInTheDocument();
    });
  });

  it('the Licenses card is clickable and resets to the full unfiltered list', async () => {
    vi.spyOn(api, 'listBomComponents').mockResolvedValue([
      buildComponent({ componentId: 'comp-1', packageName: 'left-pad', totalCveCount: 2, criticalCveCount: 1 }),
      buildComponent({ componentId: 'comp-2', packageName: 'right-pad' }),
    ]);

    renderWithProviders(<BomComponents />);
    await screen.findByText('left-pad');

    const vulnerableCard = (await screen.findByText('Vulnerable')).closest('.panel') as HTMLElement;
    fireEvent.click(vulnerableCard);
    await waitFor(() => {
      expect(screen.queryByText('right-pad')).not.toBeInTheDocument();
    });

    const licensesCard = (await screen.findByText('Licenses')).closest('.panel') as HTMLElement;
    expect(licensesCard).toHaveStyle({ cursor: 'pointer' });
    fireEvent.click(licensesCard);

    await waitFor(() => {
      expect(screen.getByText('left-pad')).toBeInTheDocument();
      expect(screen.getByText('right-pad')).toBeInTheDocument();
    });
  });

  it('renders the Findings column as critical/high/other severity chips', async () => {
    vi.spyOn(api, 'listBomComponents').mockResolvedValue([
      buildComponent({
        componentId: 'comp-1',
        packageName: 'left-pad',
        findingCount: 4,
        criticalFindingCount: 1,
        highFindingCount: 2,
      }),
    ]);

    renderWithProviders(<BomComponents />);
    const row = (await screen.findByText('left-pad')).closest('tr') as HTMLElement;

    // other = findingCount(4) - critical(1) - high(2) = 1
    expect(within(row).getByTitle('Critical')).toHaveTextContent('1');
    expect(within(row).getByTitle('High')).toHaveTextContent('2');
    expect(within(row).getByTitle('Medium / Low')).toHaveTextContent('1');
  });

  it('still allows the Vulnerable card to filter the table', async () => {
    vi.spyOn(api, 'listBomComponents').mockResolvedValue([
      buildComponent({ componentId: 'comp-1', packageName: 'left-pad', totalCveCount: 0 }),
      buildComponent({ componentId: 'comp-2', packageName: 'right-pad', totalCveCount: 2, criticalCveCount: 1 }),
    ]);

    renderWithProviders(<BomComponents />);

    await screen.findByText('left-pad');

    const vulnerableLabel = await screen.findByText('Vulnerable');
    const vulnerableCard = vulnerableLabel.closest('.panel') as HTMLElement;
    fireEvent.click(vulnerableCard);

    await waitFor(() => {
      expect(screen.queryByText('left-pad')).not.toBeInTheDocument();
      expect(screen.getByText('right-pad')).toBeInTheDocument();
    });
  });

  it('lists CBOM cryptographic assets under Crypto Libraries and opens the CBOM component page for them', async () => {
    const detail = vi.spyOn(api, 'getBomComponentDetail');
    const cbomDetail = vi.spyOn(api, 'getCbomComponentDetail').mockResolvedValue({
      component: {
        id: 'crypto-1', name: 'AES-GCM', assetType: 'ALGORITHM', primitive: 'ae', keySize: 256, curve: null, protocolVersion: null,
        storageLocation: 'kms', notAfter: null, riskScore: 1.5, assetId: 'a-1', assetName: 'checkout', environment: 'production',
        sourceBomId: 'bom-1', sourceDocument: 'checkout.cdx.json', openFindings: 1, highestSeverity: 'MEDIUM', evidenceState: 'SUPPORTED',
      },
      properties: { bomRef: 'crypto/algorithm/aes-256-gcm', componentFingerprint: 'fp-1', parameterSetIdentifier: '256', active: true,
        createdAt: '2026-11-01T00:00:00Z', updatedAt: '2026-11-02T00:00:00Z' },
      provenance: { bomId: 'bom-1', documentName: 'checkout.cdx.json', serialNumber: 'urn:uuid:1', checksumSha256: 'abc', sourceType: 'API',
        sourceMethod: 'PUSH', sourceLabel: null, bomStatus: 'ACTIVE', ingestedAt: '2026-11-01T00:00:00Z', assessmentRunId: 'run-1',
        rulePackage: 'scoutgrid-baseline@1.0.0', rulePackageDigest: 'sha256:x', evaluatorVersion: '1.0', assessedAt: '2026-11-01T00:01:00Z' },
      claims: [{ claimPath: '/cryptoProperties/0/primitive', assuranceLevel: 'DECLARED', evidenceState: 'SUPPORTED', explanation: 'Primitive is declared.' }],
      findings: [{ id: 'f-1', ruleId: 'CBOM-QUANTUM-VULNERABLE', ruleVersion: '1', severity: 'MEDIUM', riskClass: 'QUANTUM_VULNERABLE',
        title: 'Quantum-vulnerable algorithm', detail: 'Plan migration.', evidence: null, recommendation: 'Adopt ML-KEM.', status: 'OPEN',
        evidenceState: 'SUPPORTED', firstSeenAt: null, lastSeenAt: '2026-11-02T00:00:00Z',
        canonical: { id: 'cf-1', displayId: 'F-7', status: 'OPEN', assignedTo: null, dueAt: null, suppressedUntil: null } }],
      relationships: [{ direction: 'INBOUND', relationshipType: 'USES_ALGORITHM', otherType: 'COMPONENT', otherId: 'c-2', otherName: 'Credential key', evidenceKind: 'DECLARED' }],
    });
    vi.spyOn(api, 'getCbomBlastRadius').mockResolvedValue({ componentId: 'crypto-1', graph: { nodes: [], edges: [], truncated: false, depth: 3 },
      applications: [], affectedComponents: 1, openFindings: 0, openFindingsBySeverity: {} });
    vi.spyOn(api, 'listBomComponents').mockResolvedValue([
      buildComponent({ componentId: 'crypto-1', packageName: 'AES-GCM', version: null, purl: null, ecosystem: 'crypto', bomTypes: ['CBOM'], bomEvidenceState: null, correlationState: 'UNCHECKED' }),
      buildComponent({ componentId: 'comp-1', packageName: 'left-pad' }),
    ]);

    renderWithProviders(<BomComponents />);
    const cell = await screen.findByText('AES-GCM');
    const cryptoCard = screen.getByText('Crypto Libraries').closest('.panel') as HTMLElement;
    expect(within(cryptoCard).getByText('1')).toBeInTheDocument();

    fireEvent.click(cell);
    expect(detail).not.toHaveBeenCalled();
    expect(await screen.findByRole('heading', { name: 'AES-GCM' })).toBeInTheDocument();
    expect(cbomDetail).toHaveBeenCalledWith('crypto-1');
    expect(screen.getByText('crypto/algorithm/aes-256-gcm', { selector: '.mono.cbom-wrap' })).toBeInTheDocument();
    expect(screen.getByText('256 bits')).toBeInTheDocument();
    expect(screen.getByText('kms')).toBeInTheDocument();
    expect(screen.getByText('checkout.cdx.json')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: 'Findings (1)' }));
    expect(screen.getByRole('tab', { name: 'Findings (1)' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByText('Quantum-vulnerable algorithm')).toBeInTheDocument();
    expect(screen.getByText('Adopt ML-KEM.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'F-7' })).toHaveAttribute('href', '/findings/cf-1');

    fireEvent.click(screen.getByRole('tab', { name: 'Evidence & claims (1)' }));
    expect(screen.getByText('scoutgrid-baseline@1.0.0')).toBeInTheDocument();
    expect(screen.getByText('Assurance: Declared')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: 'Relationships (1)' }));
    expect(screen.getByRole('link', { name: 'Credential key' }))
      .toHaveAttribute('href', '/inventory/bom-components/cbom/c-2?returnTo=%2F');

    fireEvent.click(screen.getByRole('button', { name: '← Back to BOM Components' }));
    expect(await screen.findByText('left-pad')).toBeInTheDocument();
  });

  it('reports a failed component load with retry', async () => {
    const list = vi.spyOn(api, 'listBomComponents')
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValue([buildComponent()]);

    renderWithProviders(<BomComponents />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load BOM components.');
    fireEvent.click(screen.getByRole('button', { name: 'Retry BOM components' }));
    expect(await screen.findByText('left-pad')).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
  });

  it('regression: changing a toolbar filter returns to the first page instead of leaving an empty out-of-range page', async () => {
    // 101 rows span two pages (PAGE_SIZE 100). Moving to page 2 and then narrowing with the search
    // box used to keep page 2, so a one-row result rendered an empty table.
    const rows = Array.from({ length: 101 }, (_, i) =>
      buildComponent({ componentId: `comp-${i}`, packageName: i === 0 ? 'needle' : `pkg-${String(i).padStart(3, '0')}` }));
    vi.spyOn(api, 'listBomComponents').mockResolvedValue(rows);

    renderWithProviders(<BomComponents />);
    await screen.findByText('needle');

    fireEvent.click(screen.getByRole('button', { name: /Next/ }));
    await screen.findByText('Page 2 of 2');

    fireEvent.change(screen.getByPlaceholderText('Filter component name…'), { target: { value: 'needle' } });

    expect(await screen.findByText('needle')).toBeInTheDocument();
    expect(screen.getByText(/Showing 1–1 of 1 components/)).toBeInTheDocument();
  });

  it('shows each row\'s own application and how many other applications carry the same package', async () => {
    vi.spyOn(api, 'listBomComponents').mockResolvedValue([
      buildComponent({ componentId: 'comp-1', assetId: 'asset-1', assetName: 'kanra-mobile' }),
      buildComponent({ componentId: 'comp-2', assetId: 'asset-2', assetName: 'billing-api' }),
      buildComponent({ componentId: 'comp-3', assetId: 'asset-3', assetName: 'solo-app', packageName: 'right-pad', version: '2.0.0' }),
    ]);

    renderWithProviders(<BomComponents />);
    const rows = await screen.findAllByText('left-pad');
    const first = rows[0].closest('tr') as HTMLElement;
    expect(within(first).getByText('kanra-mobile')).toBeInTheDocument();
    expect(within(first).getByText('+1 other application')).toBeInTheDocument();

    const solo = (await screen.findByText('right-pad')).closest('tr') as HTMLElement;
    expect(within(solo).getByText('solo-app')).toBeInTheDocument();
    expect(within(solo).queryByText(/other application/)).not.toBeInTheDocument();
  });
});
