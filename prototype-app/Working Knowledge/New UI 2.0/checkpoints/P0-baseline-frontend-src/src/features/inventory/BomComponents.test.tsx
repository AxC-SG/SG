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
});
