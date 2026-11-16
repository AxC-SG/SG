import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/test-utils';
import type { InventoryComponentRecord } from './api-types';
import { InventoryResultsPanel } from './InventoryResultsPanel';

const row = (overrides: Partial<InventoryComponentRecord> = {}): InventoryComponentRecord => ({
  id: 'ic-1', assetId: 'a-1', assetName: 'web-01', assetIdentifier: 'web-01', assetType: 'HOST', componentStatus: 'ACTIVE',
  ecosystem: 'npm', packageName: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', cveCount: 0, impactedCveCount: 0,
  cveIds: [], lastObservedAt: '2026-11-15T00:00:00Z', needsReview: false, reviewItemCount: 0, reviewMissingVersion: false,
  reviewUnmappedSoftware: false, reviewLowConfidenceAlias: false, reviewDiscoveryModel: false, ...overrides
});

function renderPanel(rows: InventoryComponentRecord[]) {
  return renderWithProviders(
    <InventoryResultsPanel selectedView="bom-components" error="" loading={false} rows={rows} componentPage={0} componentTotalPages={1}
      selectedHostAssetId={null} onOpenHostDetail={() => undefined} onPreviousComponentPage={() => undefined}
      onNextComponentPage={() => undefined} />
  );
}

describe('InventoryResultsPanel owner column (Phase 0B §3.7)', () => {
  afterEach(() => localStorage.clear());

  it('shows each component occurrence owner once CLOUD_BOM ownership is canonical', () => {
    renderPanel([
      row({ ownership: { objectId: 'ic-1', authorityDomain: 'CLOUD_BOM', authorityState: 'CANONICAL', ownershipStatus: 'OWNED', ownerTeamName: 'Payments' } }),
      row({ id: 'ic-2', ownership: { objectId: 'ic-2', authorityDomain: 'CLOUD_BOM', authorityState: 'CANONICAL', ownershipStatus: 'UNOWNED' } })
    ]);
    expect(screen.getByRole('columnheader', { name: /Owner/ })).toBeInTheDocument();
    expect(screen.getByText('Payments')).toBeInTheDocument();
    expect(screen.getByText('Unowned')).toBeInTheDocument();
  });

  it('has no owner column before then', () => {
    renderPanel([row()]);
    expect(screen.queryByRole('columnheader', { name: /Owner/ })).not.toBeInTheDocument();
  });
});
