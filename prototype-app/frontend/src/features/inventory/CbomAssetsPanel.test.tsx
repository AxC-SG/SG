import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, type CbomBomAsset } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { CbomAssetsPanel } from './CbomAssetsPanel';

const ASSET: CbomBomAsset = {
  asset: {
    id: 'c-1', assetId: 'a-1', sourceBomId: 'bom-1', bomRef: 'crypto/algorithm/sha-1', name: 'SHA-1',
    description: null, assetType: 'ALGORITHM', componentType: 'cryptographic-asset', primitive: 'hash',
    keySize: 160, curve: null, padding: null, protocolVersion: null, state: 'active', format: null,
    storageLocation: null, transmission: null, sensitivity: null, usedIn: null, notAfter: null,
    riskScore: 7.5, openFindingCount: 1, highFindingCount: 1, criticalFindingCount: 0,
  },
  findings: [{
    id: 'f-1', componentId: 'c-1', componentName: 'SHA-1', assetId: 'a-1', ruleId: 'weak-hash',
    riskClass: 'WEAK_ALGORITHM', severity: 'HIGH', title: 'SHA-1 is a weak hash', detail: null,
    evidence: null, recommendation: null, status: 'OPEN', firstSeenAt: '2026-11-01T00:00:00Z',
    lastSeenAt: '2026-11-01T00:00:00Z',
  }],
};

describe('CbomAssetsPanel', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lists each asset with its crypto properties and linked findings', async () => {
    const list = vi.spyOn(api, 'listCbomAssetsForBom').mockResolvedValue([ASSET]);
    renderWithProviders(<CbomAssetsPanel bomId="bom-1" />);

    expect(await screen.findByText('SHA-1')).toBeInTheDocument();
    expect(screen.getByText('Cryptographic assets (1)')).toBeInTheDocument();
    expect(screen.getByText('Algorithm')).toBeInTheDocument();
    expect(screen.getByText('hash · 160-bit')).toBeInTheDocument();
    expect(screen.getByText('SHA-1 is a weak hash')).toBeInTheDocument();
    expect(screen.getByText('1 findings linked to these assets')).toBeInTheDocument();
    expect(list).toHaveBeenCalledWith('bom-1');
  });

  it('says so when the CBOM has no active assets', async () => {
    vi.spyOn(api, 'listCbomAssetsForBom').mockResolvedValue([]);
    renderWithProviders(<CbomAssetsPanel bomId="bom-1" />);
    expect(await screen.findByText('This CBOM has no active cryptographic assets.')).toBeInTheDocument();
  });

  it('reports a failed load with retry', async () => {
    const list = vi.spyOn(api, 'listCbomAssetsForBom').mockRejectedValueOnce(new Error('boom')).mockResolvedValue([ASSET]);
    renderWithProviders(<CbomAssetsPanel bomId="bom-1" />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Cryptographic assets could not be loaded.');
    fireEvent.click(screen.getByRole('button', { name: 'Retry cryptographic assets' }));
    expect(await screen.findByText('SHA-1')).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
  });
});
