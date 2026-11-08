import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import { submitBomFile } from '../features/connect/manualBomUpload';
import { renderWithProviders } from '../test/test-utils';
import { BomManagementPage } from './BomManagementPage';

vi.mock('../features/connect/manualBomUpload', async (importOriginal) => ({
  ...await importOriginal<typeof import('../features/connect/manualBomUpload')>(),
  durableBomUploadsEnabled: true,
  submitBomFile: vi.fn()
}));

describe('BomManagementPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('queues a file from the existing form and shows its completed result in place', async () => {
    vi.spyOn(api, 'listBomSources').mockResolvedValue([]);
    vi.mocked(submitBomFile).mockResolvedValueOnce('job-1');
    vi.spyOn(api, 'getIngestionJob').mockResolvedValueOnce({
      jobId: 'job-1', jobType: 'BOM_UPLOAD', status: 'SUCCEEDED', sourceType: 'bom-upload',
      assetIdentifier: 'checkout', requestedAt: '2026-11-08T09:10:00Z', requestedBy: 'admin',
      attemptCount: 1, startedAt: '2026-11-08T09:10:01Z', completedAt: '2026-11-08T09:10:02Z',
      resultJson: JSON.stringify({ bomId: 'bom-1', assetId: 'asset-1', bomType: 'SBOM', componentCount: 15 }),
      failureCode: null, failureMessage: null, sbomUploadId: null
    });
    const { container } = renderWithProviders(
      <ActorContextState.Provider value={{
        creator: false, principal: 'admin', userId: 'admin', tenantId: 'tenant-1',
        tenantName: 'Orchard', roles: ['TENANT_ADMIN']
      }}>
        <BomManagementPage includeGithubSources={false} />
      </ActorContextState.Provider>
    );
    const file = new File(['{}'], 'checkout.json');
    fireEvent.change(container.querySelector('input[type="file"]')!, { target: { files: [file] } });
    fireEvent.change(screen.getByLabelText(/Asset Name/), { target: { value: 'Checkout' } });
    fireEvent.change(screen.getByLabelText(/Asset Identifier/), { target: { value: 'checkout' } });
    fireEvent.click(screen.getByRole('button', { name: 'Ingest SBOM' }));

    expect(await screen.findByText('BOM import completed. Results are available below.')).toBeInTheDocument();
    expect(screen.getByText('15')).toBeInTheDocument();
    expect(submitBomFile).toHaveBeenCalledWith(file, expect.objectContaining({
      bomType: 'SBOM', assetIdentifier: 'checkout'
    }), { tenantId: 'tenant-1', userId: 'admin' }, expect.any(Function));
  });

  it('reports a failed saved-pipeline list with retry instead of "no saved pipelines"', async () => {
    vi.spyOn(api, 'listBomSources').mockResolvedValue([]);
    const list = vi.spyOn(api, 'listGithubSbomSources').mockRejectedValueOnce(new Error('offline')).mockResolvedValue([]);

    renderWithProviders(<BomManagementPage title="BOM Management" caption="" includeGithubSources />);

    fireEvent.click(screen.getByRole('button', { name: 'CI/CD & pipelines' }));
    const alert = await screen.findByText(/Saved pipelines could not be loaded\./);
    expect(screen.queryByText(/No saved pipelines yet/)).not.toBeInTheDocument();
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText(/No saved pipelines yet/)).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
  });

  it('separates ingestion, CI/CD pipelines and CBOM governance into their own sections', async () => {
    vi.spyOn(api, 'listBomSources').mockResolvedValue([]);
    vi.spyOn(api, 'listGithubSbomSources').mockResolvedValue([]);
    const rules = vi.spyOn(api, 'getCbomRuleConfiguration').mockRejectedValue(new Error('down'));
    vi.spyOn(api, 'getCbomPqcReadiness').mockResolvedValue({ total: 17, quantumVulnerable: 2, pqcReady: 1, unknown: 3, quantumSafe: 10,
      classicallyWeak: 1, highestPriority: [{ componentId: 'c-1', name: 'Legacy hash', primitive: 'hash', readiness: 'CLASSICALLY_WEAK',
        migrationPriority: 'HIGH', reason: 'SHA-1 is already broken or deprecated today' }] });
    vi.spyOn(api, 'listCbomGatePolicies').mockResolvedValue([]);
    renderWithProviders(<BomManagementPage title="BOM Management" caption="" includeGithubSources />);

    expect(screen.getByRole('heading', { name: 'Ingest Now' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'CI/CD pipeline API' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'CI gate policies' })).not.toBeInTheDocument();

    expect(screen.getByText('BOM Type')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'CI/CD & pipelines' }));
    expect(screen.getByRole('heading', { name: 'CI/CD pipeline API' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'GitHub Auto-Pipeline' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Ingest Now' })).not.toBeInTheDocument();
    expect(screen.queryByText('BOM Type')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'BOM Management' })).not.toBeInTheDocument();
    const sourceType = screen.getByLabelText('Source Type');
    expect(within(sourceType).getByRole('group', { name: 'SBOM' })).toBeInTheDocument();
    expect(within(sourceType).getByRole('option', { name: 'Repository CBOM file scan' })).toBeInTheDocument();
    expect(within(sourceType).getByRole('option', { name: 'Repository AIBOM file scan' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('BOM type your pipeline pushes'), { target: { value: 'CBOM' } });
    expect(screen.getByLabelText('curl snippet')).toHaveTextContent('bomType=CBOM');

    fireEvent.click(screen.getByRole('button', { name: 'CBOM governance' }));
    expect(screen.getByRole('heading', { name: 'Cryptographic Governance' })).toBeInTheDocument();
    expect(await screen.findByText('Quantum-safe')).toBeInTheDocument();
    expect(await screen.findByText('10')).toBeInTheDocument();
    expect(screen.getByText('Classically weak')).toBeInTheDocument();
    expect(screen.getByText(/SHA-1 is already broken or deprecated today/)).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'CI gate policies' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'CBOM rule package' })).toBeInTheDocument();
    expect(screen.queryByText('BOM Type')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'CBOM governance' })).toHaveAttribute('aria-pressed', 'true');
    expect(rules).toHaveBeenCalled();
  });
});
