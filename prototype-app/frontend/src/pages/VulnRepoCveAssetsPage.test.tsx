import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { CveDetail } from '../features/cve-workbench/types';
import { renderWithProviders } from '../test/test-utils';
import { VulnRepoCveAssetsPage } from './VulnRepoCveAssetsPage';

const CVE_ID = 'CVE-2024-1234';
const PAGE_PATH = `/vuln-repo/org-cves/${CVE_ID}/assets`;
const EMPTY_FINDINGS_PAGE = { items: [], page: 0, size: 1000, totalItems: 0, totalPages: 0 };

function buildCveDetail(overrides: Partial<CveDetail> = {}): CveDetail {
  return {
    summary: {
      externalId: CVE_ID,
      title: 'Test CVE',
      description: 'A test vulnerability',
      severity: 'HIGH',
    },
    signals: {
      exploitAvailable: false,
      exploitReason: '',
      systemsImpacted: false,
      componentCount: 0,
      softwareCount: 0,
      assetCount: 0,
      patchAvailable: false,
    },
    investigations: [],
    assessments: [],
    matchedSoftware: [],
    vendorIntelligence: [],
    ...overrides,
  };
}

function renderPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/vuln-repo/org-cves/:cveId/assets" element={<VulnRepoCveAssetsPage />} />
    </Routes>,
    { initialEntries: [PAGE_PATH] }
  );
}

async function openFindingConfig() {
  vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
    matchedSoftware: [{ componentId: 'cmp-1', assetId: 'asset-1', assetName: 'web-prod-01', assetIdentifier: 'web-prod-01.example.com',
      assetType: 'HOST', ecosystem: 'npm', packageName: 'lodash', version: '4.17.15', applicabilityState: 'APPLICABLE',
      computedImpactState: 'IMPACTED', impactState: 'IMPACTED', eligibleForFinding: true, supportGroup: 'Platform Team' }],
  }));
  vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
  renderPage();
  await screen.findByText('web-prod-01');
  fireEvent.click(screen.getAllByRole('checkbox')[0]);
  fireEvent.click(screen.getByRole('button', { name: /^Create Findings$/ }));
}

describe('VulnRepoCveAssetsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('creates findings with the chosen severity, due date and metadata', async () => {
    const create = vi.spyOn(cveWorkbenchApi, 'createManualFindings').mockResolvedValue({ cveId: CVE_ID, eligibleComponentCount: 1, createdCount: 1, reopenedCount: 0, alreadyOpenCount: 0, message: 'Created' });
    const ticket = vi.spyOn(cveWorkbenchApi, 'createServiceNowIncident');
    await openFindingConfig();
    fireEvent.change(screen.getByLabelText('Finding severity'), { target: { value: 'Critical' } });
    fireEvent.change(screen.getByLabelText('Finding due date'), { target: { value: '2026-11-01' } });
    fireEvent.change(screen.getByLabelText('Finding tags'), { target: { value: 'patch-now' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create Findings (1)' }));
    expect(await screen.findByText('Created 1 finding(s).')).toBeVisible();
    expect(create).toHaveBeenCalledWith(CVE_ID, expect.objectContaining({ componentIds: ['cmp-1'], severity: 'CRITICAL', dueDate: '2026-11-01', justification: expect.stringContaining('Tags: patch-now') }));
    expect(ticket).not.toHaveBeenCalled();
  });

  it('creates the requested ServiceNow ticket and keeps finding success visible if ticketing fails', async () => {
    vi.spyOn(cveWorkbenchApi, 'createManualFindings').mockResolvedValue({ cveId: CVE_ID, eligibleComponentCount: 1, createdCount: 1, reopenedCount: 0, alreadyOpenCount: 0, message: 'Created' });
    const ticket = vi.spyOn(cveWorkbenchApi, 'createServiceNowIncident').mockRejectedValue(new Error('ServiceNow is not configured'));
    await openFindingConfig();
    fireEvent.change(screen.getByLabelText('Finding ownership'), { target: { value: 'Assign by support group' } });
    fireEvent.click(screen.getByLabelText('Create tickets in ServiceNow'));
    fireEvent.click(screen.getByRole('button', { name: 'Create Findings (1)' }));
    expect(await screen.findByText(/Created 1 finding\(s\).*ServiceNow ticket failed: ServiceNow is not configured/)).toBeVisible();
    expect(ticket).toHaveBeenCalledWith(CVE_ID, expect.objectContaining({ affectedAssets: [expect.objectContaining({ componentId: 'cmp-1', assignmentGroup: 'Platform Team' })] }));
  });

  it('preserves a grouped creation error instead of silently creating a different finding type', async () => {
    const create = vi.spyOn(cveWorkbenchApi, 'createManualFindings').mockRejectedValue(new Error('Grouped finding unavailable'));
    await openFindingConfig();
    fireEvent.click(screen.getByRole('radio', { name: /CVE \+ Fix/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Create Findings (1)' }));
    expect(await screen.findByText('Failed to create findings: Grouped finding unavailable')).toBeVisible();
    expect(create).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenCalledWith(CVE_ID, expect.objectContaining({ findingCreationMode: 'CVE_FIX' }));
  });

  it('shows loading state while data is fetching', () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'listFindings').mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByText('Loading affected entities...')).toBeInTheDocument();
  });

  it('shows error message when the query fails', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockRejectedValue(new Error('Server error'));
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() => expect(screen.getByText('Server error')).toBeInTheDocument());
  });

  it('shows empty state when no assets are matched', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail());
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText('No affected entities were found for this CVE.')).toBeInTheDocument()
    );
  });

  it('renders an asset row when matchedSoftware contains an entry with an assetId', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
          assetId: 'asset-1',
          assetName: 'web-prod-01',
          assetIdentifier: 'web-prod-01.example.com',
          assetType: 'HOST',
          ecosystem: 'npm',
          packageName: 'lodash',
          version: '4.17.15',
          applicabilityState: 'APPLICABLE',
          computedImpactState: 'IMPACTED',
          impactState: 'IMPACTED',
          eligibleForFinding: true,
        },
      ],
    }));
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());
  });

  it('disables Create Findings when no asset rows are selected', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
          assetId: 'asset-1',
          assetName: 'web-prod-01',
          assetIdentifier: 'web-prod-01.example.com',
          assetType: 'HOST',
          ecosystem: 'npm',
          packageName: 'lodash',
          version: '4.17.15',
          applicabilityState: 'APPLICABLE',
          computedImpactState: 'IMPACTED',
          impactState: 'IMPACTED',
          eligibleForFinding: true,
        },
      ],
    }));
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /create findings/i })).toBeDisabled();
  });

  it('renders the Back to CVE button', () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'listFindings').mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByRole('button', { name: /back to cve/i })).toBeInTheDocument();
  });

  it('shows the ASSET / CI column header when table data is loaded', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
          assetId: 'asset-1',
          assetName: 'web-prod-01',
          assetIdentifier: 'web-prod-01.example.com',
          assetType: 'HOST',
          ecosystem: 'npm',
          packageName: 'lodash',
          version: '4.17.15',
          applicabilityState: 'APPLICABLE',
          computedImpactState: 'IMPACTED',
          impactState: 'IMPACTED',
          eligibleForFinding: true,
        },
      ],
    }));
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() => expect(screen.getByText('ASSET / CI')).toBeInTheDocument());
  });
});
