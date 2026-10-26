import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { CveDetail } from '../features/cve-workbench/types';
import { renderWithProviders } from '../test/test-utils';
import { VulnRepoCveSoftwarePage } from './VulnRepoCveSoftwarePage';

const CVE_ID = 'CVE-2024-1234';
const PAGE_PATH = `/vuln-repo/org-cves/${CVE_ID}/software`;

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
      <Route path="/vuln-repo/org-cves/:cveId/software" element={<VulnRepoCveSoftwarePage />} />
    </Routes>,
    { initialEntries: [PAGE_PATH] }
  );
}

describe('VulnRepoCveSoftwarePage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows loading state while data is fetching', () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByText('Loading impacted software...')).toBeInTheDocument();
  });

  it('shows error message when the query fails', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockRejectedValue(new Error('Network error'));
    renderPage();
    await waitFor(() => expect(screen.getByText('Network error')).toBeInTheDocument());
  });

  it('shows empty state when no software is matched', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail());
    renderPage();
    await waitFor(() =>
      expect(screen.getByText('No impacted software was found for this CVE.')).toBeInTheDocument()
    );
  });

  it('renders a row for each unique package name and version', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
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
    renderPage();
    await waitFor(() => expect(screen.getByText('lodash')).toBeInTheDocument());
    expect(screen.getByText('4.17.15')).toBeInTheDocument();
  });

  it('deduplicates rows with the same package name and version', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
          ecosystem: 'npm',
          packageName: 'lodash',
          version: '4.17.15',
          applicabilityState: 'APPLICABLE',
          computedImpactState: 'IMPACTED',
          impactState: 'IMPACTED',
          eligibleForFinding: true,
        },
        {
          componentId: 'cmp-2',
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
    renderPage();
    await waitFor(() => expect(screen.getByText('lodash')).toBeInTheDocument());
    expect(screen.getAllByText('lodash')).toHaveLength(1);
  });

  it('shows the software count in the caption', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
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
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/1 matched software entries correlated/i)).toBeInTheDocument()
    );
  });

  it('renders the Back to CVE button', () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByRole('button', { name: /back to cve/i })).toBeInTheDocument();
  });
});
