import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { renderWithProviders } from '../test/test-utils';
import { VulnRepoOrgCvePage } from './VulnRepoOrgCvePage';

describe('VulnRepoOrgCvePage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('ignores concept review query params and renders only the current investigation flow', async () => {
    vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue({
      summary: {
        reviewQueueCount: 1,
        applicableCount: 1,
        impactedCount: 0,
        underInvestigationCount: 1,
        resolvedCount: 0,
      },
      items: [
        {
          recordId: '10000000-0000-0000-0000-000000000001',
          vulnerabilityId: '20000000-0000-0000-0000-000000000001',
          externalId: 'CVE-2026-1001',
          title: 'Repo investigation record',
          descriptionSnippet: 'Tracked vulnerability',
          applicability: 'UNKNOWN',
          impacted: false,
          impactState: 'UNDER_INVESTIGATION',
          severity: 'HIGH',
          cvssScore: 8.1,
          epssScore: 0.12,
          inKev: false,
          matchedComponentCount: 1,
          matchedSoftwareCount: 1,
          matchedAssetCount: 1,
          applicableComponentCount: 0,
          impactedComponentCount: 0,
          notAffectedComponentCount: 0,
          fixedComponentCount: 0,
          noPatchComponentCount: 0,
          underInvestigationComponentCount: 1,
          unknownComponentCount: 0,
          openFindings: 0,
          eolComponentCount: 0,
          eosComponentCount: 0,
          hasInvestigationSummary: false,
          hasAiSolution: false,
        },
      ],
      page: 0,
      size: 25,
      totalItems: 1,
      totalPages: 1,
    });
    vi.spyOn(cveWorkbenchApi, 'getOrgSpecificCveAutomationStatus').mockResolvedValue({
      automationEnabled: true,
      pendingEventCount: 0,
      processingEventCount: 0,
      pendingByType: {},
      staleEventCount: 0,
      failedEventCount: 0,
      oldestPendingEventAgeSeconds: 0,
      oldestProcessingEventAgeSeconds: 0,
      ingestionQueuedJobCount: 0,
      ingestionRunningJobCount: 0,
      oldestQueuedIngestionAgeSeconds: 0,
      oldestRunningIngestionAgeSeconds: 0,
    });
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue({
      summary: {
        externalId: 'CVE-2026-1001',
        title: 'Repo investigation record',
        description: 'Tracked vulnerability',
        severity: 'HIGH',
        cvssScore: 8.1,
        epssScore: 0.12,
        cweIds: 'CWE-79',
        source: 'GHSA',
        inKev: false,
      },
      signals: {
        exploitAvailable: false,
        exploitReason: '',
        systemsImpacted: false,
        componentCount: 1,
        softwareCount: 1,
        assetCount: 1,
        patchAvailable: true,
        patchVersions: '1.2.3',
      },
      investigations: [],
      assessments: [],
      matchedSoftware: [
        {
          componentId: 'cmp-1',
          assetId: 'asset-1',
          assetName: 'host-1',
          assetIdentifier: 'host-1',
          assetType: 'HOST',
          ecosystem: 'linux',
          packageName: 'openssl',
          version: '1.2.2',
          applicabilityState: 'UNKNOWN',
          computedImpactState: 'UNDER_INVESTIGATION',
          impactState: 'UNDER_INVESTIGATION',
          eligibleForFinding: true,
        },
      ],
      vendorIntelligence: [],
    });

    renderWithProviders(<VulnRepoOrgCvePage />, {
      route: '/vuln-repo/org-cves?investigationCanvas=concept',
    });

    await screen.findByText('CVE-2026-1001');
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'CVE-2026-1001' }));

    await waitFor(() => {
      expect(cveWorkbenchApi.getCveDetail).toHaveBeenCalledWith('CVE-2026-1001');
    });

    expect(screen.queryByText('Investigation Canvas Review')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Investigation canvas concept review')).not.toBeInTheDocument();
  });
});
