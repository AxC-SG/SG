import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { renderWithProviders } from '../test/test-utils';
import { VulnRepoVulnerabilitiesPage } from './VulnRepoVulnerabilitiesPage';

describe('VulnRepoVulnerabilitiesPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('uses the vuln repo endpoint and renders ingested-only rows without breaking the table', async () => {
    const listVulnRepoSpy = vi.spyOn(cveWorkbenchApi, 'listVulnRepoVulnerabilities').mockResolvedValue({
      summary: {
        reviewQueueCount: 7,
        applicableCount: 5,
        impactedCount: 3,
        underInvestigationCount: 1,
        resolvedCount: 2,
      },
      items: [
        {
          recordId: '10000000-0000-0000-0000-000000000001',
          vulnerabilityId: '20000000-0000-0000-0000-000000000001',
          externalId: 'CVE-2026-23360',
          title: 'Canonical only',
          descriptionSnippet: 'Only ingested',
          applicability: 'UNKNOWN',
          impacted: false,
          impactState: 'UNKNOWN',
          severity: 'HIGH',
          cvssScore: 8.8,
          epssScore: 0.12,
          inKev: false,
          matchedComponentCount: 0,
          matchedSoftwareCount: 0,
          matchedAssetCount: 0,
          applicableComponentCount: 0,
          impactedComponentCount: 0,
          notAffectedComponentCount: 0,
          fixedComponentCount: 0,
          noPatchComponentCount: 0,
          underInvestigationComponentCount: 0,
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
    const listOrgSpecificSpy = vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue({
      summary: {
        reviewQueueCount: 0,
        applicableCount: 0,
        impactedCount: 0,
        underInvestigationCount: 0,
        resolvedCount: 0,
      },
      items: [],
      page: 0,
      size: 25,
      totalItems: 0,
      totalPages: 0,
    });

    renderWithProviders(
      <VulnRepoVulnerabilitiesPage />,
      { route: '/vuln-repo/vulnerabilities?query=CVE-2026-23360' }
    );

    await screen.findByText('CVE-2026-23360');
    await waitFor(() => {
      expect(listVulnRepoSpy).toHaveBeenCalledWith(expect.objectContaining({
        page: 0,
        size: 25,
        query: 'CVE-2026-23360',
      }));
      expect(listOrgSpecificSpy).not.toHaveBeenCalled();
    });

    expect(screen.getByText('Only ingested')).toBeInTheDocument();
    expect(screen.getAllByText('No').length).toBeGreaterThan(0);
    expect(screen.getByText('8.8')).toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('shows reviewed investigation status when the server has a saved investigation summary', async () => {
    vi.spyOn(cveWorkbenchApi, 'listVulnRepoVulnerabilities').mockResolvedValue({
      summary: {
        reviewQueueCount: 7,
        applicableCount: 5,
        impactedCount: 3,
        underInvestigationCount: 1,
        resolvedCount: 2,
      },
      items: [
        {
          recordId: '10000000-0000-0000-0000-000000000002',
          vulnerabilityId: '20000000-0000-0000-0000-000000000002',
          externalId: 'CVE-2026-9999',
          title: 'Reviewed CVE',
          descriptionSnippet: 'Investigation completed',
          applicability: 'UNKNOWN',
          impacted: true,
          impactState: 'IMPACTED',
          severity: 'HIGH',
          cvssScore: 8.8,
          epssScore: 0.12,
          inKev: false,
          matchedComponentCount: 1,
          matchedSoftwareCount: 1,
          matchedAssetCount: 1,
          applicableComponentCount: 1,
          impactedComponentCount: 1,
          notAffectedComponentCount: 0,
          fixedComponentCount: 0,
          noPatchComponentCount: 0,
          underInvestigationComponentCount: 0,
          unknownComponentCount: 0,
          openFindings: 1,
          lastEvaluatedAt: '2026-06-19T00:00:00Z',
          eolComponentCount: 0,
          eosComponentCount: 0,
          hasInvestigationSummary: true,
          investigationSummaryGeneratedAt: '2026-06-19T00:00:00Z',
          hasAiSolution: false,
        },
      ],
      page: 0,
      size: 25,
      totalItems: 1,
      totalPages: 1,
    });
    vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue({
      summary: {
        reviewQueueCount: 0,
        applicableCount: 0,
        impactedCount: 0,
        underInvestigationCount: 0,
        resolvedCount: 0,
      },
      items: [],
      page: 0,
      size: 25,
      totalItems: 0,
      totalPages: 0,
    });

    renderWithProviders(
      <VulnRepoVulnerabilitiesPage />,
      { route: '/vuln-repo/vulnerabilities?query=CVE-2026-9999' }
    );

    await screen.findByText('CVE-2026-9999');
    expect(screen.getByText('Reviewed')).toBeInTheDocument();
  });

  it('shows readable filter properties and labels in the column filter popover', async () => {
    vi.spyOn(cveWorkbenchApi, 'listVulnRepoVulnerabilities').mockResolvedValue({
      summary: {
        reviewQueueCount: 0,
        applicableCount: 0,
        impactedCount: 0,
        underInvestigationCount: 0,
        resolvedCount: 0,
      },
      items: [],
      page: 0,
      size: 25,
      totalItems: 0,
      totalPages: 0,
    });

    renderWithProviders(<VulnRepoVulnerabilitiesPage />);

    fireEvent.click(await screen.findByTitle('Filter Severity'));

    expect(screen.getByRole('dialog', { name: 'Column filter options' })).toBeInTheDocument();
    expect(screen.getByText('Critical')).toBeVisible();
    expect(screen.getByText('High')).toBeVisible();
    expect(screen.getByText('Medium')).toBeVisible();
    expect(screen.getByText('Low')).toBeVisible();
    expect(screen.getByText('Unknown')).toBeVisible();
  });
});
