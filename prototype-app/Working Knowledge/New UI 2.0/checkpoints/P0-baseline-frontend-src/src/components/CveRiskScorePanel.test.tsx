import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { defaultRiskPolicy } from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { CveRiskScorePanel } from './CveRiskScorePanel';

function buildCveRecord(
  overrides: Partial<OrgSpecificCveExposureRecord> = {}
): OrgSpecificCveExposureRecord {
  return {
    recordId: 'rec-1',
    vulnerabilityId: 'vuln-1',
    externalId: 'CVE-2024-1234',
    title: 'Test CVE',
    applicability: 'APPLICABLE',
    impacted: true,
    impactState: 'IMPACTED',
    severity: 'HIGH',
    inKev: false,
    matchedComponentCount: 1,
    matchedSoftwareCount: 1,
    matchedAssetCount: 0,
    applicableComponentCount: 1,
    impactedComponentCount: 1,
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
    ...overrides,
  };
}

describe('CveRiskScorePanel', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders nothing when the risk score journey has only one stage', () => {
    // cvssScore=0, no other signals → only "CVE Published" stage → journey.length=1 → null
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    const { container } = renderWithProviders(
      <CveRiskScorePanel item={buildCveRecord({ cvssScore: 0 })} mini />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders SCOUT RISK SCORE header in mini mode when journey has multiple stages', async () => {
    // cvssScore=7.5 + inKev=true → "CVE Published" + "In CISA KEV" → 2 stages
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    renderWithProviders(
      <CveRiskScorePanel item={buildCveRecord({ cvssScore: 7.5, inKev: true })} mini />
    );
    await waitFor(() =>
      expect(screen.getByText('SCOUT RISK SCORE')).toBeInTheDocument()
    );
  });

  it('renders period selector buttons in mini mode', async () => {
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    renderWithProviders(
      <CveRiskScorePanel item={buildCveRecord({ cvssScore: 7.5, inKev: true })} mini />
    );
    await waitFor(() => expect(screen.getByText('14d')).toBeInTheDocument());
    expect(screen.getByText('30d')).toBeInTheDocument();
    expect(screen.getByText('90d')).toBeInTheDocument();
  });

  it('switches active period when a period button is clicked', async () => {
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    renderWithProviders(
      <CveRiskScorePanel item={buildCveRecord({ cvssScore: 7.5, inKev: true })} mini />
    );
    await waitFor(() => expect(screen.getByText('30d')).toBeInTheDocument());
    fireEvent.click(screen.getByText('30d'));
    expect(screen.getByText('30d').className).toContain('active');
    expect(screen.getByText('14d').className).not.toContain('active');
  });

  it('renders a numeric risk score in mini mode', async () => {
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    renderWithProviders(
      <CveRiskScorePanel item={buildCveRecord({ cvssScore: 7.5, inKev: true })} mini />
    );
    // Score appears as a decimal like "3.8" — check a number-like text is present
    await waitFor(() =>
      expect(screen.getByText(/^\d+\.\d+$/)).toBeInTheDocument()
    );
  });

  it('uses default policy when getRiskPolicy is still loading', () => {
    // Keep policy pending — component should still render with DEFAULT_POLICY
    vi.spyOn(api, 'getRiskPolicy').mockReturnValue(new Promise(() => {}));
    const { container } = renderWithProviders(
      <CveRiskScorePanel item={buildCveRecord({ cvssScore: 7.5, inKev: true })} mini />
    );
    // Component renders immediately with default policy (no waiting for policy)
    expect(container.firstChild).not.toBeNull();
  });
});
