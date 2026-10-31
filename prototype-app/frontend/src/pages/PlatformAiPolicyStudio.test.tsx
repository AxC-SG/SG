import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { PlatformAiPolicyStudio } from './PlatformAiPolicyStudio';

describe('PlatformAiPolicyStudio', () => {
  afterEach(() => vi.restoreAllMocks());

  it('renders the shipped catalog summary and OWASP mappings', async () => {
    vi.spyOn(api, 'listPlatformAiGridPolicies').mockResolvedValue([{
      policyId: 'AGCF-AWS-001', available: true, defaultSelection: 'REQUIRED', rolloutStage: 'GENERAL_AVAILABILITY',
      canaryTenantIdsJson: '[]', pinnedVersion: '1.0.0', updatedBy: 'compiler', updatedAt: '2026-01-01T00:00:00Z',
      version: '1.0.0', name: 'Guardrail attached', severity: 'HIGH', lifecycle: 'PUBLISHED', provider: 'AWS',
      frameworkMappingsJson: '[{"framework":"OWASP_GENAI_LLM_TOP_10","frameworkVersion":"2026","controlId":"LLM01","mappingType":"DIRECT"}]',
    }]);
    vi.spyOn(api, 'getPlatformAiGridShippingStatus').mockResolvedValue({ expectedPolicies: 76, installedPolicies: 76, publishedPolicies: 76, distributedPolicies: 76, digestMatchedPolicies: 76, rolloutPendingTenants: 0, blockers: [] });
    vi.spyOn(api, 'getAiFrameworks').mockResolvedValue([{ framework: 'OWASP_GENAI_LLM_TOP_10', frameworkVersion: '2026', displayName: 'OWASP GenAI LLM Top 10', controls: [{ controlId: 'LLM01', name: 'Prompt injection', displayOrder: 1 }] }]);
    vi.spyOn(api, 'listTenants').mockResolvedValue([]);
    vi.spyOn(api, 'listPlatformAiGridPolicyRollouts').mockResolvedValue([]);
    renderWithProviders(<PlatformAiPolicyStudio />);
    expect(await screen.findByText('Guardrail attached')).toBeInTheDocument();
    expect(screen.getByText('OWASP GenAI LLM Top 10 2026 · LLM01 (DIRECT)')).toBeInTheDocument();
    expect(screen.getByText('digest verified')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open policy: Guardrail attached' })).toHaveAttribute('href', '/platform/ai-policies/AGCF-AWS-001');
  });
  it('does not report a healthy catalog while shipping status is loading or failed', async () => {
    vi.spyOn(api, 'listPlatformAiGridPolicies').mockResolvedValue([]);
    vi.spyOn(api, 'getAiFrameworks').mockResolvedValue([]);
    vi.spyOn(api, 'listPlatformAiGridPolicyRollouts').mockResolvedValue([]);
    vi.spyOn(api, 'getPlatformAiGridShippingStatus').mockRejectedValue(new Error('down'));
    renderWithProviders(<PlatformAiPolicyStudio />);

    expect(screen.getByText('Checking catalog')).toBeInTheDocument();
    expect(await screen.findByText('Status unavailable')).toBeInTheDocument();
    expect(screen.queryByText('Catalog healthy')).not.toBeInTheDocument();
    expect(screen.queryByText('Ready to ship')).not.toBeInTheDocument();
    expect(screen.getByText('No policies are in the shipped catalog.')).toBeInTheDocument();
  });

  it('shows catalog and rollout load failures with Retry instead of empty lists', async () => {
    vi.spyOn(api, 'listPlatformAiGridPolicies').mockRejectedValue(new Error('down'));
    vi.spyOn(api, 'getAiFrameworks').mockResolvedValue([]);
    vi.spyOn(api, 'getPlatformAiGridShippingStatus').mockResolvedValue({ expectedPolicies: 1, installedPolicies: 1, publishedPolicies: 1, distributedPolicies: 1, digestMatchedPolicies: 1, rolloutPendingTenants: 0, blockers: [] });
    const rollouts = vi.spyOn(api, 'listPlatformAiGridPolicyRollouts').mockRejectedValueOnce(new Error('down')).mockResolvedValueOnce([]);
    renderWithProviders(<PlatformAiPolicyStudio />);

    expect(await screen.findByText('The policy catalog could not be loaded.')).toBeInTheDocument();
    expect(screen.queryByText('No policies match the selected filters.')).not.toBeInTheDocument();
    expect(await screen.findByText('Rollout jobs could not be loaded.')).toBeInTheDocument();
    expect(screen.queryByText('No rollout jobs are waiting.')).not.toBeInTheDocument();
    expect(screen.getByText('— active')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry loading' }));
    expect(await screen.findByText('No rollout jobs are waiting.')).toBeInTheDocument();
    expect(rollouts).toHaveBeenCalledTimes(2);
  });
});
