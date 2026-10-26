import { screen } from '@testing-library/react';
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
    expect(screen.getByRole('button', { name: /open guardrail attached/i })).toBeInTheDocument();
  });
});
