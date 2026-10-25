import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { Tenant } from '../features/admin/types';
import type { AiGridPlatformPolicyDetail, AiGridPolicyDistribution } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { PlatformAiPolicyDetailPage } from './PlatformAiPolicyDetailPage';

function distribution(overrides: Partial<AiGridPolicyDistribution> = {}): AiGridPolicyDistribution {
  return {
    policyId: 'aws.agent-tool-scope', available: true, defaultSelection: 'ENABLED', rolloutStage: 'DEV', canaryTenantIdsJson: '[]',
    pinnedVersion: null, updatedBy: 'owner@example.test', updatedAt: '2026-10-20T00:00:00Z', version: '1.0.0',
    name: 'Unrestricted agent tool permissions', severity: 'CRITICAL', lifecycle: 'VALIDATED', provider: 'AWS',
    artifactTypesJson: '["AI_AGENT"]',
    frameworkMappingsJson: '[{"framework":"OWASP_AGENTIC_TOP_10","frameworkVersion":"2026","controlId":"ASI02","mappingType":"INFORMATIVE"}]',
    ...overrides,
  };
}

function detail(overrides: Partial<AiGridPlatformPolicyDetail> = {}): AiGridPlatformPolicyDetail {
  return {
    policyId: 'aws.agent-tool-scope', version: '1.0.0', name: 'Unrestricted agent tool permissions', description: 'Finds tools without a constrained scope.',
    severity: 'CRITICAL', lifecycle: 'VALIDATED', workflowClass: 'POSTURE', defaultSelection: 'ENABLED', controlObjectiveId: 'objective.tool-scope',
    objectiveName: null, securityIntent: 'Keep agent tools scoped.', remediationIntent: 'Constrain the tool scope.', provider: 'AWS',
    evaluationMode: 'STATIC_FACTS', evaluationDefinition: null, baseEvidenceTiers: [], conditionalCapabilities: [], requiredCapabilities: [],
    requiredRelationships: [], requiredResourceFamilies: [], nativeKinds: ['BEDROCK_AGENT'], requiredFacts: [], frameworkMappings: undefined,
    certificationParameterProfile: null, packageDigest: 'sha256:abc', packageSourceRef: 'catalog/aws.agent-tool-scope@1.0.0', releaseFamily: 'phase-1',
    releaseWave: 'wave-1', governanceOwner: 'Platform Security', governanceStatus: 'AWAITING_APPROVAL', tenantConfigurable: false,
    governanceNotes: null, approvedBy: null, approvedAt: null, publishedAt: null, evaluationSubject: 'ARTIFACT',
    ...overrides,
  };
}

function tenant(id: string, name: string, status: string): Tenant {
  return {
    id, name, slug: id, status, planCode: null, billingRef: null, maxConnectorCount: null, maxServiceAccountCount: null,
    maxDailySbomUploads: null, maxExportRows: null, maxDailyExposureRefreshes: null, createdAt: '2026-01-01T00:00:00Z', updatedAt: null,
  };
}

function mockCatalog(policy: AiGridPolicyDistribution) {
  vi.spyOn(api, 'listPlatformAiGridPolicies').mockResolvedValue([policy]);
  vi.spyOn(api, 'getPlatformAiGridPolicyDetail').mockResolvedValue(detail({ lifecycle: policy.lifecycle }));
  vi.spyOn(api, 'listTenants').mockResolvedValue([tenant('t-acme', 'Acme', 'ACTIVE'), tenant('t-globex', 'Globex', 'SUSPENDED')]);
}

async function openGovernance() {
  fireEvent.click(await screen.findByRole('button', { name: 'Open governance controls →' }));
  return screen.findByText('Governance actions');
}

describe('PlatformAiPolicyDetailPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('renders the platform definition, mappings and governance without tenant results', async () => {
    mockCatalog(distribution());
    renderWithProviders(<PlatformAiPolicyDetailPage policyId="aws.agent-tool-scope" />);

    expect(await screen.findByRole('heading', { name: 'Unrestricted agent tool permissions' })).toBeInTheDocument();
    expect(await screen.findByText('Finds tools without a constrained scope.')).toBeInTheDocument();
    expect(api.getPlatformAiGridPolicyDetail).toHaveBeenCalledWith('aws.agent-tool-scope', '1.0.0');
    expect(screen.getByText('Framework Mappings · 1')).toBeInTheDocument();
    expect(screen.getByText('ASI02 · Supporting (Legacy)')).toBeInTheDocument();
    expect(screen.getByText('Bedrock Agent')).toBeInTheDocument();
    expect(screen.getByText('Platform controlled')).toBeInTheDocument();
    expect(screen.getByText('Platform Security')).toBeInTheDocument();
  });

  it('requires a note and cohort before dev/test deployment and approval of a validated policy', async () => {
    mockCatalog(distribution());
    const deploy = vi.spyOn(api, 'deployPlatformAiGridPolicyToDev').mockResolvedValue(undefined);
    const approve = vi.spyOn(api, 'approvePlatformAiGridPolicy').mockResolvedValue({ approved: false, reason: 'release gates have not passed' });
    renderWithProviders(<PlatformAiPolicyDetailPage policyId="aws.agent-tool-scope" />);
    await openGovernance();

    const approveButton = screen.getByRole('button', { name: 'Approve policy' });
    const deployButton = screen.getByRole('button', { name: 'Deploy to dev/test' });
    expect(approveButton).toBeDisabled();
    expect(deployButton).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Publish to all active tenants' })).toBeDisabled();

    const cohort = screen.getByRole('listbox');
    expect(Array.from((cohort as HTMLSelectElement).options).map((option) => option.textContent)).toEqual(['Acme']);
    fireEvent.change(screen.getByPlaceholderText('Describe the review evidence supporting approval or rollout'), { target: { value: ' Dev cohort passed. ' } });
    expect(approveButton).toBeEnabled();
    expect(deployButton).toBeDisabled();
    (cohort as HTMLSelectElement).options[0].selected = true;
    fireEvent.change(cohort);
    fireEvent.click(deployButton);
    await waitFor(() => expect(deploy).toHaveBeenCalledWith('aws.agent-tool-scope', ['t-acme'], 'Dev cohort passed.'));
    expect(await screen.findByText('Policy deployed to the selected dev/test tenants.')).toBeInTheDocument();

    fireEvent.click(approveButton);
    await waitFor(() => expect(approve).toHaveBeenCalledWith('aws.agent-tool-scope', 'Dev cohort passed.'));
    expect(await screen.findByText('Approval blocked: release gates have not passed')).toHaveClass('notice', 'error');
  });

  it('publishes an approved policy to all active tenants and reports a failed deprecation', async () => {
    mockCatalog(distribution({ lifecycle: 'APPROVED', rolloutStage: 'CANARY' }));
    const publish = vi.spyOn(api, 'publishPlatformAiGridPolicy').mockResolvedValue(undefined);
    vi.spyOn(api, 'deprecatePlatformAiGridPolicy').mockRejectedValue(new Error('Deprecation requires a successor'));
    renderWithProviders(<PlatformAiPolicyDetailPage policyId="aws.agent-tool-scope" />);
    await openGovernance();

    expect(screen.getByRole('button', { name: 'Approve policy' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Publish canary' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Publish to all active tenants' }));
    await waitFor(() => expect(publish).toHaveBeenCalledWith('aws.agent-tool-scope', [], true));
    expect(await screen.findByText('Policy publication started.')).toHaveClass('notice', 'success');

    const deprecateButton = screen.getByRole('button', { name: 'Deprecate policy' });
    expect(deprecateButton).toBeDisabled();
    fireEvent.change(screen.getByPlaceholderText('Why this policy is being retired'), { target: { value: 'Superseded' } });
    fireEvent.click(deprecateButton);
    expect(await screen.findByText('Action failed: Deprecation requires a successor')).toHaveClass('notice', 'error');
  });

  it('shows a not-found state for a policy missing from the catalog', async () => {
    vi.spyOn(api, 'listPlatformAiGridPolicies').mockResolvedValue([distribution()]);
    vi.spyOn(api, 'listTenants').mockResolvedValue([]);
    renderWithProviders(<PlatformAiPolicyDetailPage policyId="missing.policy" />);
    expect(await screen.findByText('missing.policy')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '← Back' })).toBeInTheDocument();
  });
});
