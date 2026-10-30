import { screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiGridPolicy, AiSecurityFinding, AiSecurityPolicy, PolicyConfiguration } from '../features/ai-security/types';
import { ActorContextState } from '../features/auth/context';
import { renderWithProviders } from '../test/test-utils';
import { AiPolicyDetailPage } from './AiPolicyDetailPage';

function buildPolicy(overrides: Partial<AiSecurityPolicy> = {}): AiSecurityPolicy {
  return {
    id: 'AWS_BEDROCK_PUBLIC_KB_S3',
    version: '1.0.0',
    name: 'Public knowledge-base S3 source',
    severity: 'CRITICAL',
    lifecycle: 'PUBLISHED',
    artifactTypes: ['AI_MODEL'],
    requiredResourceFamilies: ['BEDROCK_KNOWLEDGE_BASES', 'S3_EXPOSURE'],
    description: 'A Bedrock knowledge base uses an S3 data source that is publicly accessible.',
    remediation: 'Block public access and restrict the bucket policy to the knowledge-base execution role.',
    controlMappings: { NIST_AI_RMF: 'GOVERN-1.1' },
    available: true,
    enabled: true,
    openFindings: 1,
    lifetimeFindings: 2,
    lastEvaluatedAt: '2026-07-01T00:00:00Z',
    decisionCoverage: 0.5,
    decisionCoverageThreshold: 0.95,
    decisionCoverageStatus: 'FAIL',
    evaluatedArtifacts: 2,
    noDecisionCount: 1,
    ...overrides,
  };
}

function buildFinding(overrides: Partial<AiSecurityFinding> = {}): AiSecurityFinding {
  return {
    id: 'finding-1',
    displayId: 'AIF-001',
    policyId: 'AWS_BEDROCK_PUBLIC_KB_S3',
    policyVersion: '1.0.0',
    artifactId: 'artifact-1',
    artifactName: 'kb-source-bucket',
    severity: 'CRITICAL',
    status: 'OPEN',
    title: 'Public knowledge-base S3 source detected',
    evidence: {},
    reviewDisposition: 'NEEDS_INVESTIGATION',
    firstObservedAt: '2026-06-01T00:00:00Z',
    lastObservedAt: '2026-07-01T00:00:00Z',
    resolvedAt: null,
    ...overrides,
  };
}

function buildPolicyMetadata(nativeKindsJson: string, name = 'Bedrock agent policy'): AiGridPolicy {
  return {
    policyId: 'AWS_BEDROCK_PUBLIC_KB_S3',
    version: '1.0.0',
    name,
    severity: 'CRITICAL',
    lifecycle: 'PUBLISHED',
    workflowClass: 'POSTURE_FINDING',
    selection: 'ENABLED',
    controlObjectiveId: 'AWS-CONTROL-1',
    provider: 'AWS',
    evaluationMode: 'ARTIFACT_FACTS',
    artifactTypesJson: '["AI_AGENT"]',
    nativeKindsJson,
    requiredResourceFamiliesJson: '["BEDROCK_AGENTS"]',
    baseEvidenceTiersJson: '[]',
    conditionalCapabilitiesJson: '[]',
    requiredCapabilitiesJson: '[]',
    frameworkMappingsJson: '[]',
    readiness: 'READY',
    failedArtifacts: 0,
    totalArtifacts: 1,
  };
}

describe('AiPolicyDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders policy metadata, control mappings and required evidence in the overview tab', async () => {
    vi.spyOn(api, 'getAiGridPolicyDetail').mockResolvedValue(buildPolicy());
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [buildFinding()], page: 0, size: 200, total: 1 });
    renderWithProviders(<AiPolicyDetailPage policyId="AWS_BEDROCK_PUBLIC_KB_S3" />);

    expect(await screen.findByRole('heading', { name: 'Public knowledge-base S3 source' })).toBeInTheDocument();
    expect(screen.getByText('Block public access and restrict the bucket policy to the knowledge-base execution role.')).toBeInTheDocument();
    expect(screen.getByText('Bedrock Knowledge Bases')).toBeInTheDocument();
    expect(screen.getByText('S3 Exposure')).toBeInTheDocument();
    expect(screen.getByText('NIST_AI_RMF')).toBeInTheDocument();
    expect(screen.getByText('GOVERN-1.1')).toBeInTheDocument();
  });

  it.each([
    { declared: '["AWS_BEDROCK_AGENT"]', expected: 'Aws Bedrock Agent' },
    { declared: '[]', expected: 'Not specified' },
  ])('displays declared native types without guessing from the policy name', async ({ declared, expected }) => {
    vi.spyOn(api, 'getAiGridPolicyDetail').mockResolvedValue(buildPolicy());
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([buildPolicyMetadata(declared)]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    renderWithProviders(<AiPolicyDetailPage policyId="AWS_BEDROCK_PUBLIC_KB_S3" />);

    expect(await screen.findByText(expected)).toBeInTheDocument();
  });

  it('shows the impacted findings and AI artifacts in their own tabs', async () => {
    vi.spyOn(api, 'getAiGridPolicyDetail').mockResolvedValue(buildPolicy());
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({
      items: [buildFinding()],
      page: 0,
      size: 200,
      total: 1,
    });
    renderWithProviders(<AiPolicyDetailPage policyId="AWS_BEDROCK_PUBLIC_KB_S3" />);
    await screen.findByRole('heading', { name: 'Public knowledge-base S3 source' });

    fireEvent.click(screen.getByRole('button', { name: /^Findings/ }));
    expect(await screen.findByText('AIF-001')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^AI Artifacts/ }));
    expect(await screen.findByText('kb-source-bucket')).toBeInTheDocument();
  });

  function buildConfiguration(overrides: Partial<PolicyConfiguration> = {}): PolicyConfiguration {
    return {
      governance: {
        platformPolicyVersion: '1.0.0', platformLifecycle: 'PUBLISHED', platformOwner: 'platform', governanceStatus: 'APPROVED',
        tenantConfigurable: true, platformDefaultSelection: 'ENABLED', configurationSource: 'PLATFORM_DEFAULT', tenantConfigurationUpdatedAt: null,
      },
      scope: { mode: 'ALL', conditionLogic: 'AND', conditions: [], updatedBy: null, updatedAt: null },
      exceptions: [],
      parameters: [{ key: 'threshold', label: 'Exposure threshold', type: 'ENUM', options: ['LOW', 'HIGH'], defaultValue: 'LOW', helpText: 'When to flag', value: 'LOW' }],
      matchedArtifactCount: 2,
      totalArtifactCount: 3,
      ...overrides,
    };
  }

  function renderAsAdmin() {
    return renderWithProviders(
      <ActorContextState.Provider value={{ creator: false, principal: 'a', userId: 'u', tenantId: 't', tenantName: 'T', roles: ['ROLE_TENANT_ADMIN'] }}>
        <AiPolicyDetailPage policyId="AWS_BEDROCK_PUBLIC_KB_S3" />
      </ActorContextState.Provider>,
    );
  }

  it('waits for the catalog instead of reporting not found while one source is still loading', async () => {
    vi.spyOn(api, 'getAiGridPolicyDetail').mockRejectedValue(new Error('legacy detail unavailable'));
    let resolveCatalog: (value: AiGridPolicy[]) => void = () => undefined;
    vi.spyOn(api, 'listAiGridPolicies').mockReturnValue(new Promise((resolve) => { resolveCatalog = resolve; }));
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    renderWithProviders(<AiPolicyDetailPage policyId="AWS_BEDROCK_PUBLIC_KB_S3" />);

    await waitFor(() => expect(api.getAiGridPolicyDetail).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.getByText('Loading policy…')).toBeInTheDocument();
    expect(screen.queryByText(/was not found/)).not.toBeInTheDocument();
    resolveCatalog([buildPolicyMetadata('[]')]);
    expect(await screen.findByRole('heading', { name: 'Bedrock agent policy' })).toBeInTheDocument();
  });

  it('marks unsaved scope changes, keeps them on a failed save, and confirms a successful save', async () => {
    vi.spyOn(api, 'getAiGridPolicyDetail').mockResolvedValue(buildPolicy());
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiGridPolicyConfiguration').mockResolvedValue(buildConfiguration());
    const save = vi.spyOn(api, 'updateAiGridPolicyScope')
      .mockRejectedValueOnce(new Error('rejected'))
      .mockResolvedValueOnce(buildConfiguration({ scope: { mode: 'CUSTOM_LIST', conditionLogic: 'AND', conditions: [], updatedBy: 'u', updatedAt: null } }));
    renderAsAdmin();

    await screen.findByRole('heading', { name: 'Public knowledge-base S3 source' });
    fireEvent.click(screen.getByRole('button', { name: 'Governance' }));
    expect(await screen.findByText('Permitted by platform')).toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Custom list' }));
    expect(screen.getByText('Unsaved scope changes')).toBeInTheDocument();
    expect(screen.getByText(/currently match the saved scope/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Save scope' }));
    expect(await screen.findByText('The scope could not be saved. Your changes are kept; try again.')).toBeInTheDocument();
    expect(screen.getByText('Unsaved scope changes')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Save scope' }));
    expect(await screen.findByText('Scope saved.')).toBeInTheDocument();
    expect(save).toHaveBeenLastCalledWith('AWS_BEDROCK_PUBLIC_KB_S3', 'CUSTOM_LIST', 'AND', []);
    expect(screen.queryByRole('button', { name: 'Discard scope changes' })).not.toBeInTheDocument();
  });

  it('names parameter selects and discards unsaved parameter changes', async () => {
    vi.spyOn(api, 'getAiGridPolicyDetail').mockResolvedValue(buildPolicy());
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiGridPolicyConfiguration').mockResolvedValue(buildConfiguration());
    renderAsAdmin();

    await screen.findByRole('heading', { name: 'Public knowledge-base S3 source' });
    fireEvent.click(screen.getByRole('button', { name: 'Governance' }));
    const select = await screen.findByRole('combobox', { name: 'Exposure threshold' });
    fireEvent.change(select, { target: { value: 'HIGH' } });
    expect(screen.getByText('Unsaved parameter changes')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Discard parameter changes' }));
    await waitFor(() => expect(select).toHaveValue('LOW'));
    expect(screen.queryByText('Unsaved parameter changes')).not.toBeInTheDocument();
  });

  it('shows a not-found state for an unknown policy id', async () => {
    vi.spyOn(api, 'getAiGridPolicyDetail').mockRejectedValue(new Error('Not found'));
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    renderWithProviders(<AiPolicyDetailPage policyId="DOES_NOT_EXIST" />);

    expect(await screen.findByText(/was not found/)).toBeInTheDocument();
  });
});
