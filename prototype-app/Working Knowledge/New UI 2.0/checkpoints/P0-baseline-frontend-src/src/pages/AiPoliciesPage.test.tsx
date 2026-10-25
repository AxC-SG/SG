import { screen, fireEvent } from '@testing-library/react';
import { Route, Routes, useParams } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiGridPolicy } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiPoliciesPage } from './AiPoliciesPage';
import { AiPolicyDetailPage } from './AiPolicyDetailPage';

function PolicyDetailRoute() {
  const params = useParams<{ policyId: string }>();
  return <AiPolicyDetailPage policyId={decodeURIComponent(params.policyId ?? '')} />;
}

function renderPoliciesPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/policies" element={<AiPoliciesPage />} />
      <Route path="/policies/:policyId" element={<PolicyDetailRoute />} />
    </Routes>,
    { route: '/policies' }
  );
}

function buildPolicy(overrides: Partial<AiGridPolicy> = {}): AiGridPolicy {
  return {
    policyId: 'AGCF-AWS-001',
    version: '1.0.0',
    name: 'Public knowledge-base S3 source',
    severity: 'CRITICAL',
    lifecycle: 'PUBLISHED',
    workflowClass: 'POSTURE_FINDING',
    selection: 'ENABLED',
    controlObjectiveId: 'AGCF-OBJ-AWS-001',
    provider: 'AWS',
    evaluationMode: 'ARTIFACT_FACTS',
    artifactTypesJson: '["AI_AGENT"]',
    requiredResourceFamiliesJson: '["BEDROCK"]',
    baseEvidenceTiersJson: '["E0"]',
    conditionalCapabilitiesJson: '[]',
    requiredCapabilitiesJson: '["BEDROCK_KNOWLEDGE_BASES"]',
    frameworkMappingsJson: '[]',
    readiness: 'READY',
    failedArtifacts: 1,
    totalArtifacts: 3,
    ...overrides,
  };
}

describe('AiPoliciesPage', () => {
  beforeEach(() => {
    vi.spyOn(api, 'getAiFrameworks').mockResolvedValue([{
      framework: 'OWASP_GENAI_LLM_TOP_10', frameworkVersion: '2026', displayName: 'OWASP GenAI LLM Top 10', controls: [],
    }]);
    vi.spyOn(api, 'getAiFrameworkCoverage').mockResolvedValue({
      framework: 'OWASP_GENAI_LLM_TOP_10', frameworkVersion: '2026', coverageEpochId: null, runId: null,
      tenantSchemaReady: true, blockers: ['NO_COVERAGE_EPOCH'], controls: [],
      legacyCompatibility: { policies: 21, distributed: 21, required: 13, enabled: 0, preview: 8 },
    });
    vi.spyOn(api, 'getAiRuntimeTelemetryReadiness').mockResolvedValue({
      windowStart: '2026-01-01T00:00:00Z', windowEnd: '2026-01-15T00:00:00Z', windowDays: 14,
      minimumFillRate: 0.95, minimumAgentCorrelationRate: 0.9, minimumVersionCorrelationRate: 0.8,
      minimumExecutionsPerProvider: 100, minimumVersionApplicableExecutions: 50,
      available: true, program2EntryGateMet: false, blockers: [], providers: [],
    });
    vi.spyOn(api, 'getLatestAiGridAssessmentStates').mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders one row per policy with governed metadata and artifact coverage', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([buildPolicy()]);
    renderPoliciesPage();

    expect(await screen.findByText('Public knowledge-base S3 source')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('1 / 3')).toBeInTheDocument();
    expect(screen.getByText('Ai Agent')).toBeInTheDocument();
    expect(screen.getByText('aws')).toBeInTheDocument();
  });

  it('navigates to the policy detail page when a row is clicked', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'getAiGridPolicyDetail').mockResolvedValue({
      id: 'AGCF-AWS-001', version: '1.0.0', name: 'Public knowledge-base S3 source', severity: 'CRITICAL',
      artifactTypes: [], requiredResourceFamilies: [], description: 'Block public access and restrict the bucket policy.',
      remediation: 'Block public access and restrict the bucket policy.', controlMappings: {}, available: true, enabled: true,
      lifecycle: 'PUBLISHED',
      openFindings: 0, lifetimeFindings: 0, lastEvaluatedAt: null, decisionCoverage: 1, decisionCoverageThreshold: 1,
      decisionCoverageStatus: 'PASS', evaluatedArtifacts: 1, noDecisionCount: 0,
    });
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    renderPoliciesPage();

    const nameCell = await screen.findByText('Public knowledge-base S3 source');
    fireEvent.click(nameCell.closest('tr')!);

    expect((await screen.findAllByText(/Block public access/)).length).toBeGreaterThan(0);
    expect(screen.getByRole('heading', { name: 'Public knowledge-base S3 source' })).toBeInTheDocument();
  });

  it('renders one policy list and opens metadata in the policy overview', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([
      buildPolicy({
        policyId: 'AGCF-AWS-013', name: 'Sensitive-data agent lacks PII guardrail',
        conditionalCapabilitiesJson: '["MACIE_CLASSIFICATION"]',
        frameworkMappingsJson: JSON.stringify([{ framework: 'OWASP_GENAI_LLM_TOP_10', frameworkVersion: '2026', controlId: 'LLM02', mappingType: 'DIRECT', rationale: 'PII guardrail reduces sensitive disclosure.' }]),
      }),
      buildPolicy({ policyId: 'AGCF-AZR-001', name: 'Azure public network access', provider: 'AZURE' }),
    ]);
    vi.spyOn(api, 'getAiGridPolicyDetail').mockResolvedValue({
      id: 'AGCF-AWS-013', version: '1.0.0', name: 'Sensitive-data agent lacks PII guardrail', severity: 'CRITICAL',
      artifactTypes: [], requiredResourceFamilies: [], description: 'Require a PII guardrail.',
      remediation: 'Attach a PII guardrail.', controlMappings: {}, available: true, enabled: true,
      lifecycle: 'PUBLISHED',
      openFindings: 0, lifetimeFindings: 0, lastEvaluatedAt: null, decisionCoverage: 1, decisionCoverageThreshold: 1,
      decisionCoverageStatus: 'PASS', evaluatedArtifacts: 1, noDecisionCount: 0,
    });
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    renderPoliciesPage();

    await screen.findByText('Sensitive-data agent lacks PII guardrail');
    // Policies from all providers share one table; provider is shown in its column.
    expect(screen.queryByRole('heading', { name: 'AWS policies' })).not.toBeInTheDocument();
    // Nine policy columns plus five framework-coverage and nine telemetry columns.
    expect(screen.getAllByRole('columnheader')).toHaveLength(14);
    expect(screen.getByRole('checkbox', { name: 'Select Sensitive-data agent lacks PII guardrail' })).toBeInTheDocument();
    // A conditional-capability policy is flagged, but metadata is no longer inline.
    expect(screen.getByText(/needs capability/)).toBeInTheDocument();
    expect(screen.queryByText('Required connector capabilities')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Sensitive-data agent lacks PII guardrail').closest('tr')!);

    expect(await screen.findByText('Required connector capabilities')).toBeInTheDocument();
    expect(screen.getByText('DIRECT')).toBeInTheDocument();
    expect(screen.getByText('PII guardrail reduces sensitive disclosure.')).toBeInTheDocument();
  });

  it('shows customer-facing assessment states without treating out-of-scope subjects as unknown', async () => {
    vi.mocked(api.getLatestAiGridAssessmentStates).mockResolvedValue([{
      policyId: 'AGCF-AWS-001', policyVersion: '1.0.0', pass: 1, fail: 0, unknown: 0, notAssessed: 2,
    }]);
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([buildPolicy()]);
    renderPoliciesPage();

    expect(await screen.findByText('Pass 1')).toBeInTheDocument();
    expect(screen.getByText('Not assessed 2')).toBeInTheDocument();
    expect(screen.queryByText(/Unknown 2/)).not.toBeInTheDocument();
  });

  it('does not request or show runtime telemetry readiness', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([buildPolicy()]);
    renderPoliciesPage();
    await screen.findByText(buildPolicy().name);
    expect(api.getAiRuntimeTelemetryReadiness).not.toHaveBeenCalled();
    expect(screen.queryByText('Runtime telemetry gate')).not.toBeInTheDocument();
  });

  it('turns internal framework blocker codes into customer-readable explanations', async () => {
    vi.mocked(api.getAiFrameworkCoverage).mockResolvedValue({
      framework: 'OWASP_GENAI_LLM_TOP_10', frameworkVersion: '2026', coverageEpochId: 'epoch-1', runId: 'run-1',
      tenantSchemaReady: true, blockers: [],
      controls: [{
        controlId: 'LLM01', name: 'Prompt Injection', coverageStatus: 'NOT_ASSESSED',
        mappedPolicies: 1, distributedPolicies: 1, selectedPolicies: 1, previewPolicies: 0,
        previewDecisionReadyPolicies: 0, effectivePolicies: 0, applicableCount: 10, decisionReadyCount: 0,
        blockers: ['assessment:9a8d8d7c-6b5a-4e3f-8d7c-6b5a4e3f8d7c', 'capability:FOUNDRY_DEPLOYMENTS_RAI:MISSING'],
        mappings: [],
      }],
      legacyCompatibility: { policies: 21, distributed: 21, required: 13, enabled: 0, preview: 8 },
    });
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([buildPolicy()]);
    renderPoliciesPage();

    expect(await screen.findByText(/mapped policy has not yet produced decision-ready assessment evidence/i)).toBeInTheDocument();
    expect(screen.getByText(/required connector data is unavailable: azure ai foundry deployment and responsible-ai policy data/i)).toBeInTheDocument();
    expect(screen.queryByText(/assessment:9a8d8d7c/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/capability:FOUNDRY_DEPLOYMENTS_RAI:MISSING/i)).not.toBeInTheDocument();
  });

  it('filters rows by severity pill and by search text', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([
      buildPolicy(),
      buildPolicy({ policyId: 'AGCF-AZR-001', name: 'Unauthenticated action-group Lambda URL', severity: 'HIGH', provider: 'AZURE' }),
    ]);
    renderPoliciesPage();

    expect(await screen.findByText('Public knowledge-base S3 source')).toBeInTheDocument();
    expect(screen.getByText('Unauthenticated action-group Lambda URL')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'High' }));
    expect(screen.queryByText('Public knowledge-base S3 source')).not.toBeInTheDocument();
    expect(screen.getByText('Unauthenticated action-group Lambda URL')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'All' }));
    fireEvent.change(screen.getByPlaceholderText('Search policies'), { target: { value: 'knowledge-base' } });
    expect(screen.getByText('Public knowledge-base S3 source')).toBeInTheDocument();
    expect(screen.queryByText('Unauthenticated action-group Lambda URL')).not.toBeInTheDocument();
  });
});
