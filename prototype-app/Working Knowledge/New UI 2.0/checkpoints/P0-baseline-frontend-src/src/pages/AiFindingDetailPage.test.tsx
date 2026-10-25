import { screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import type { AiSecurityArtifact, AiSecurityFinding, AiSecurityPolicy } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiFindingDetailPage } from './AiFindingDetailPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

const TENANT_ADMIN_ACTOR: ActorContext = {
  creator: false,
  principal: 'admin@example.com',
  userId: 'user-admin',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_TENANT_ADMIN'],
};

function renderAsTenantAdmin(ui: React.ReactElement, route?: string) {
  return renderWithProviders(
    <ActorContextState.Provider value={TENANT_ADMIN_ACTOR}>{ui}</ActorContextState.Provider>,
    route ? { route } : undefined,
  );
}

function buildFinding(overrides: Partial<AiSecurityFinding> = {}): AiSecurityFinding {
  return {
    id: 'finding-1',
    displayId: 'AIF-101B8AF0',
    policyId: 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER',
    policyVersion: '1.0.0',
    artifactId: 'artifact-1',
    artifactName: 'Guardrails73',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'Azure RAI policy contains a non-blocking filter',
    evidence: { facts: { state: 'KNOWN', value: true } },
    reviewDisposition: 'UNREVIEWED',
    firstObservedAt: '2026-08-04T15:22:15Z',
    lastObservedAt: '2026-08-05T15:22:15Z',
    resolvedAt: null,
    ...overrides,
  };
}

function buildPolicy(overrides: Partial<AiSecurityPolicy> = {}): AiSecurityPolicy {
  return {
    id: 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER',
    version: '1.0.0',
    name: 'Azure RAI policy contains a non-blocking filter',
    severity: 'HIGH',
    lifecycle: 'PUBLISHED',
    artifactTypes: ['OTHER_AI_ARTIFACT'],
    requiredResourceFamilies: ['AZURE_RAI_POLICIES'],
    description: 'A guardrail RAI policy filter is configured to annotate rather than block.',
    remediation: 'Set the filter mode to Block for the affected content categories.',
    controlMappings: {},
    available: true,
    enabled: true,
    openFindings: 1,
    lifetimeFindings: 1,
    lastEvaluatedAt: '2026-08-05T00:00:00Z',
    decisionCoverage: 1,
    decisionCoverageThreshold: 0.95,
    decisionCoverageStatus: 'PASS',
    evaluatedArtifacts: 1,
    noDecisionCount: 0,
    ...overrides,
  };
}

function buildArtifact(overrides: Partial<AiSecurityArtifact> = {}): AiSecurityArtifact {
  return {
    id: 'artifact-1',
    provider: 'AZURE',
    providerResourceId: '/subscriptions/abc/resourceGroups/rg/providers/microsoft.cognitiveservices/accounts/guardrails73',
    artifactType: 'OTHER_AI_ARTIFACT',
    nativeKind: 'AZURE_RAI_POLICY',
    name: 'Guardrails73',
    accountId: 'abc-123',
    region: 'eastus2',
    active: true,
    attributes: { kind: 'Guardrail' },
    firstObservedAt: '2026-08-04T00:00:00Z',
    lastObservedAt: '2026-08-05T00:00:00Z',
    ownerName: null,
    ownerState: 'UNOWNED',
    ownerSource: null,
    ownerConfidence: null,
    ownerConfidenceMethod: null,
    ownerConfidenceMethodVersion: null,
    businessCriticality: null,
    environment: null,
    piiScanStatus: 'NOT_APPLICABLE',
    piiSource: null,
    piiInfoTypes: [],
    piiFindingCount: 0,
    piiLastScannedAt: null,
    attachmentState: 'STANDALONE_OPTIONAL',
    systemIds: [],
    ...overrides,
  };
}

describe('AiFindingDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('renders finding identity and policy details on the Overview tab by default, with no evidence viewer', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockResolvedValue(buildFinding());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);

    renderWithProviders(<AiFindingDetailPage findingId="finding-1" />);

    expect(await screen.findByText('AIF-101B8AF0')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Overview' })).toHaveClass('fd3-tab--active');
    expect(screen.getAllByText('Azure RAI policy contains a non-blocking filter')).toHaveLength(2);
    expect(screen.getByText('Set the filter mode to Block for the affected content categories.')).toBeInTheDocument();
    expect(screen.queryByText(/"state": "KNOWN"/)).not.toBeInTheDocument();
    expect(screen.queryByText('Evidence')).not.toBeInTheDocument();
  });

  it('shows artifact details in the Artifact tab', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockResolvedValue(buildFinding());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());

    renderWithProviders(<AiFindingDetailPage findingId="finding-1" />);
    await screen.findByText('AIF-101B8AF0');

    fireEvent.click(screen.getByRole('button', { name: 'Artifact' }));
    expect(await screen.findByText('eastus2')).toBeInTheDocument();
    expect(screen.getByText('AZURE')).toBeInTheDocument();
  });

  it('submits a review disposition when an action button is clicked', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockResolvedValue(buildFinding());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    const review = vi.spyOn(api, 'reviewAiSecurityFinding').mockResolvedValue(buildFinding({ reviewDisposition: 'CONFIRMED' }));

    renderWithProviders(<AiFindingDetailPage findingId="finding-1" />);
    await screen.findByText('AIF-101B8AF0');

    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(review).toHaveBeenCalledWith('finding-1', 'CONFIRMED'));
  });

  it('navigates back to the AI findings list', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockResolvedValue(buildFinding());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);

    renderWithProviders(<AiFindingDetailPage findingId="finding-1" />);
    await screen.findByText('AIF-101B8AF0');

    fireEvent.click(screen.getByRole('button', { name: '← Back' }));
    expect(navigateMock).toHaveBeenCalledWith('/findings/ai');
  });

  it('shows a not-found state for an unknown finding', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockRejectedValue(new Error('not found'));
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([]);

    renderWithProviders(<AiFindingDetailPage findingId="does-not-exist" />);

    expect(await screen.findByText(/could not be found/)).toBeInTheDocument();
  });

  it('does not show Create Incident or Resolve for a user with no workflow roles', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockResolvedValue(buildFinding());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);

    renderWithProviders(<AiFindingDetailPage findingId="finding-1" />);
    await screen.findByText('AIF-101B8AF0');

    expect(screen.queryByRole('button', { name: '+ Create Incident' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Resolve' })).not.toBeInTheDocument();
  });

  it('resolves an open finding via the workflow endpoint for a tenant admin', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockResolvedValue(buildFinding({ status: 'OPEN' }));
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    const workflow = vi.spyOn(api, 'updateFindingWorkflow').mockResolvedValue({});

    renderAsTenantAdmin(<AiFindingDetailPage findingId="finding-1" />);
    await screen.findByText('AIF-101B8AF0');

    fireEvent.click(screen.getByRole('button', { name: 'Resolve' }));
    await waitFor(() => expect(workflow).toHaveBeenCalledWith(
      'finding-1',
      expect.objectContaining({ status: 'RESOLVED' }),
    ));
  });

  it('shows Re-open instead of Resolve once a finding is no longer open', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockResolvedValue(buildFinding({ status: 'RESOLVED' }));
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);

    renderAsTenantAdmin(<AiFindingDetailPage findingId="finding-1" />);
    await screen.findByText('AIF-101B8AF0');

    expect(screen.queryByRole('button', { name: 'Resolve' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Re-open' })).toBeInTheDocument();
  });

  it('creates a ServiceNow incident and shows the incident number on success', async () => {
    vi.spyOn(api, 'getAiSecurityFinding').mockResolvedValue(buildFinding());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    const createIncident = vi.spyOn(api, 'createFindingIncident').mockResolvedValue({
      incidentNumber: 'INC0012345',
      sysId: 'sys-1',
      url: 'https://example.service-now.com/inc/sys-1',
      status: 'created',
      message: 'Incident created',
    });

    renderAsTenantAdmin(<AiFindingDetailPage findingId="finding-1" />);
    await screen.findByText('AIF-101B8AF0');

    fireEvent.click(screen.getByRole('button', { name: '+ Create Incident' }));
    await waitFor(() => expect(createIncident).toHaveBeenCalledWith('finding-1', expect.objectContaining({
      findingTitle: 'Azure RAI policy contains a non-blocking filter',
      severity: 'HIGH',
    })));
    expect(await screen.findByText(/INC0012345/)).toBeInTheDocument();
  });
});
