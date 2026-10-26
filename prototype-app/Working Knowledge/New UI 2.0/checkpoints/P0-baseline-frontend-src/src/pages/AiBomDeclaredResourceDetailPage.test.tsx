import { screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiBomDeclaredResource, AiBomDeclaredResourceDetail, AiBomCorrelationEvidence } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { buildFinding } from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { AiBomDeclaredResourceDetailPage } from './AiBomDeclaredResourceDetailPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

const ANALYST_ACTOR: ActorContext = {
  creator: false,
  principal: 'analyst@example.com',
  userId: 'user-analyst',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_SECURITY_ANALYST'],
};

const TENANT_ADMIN_ACTOR: ActorContext = {
  ...ANALYST_ACTOR,
  principal: 'admin@example.com',
  userId: 'user-admin',
  roles: ['ROLE_TENANT_ADMIN'],
};

function renderAs(actor: ActorContext, ui: React.ReactElement) {
  return renderWithProviders(<ActorContextState.Provider value={actor}>{ui}</ActorContextState.Provider>);
}

function buildResource(overrides: Partial<AiBomDeclaredResource> = {}): AiBomDeclaredResource {
  return {
    id: 'resource-1',
    sourceId: 'source-1',
    bomId: 'bom-1',
    bomComponentId: 'component-1',
    resourceKind: 'MODEL',
    name: 'llama-3',
    version: '3.1',
    identityKind: 'VERSIONED_IDENTIFIER',
    identityValue: 'llama-3@3.1',
    deploymentState: 'UNVERIFIED',
    linkedArtifactId: null,
    linkMethod: null,
    linkReviewedBy: null,
    linkReviewedAt: null,
    proposedArtifactId: null,
    proposedBy: null,
    proposedAt: null,
    firstDeclaredAt: '2026-08-01T00:00:00Z',
    lastDeclaredAt: '2026-08-01T00:00:00Z',
    ...overrides,
  };
}

function buildDetail(overrides: Partial<AiBomDeclaredResourceDetail> = {}): AiBomDeclaredResourceDetail {
  return {
    resource: buildResource(),
    sourceBomType: 'AI_BOM',
    sourceState: 'ACTIVE',
    sourceRevision: 1,
    currentInLatestRevision: true,
    component: {
      componentId: 'component-1',
      name: 'llama-3',
      version: '3.1',
      purl: 'pkg:huggingface/llama-3@3.1',
      license: null,
      scope: null,
      componentType: 'machine-learning-model',
    },
    completeness: { completeness: 'PARTIAL', assertedBy: 'uploader@example.com', assertedAt: '2026-08-01T00:00:00Z' },
    projection: {
      provenanceProjected: true,
      provenanceProjectedAt: '2026-08-01T00:05:00Z',
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      latestReceiptOperation: 'PROVENANCE_PROJECTION',
      latestReceiptCompletedAt: '2026-08-01T00:05:00Z',
    },
    ...overrides,
  };
}

function evidence(overrides: Partial<AiBomCorrelationEvidence> = {}): AiBomCorrelationEvidence {
  return { paths: [], gaps: [], pathCount: 0, gapCount: 0, page: 0, size: 50, ...overrides };
}
function path(overrides: Partial<AiBomCorrelationEvidence['paths'][number]> = {}): AiBomCorrelationEvidence['paths'][number] {
  return { id: 'path-1', findingId: 'finding-1', status: 'ACTIVE', bomId: 'bom-1', sourceRevision: 1,
    components: [{ id: 'model', ref: 'model', name: 'model', version: '1' }, { id: 'framework', ref: 'framework', name: 'framework', version: '2' }, { id: 'lib', ref: 'lib', name: 'library', version: '3' }],
    relationshipIds: ['edge-1', 'edge-2'], terminalComponentId: 'inventory-1', matchMethod: 'PURL_VERSION',
    confirmedAt: '2026-10-13T00:00:00Z', retiredAt: null, retirementReason: null, uncertain: false, ...overrides };
}

describe('AiBomDeclaredResourceDetailPage', () => {
  beforeEach(() => { vi.spyOn(api, 'getAiBomCorrelationEvidence').mockResolvedValue(evidence()); });
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('renders declaration, source, component, and projection details', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail());
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);

    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    expect(await screen.findByText('UNVERIFIED')).toBeInTheDocument();
    expect(screen.getByText('CycloneDX')).toBeInTheDocument();
    expect(screen.getByText('pkg:huggingface/llama-3@3.1')).toBeInTheDocument();
  });

  it('lets an analyst propose a mapping', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail());
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    const propose = vi.spyOn(api, 'proposeAiBomMapping').mockResolvedValue(
      buildResource({ proposedArtifactId: 'artifact-9', proposedBy: 'user-analyst' }));

    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    const input = await screen.findByLabelText('Artifact ID to propose');
    fireEvent.change(input, { target: { value: 'artifact-9' } });
    fireEvent.click(screen.getByText('Propose mapping'));

    await waitFor(() => expect(propose).toHaveBeenCalledWith('resource-1', 'artifact-9'));
  });

  it('does not show approve controls to a plain analyst when a proposal is pending', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({
      resource: buildResource({ proposedArtifactId: 'artifact-9', proposedBy: 'user-analyst', proposedAt: '2026-08-02T00:00:00Z' }),
    }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);

    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    await screen.findByText('artifact-9');
    expect(screen.queryByText('Approve mapping')).not.toBeInTheDocument();
    expect(screen.getByText('Awaiting approval from an inventory admin or tenant admin.')).toBeInTheDocument();
  });

  it('lets a tenant admin approve a pending proposal', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({
      resource: buildResource({ proposedArtifactId: 'artifact-9', proposedBy: 'user-analyst', proposedAt: '2026-08-02T00:00:00Z' }),
    }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    const approve = vi.spyOn(api, 'approveAiBomMapping').mockResolvedValue(
      buildResource({ deploymentState: 'LINKED', linkedArtifactId: 'artifact-9', linkMethod: 'REVIEWED', linkReviewedBy: 'user-admin' }));

    renderAs(TENANT_ADMIN_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    fireEvent.click(await screen.findByText('Approve mapping'));

    await waitFor(() => expect(approve).toHaveBeenCalledWith('resource-1'));
  });

  it('renders findings affecting this resource', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail());
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([buildFinding({ id: 'finding-7', displayId: 'F-000007' })]);

    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    expect(await screen.findByText('F-000007')).toBeInTheDocument();
  });

  it('qualifies empty results without claiming a completed assessment', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({ correlation: evidence() }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);
    expect(await screen.findByText(/an empty list does not confirm absence of risk/)).toBeInTheDocument();
    expect(screen.getByText(/No supporting paths recorded yet/)).toBeInTheDocument();
  });

  it('shows ordered evidence and remediation for retained uncertain support', async () => {
    const gaps = ['VERSION_MISSING', 'IDENTITY_AMBIGUOUS', 'TRAVERSAL_LIMIT_REACHED'].map(reason => ({ id: reason, componentId: null, componentRef: 'lib', reason, remediation: `Remediate ${reason}`, sourceRevision: 1, detectedAt: '2026-10-13T00:00:00Z' }));
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({ correlation: evidence({ paths: [path({ uncertain: true })], gaps, pathCount: 1, gapCount: 3 }) }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);
    expect(await screen.findByText('model @ 1 → framework @ 2 → library @ 3')).toBeInTheDocument();
    expect(screen.getByText(/Support retained with uncertainty/)).toBeInTheDocument();
    gaps.forEach(gap => expect(screen.getByText(gap.reason)).toBeInTheDocument());
  });

  it('loads retired evidence only when history is selected', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({ correlation: evidence() }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    vi.mocked(api.getAiBomCorrelationEvidence).mockResolvedValue(evidence({ paths: [path({ status: 'RETIRED', retirementReason: 'SOURCE_SUPPORT_WITHDRAWN', retiredAt: '2026-10-13T00:00:00Z' })], pathCount: 1 }));
    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Retired history' }));
    expect(await screen.findByText(/SOURCE_SUPPORT_WITHDRAWN/)).toBeInTheDocument();
    expect(api.getAiBomCorrelationEvidence).toHaveBeenCalledWith('resource-1', true, 0);
  });

  it('shows evidence and finding load failures without rendering zero risk', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail());
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockRejectedValue(new Error('failed'));
    vi.mocked(api.getAiBomCorrelationEvidence).mockRejectedValue(new Error('failed'));
    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);
    expect(await screen.findByText('Dependency evidence could not be loaded.')).toBeInTheDocument();
    expect(await screen.findByText('Affected findings could not be loaded.')).toBeInTheDocument();
    expect(screen.queryByText(/an empty list does not confirm/)).not.toBeInTheDocument();
  });

  it('shows evidence loading and paginates without hiding gaps', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({ correlation: evidence({ pathCount: 51 }) }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    vi.mocked(api.getAiBomCorrelationEvidence).mockImplementation(() => new Promise(() => {}));
    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Next evidence' }));
    expect(await screen.findByText('Loading dependency evidence…')).toBeInTheDocument();
    expect(api.getAiBomCorrelationEvidence).toHaveBeenCalledWith('resource-1', false, 1);
  });

  it('qualifies legacy associations that have no backfilled paths', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({ correlation: evidence({ associationsWithoutPaths: [{ id: 'legacy', findingId: 'finding-1', status: 'ACTIVE', confirmedAt: null, retiredAt: null, retirementReason: null, lifecycleHistory: [] }], associationCount: 1 }) }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);
    expect(await screen.findByText(/Legacy association retained/)).toBeInTheDocument();
    expect(screen.queryByText(/No supporting paths recorded yet/)).not.toBeInTheDocument();
  });

  it('keeps lifecycle history visible after a path is reactivated', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({ correlation: evidence({ paths: [path({ lifecycleHistory: [{ status: 'RETIRED', at: '2026-10-13T00:00:00Z', revision: 2 }, { status: 'ACTIVE', at: '2026-10-13T01:00:00Z', revision: 3 }] })], pathCount: 1 }) }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);
    expect(await screen.findByText('Association history')).toBeInTheDocument();
    expect(screen.getByText(/RETIRED at/)).toBeInTheDocument();
    expect(screen.getByText(/ACTIVE at/)).toBeInTheDocument();
  });
});
