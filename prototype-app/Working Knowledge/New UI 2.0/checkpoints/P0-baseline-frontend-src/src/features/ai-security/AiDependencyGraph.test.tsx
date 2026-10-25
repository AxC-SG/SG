import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { AiDependencyGraph } from './AiDependencyGraph';
import { mockElementDimensionsForReactFlow } from './test-support';
import type { AiSecurityArtifact, AiSecurityGraph, AiSecurityPolicy } from './types';

function buildNode(overrides: Partial<AiSecurityArtifact> = {}): AiSecurityArtifact {
  return {
    id: 'artifact-1',
    provider: 'AWS',
    providerResourceId: 'arn:aws:bedrock:us-east-1:123456789012:agent/depth-agent',
    artifactType: 'AI_AGENT',
    nativeKind: 'AWS_BEDROCK_AGENT',
    name: 'depth-agent',
    accountId: '123456789012',
    region: 'us-east-1',
    active: true,
    attributes: {},
    ownerName: null,
    ownerState: 'UNOWNED',
    ownerSource: null,
    ownerConfidence: null,
    ownerConfidenceMethod: null,
    ownerConfidenceMethodVersion: null,
    businessCriticality: null,
    environment: null,
    firstObservedAt: '2026-08-01T00:00:00Z',
    lastObservedAt: '2026-08-01T00:00:00Z',
    piiScanStatus: 'NOT_APPLICABLE',
    piiSource: null,
    piiInfoTypes: [],
    piiFindingCount: 0,
    piiLastScannedAt: null,
    attachmentState: 'ROOT',
    systemIds: [],
    ...overrides,
  };
}

function buildGraph(overrides: Partial<AiSecurityGraph> = {}): AiSecurityGraph {
  return {
    nodes: [
      buildNode(),
      buildNode({ id: 'artifact-2', name: 'depth-fn', artifactType: 'OTHER_AI_ARTIFACT', nativeKind: 'AWS_LAMBDA_FUNCTION' }),
    ],
    edges: [{
      id: 'edge-1',
      relationshipType: 'IMPLEMENTED_BY',
      sourceArtifactId: 'artifact-1',
      sourceName: 'depth-agent',
      targetArtifactId: 'artifact-2',
      targetName: 'depth-fn',
      attributes: {},
    }],
    truncated: false,
    ...overrides,
  };
}

describe('AiDependencyGraph', () => {
  beforeEach(() => {
    mockElementDimensionsForReactFlow();
    vi.spyOn(api, 'getAiAssetPosture').mockResolvedValue({ artifactId: 'artifact-2', controls: [], exposures: [] });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders every node in the graph', async () => {
    renderWithProviders(<AiDependencyGraph graph={buildGraph()} rootArtifactId="artifact-1" />);
    expect(await screen.findByText('depth-agent')).toBeInTheDocument();
    expect(await screen.findByText('depth-fn')).toBeInTheDocument();
  });

  it('opens a details popup with key facts when a node is clicked, without account/region/owner or a close button', async () => {
    renderWithProviders(
      <AiDependencyGraph
        graph={buildGraph()}
        rootArtifactId="artifact-1"
        findingsCountByArtifactId={{ 'artifact-2': 3 }}
      />,
    );

    fireEvent.click(await screen.findByText('depth-fn'));

    expect(await screen.findByRole('dialog', { name: 'depth-fn details' })).toBeInTheDocument();
    expect(screen.getByText('AWS_LAMBDA_FUNCTION')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('Not classified')).toBeInTheDocument();
    expect(screen.getByText('Not applicable')).toBeInTheDocument();
    expect(await screen.findByText('0')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View Details' })).toBeInTheDocument();

    expect(screen.queryByText('Account')).not.toBeInTheDocument();
    expect(screen.queryByText('Region')).not.toBeInTheDocument();
    expect(screen.queryByText('Owner')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /close/i })).not.toBeInTheDocument();
  });

  it('shows the finding count and info types when the artifact has PII findings', async () => {
    const graph = buildGraph({
      nodes: [
        buildNode(),
        buildNode({
          id: 'artifact-2',
          name: 'depth-fn',
          artifactType: 'OTHER_AI_ARTIFACT',
          nativeKind: 'AWS_LAMBDA_FUNCTION',
          piiScanStatus: 'SCANNED_PII_FOUND',
          piiSource: 'AWS_MACIE',
          piiInfoTypes: ['EMAIL_ADDRESS', 'NAME'],
          piiFindingCount: 2,
          piiLastScannedAt: '2026-08-01T00:00:00Z',
        }),
      ],
    });
    renderWithProviders(<AiDependencyGraph graph={graph} rootArtifactId="artifact-1" />);

    fireEvent.click(await screen.findByText('depth-fn'));
    expect(await screen.findByText('2 findings (EMAIL_ADDRESS, NAME)')).toBeInTheDocument();
  });

  it('counts only failed CRITICAL-severity policies for the selected node', async () => {
    vi.spyOn(api, 'getAiAssetPosture').mockResolvedValue({
      artifactId: 'artifact-2',
      controls: [
        { policyId: 'policy-critical', selection: 'ENABLED', evidenceReadiness: 'READY', decision: 'FAIL', missingEvidenceJson: '{}' },
        { policyId: 'policy-high', selection: 'ENABLED', evidenceReadiness: 'READY', decision: 'FAIL', missingEvidenceJson: '{}' },
        { policyId: 'policy-critical-passing', selection: 'ENABLED', evidenceReadiness: 'READY', decision: 'PASS', missingEvidenceJson: '{}' },
      ],
      exposures: [],
    });
    const policies = [
      { id: 'policy-critical', severity: 'CRITICAL' },
      { id: 'policy-high', severity: 'HIGH' },
      { id: 'policy-critical-passing', severity: 'CRITICAL' },
    ] as AiSecurityPolicy[];

    renderWithProviders(<AiDependencyGraph graph={buildGraph()} rootArtifactId="artifact-1" policies={policies} />);

    fireEvent.click(await screen.findByText('depth-fn'));
    expect(await screen.findByText('1')).toBeInTheDocument();
  });

  it('calls onNodeClick with the artifact id only after View Details is clicked', async () => {
    const onNodeClick = vi.fn();
    renderWithProviders(<AiDependencyGraph graph={buildGraph()} rootArtifactId="artifact-1" onNodeClick={onNodeClick} />);

    fireEvent.click(await screen.findByText('depth-fn'));
    expect(onNodeClick).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'View Details' }));
    expect(onNodeClick).toHaveBeenCalledWith('artifact-2');
  });

  it('disables View Details for the root node', async () => {
    renderWithProviders(<AiDependencyGraph graph={buildGraph()} rootArtifactId="artifact-1" />);

    fireEvent.click(await screen.findByText('depth-agent'));
    expect(screen.getByRole('button', { name: 'Currently viewing this asset' })).toBeDisabled();
  });

  it('closes the popup when the canvas background is clicked', async () => {
    const { container } = renderWithProviders(<AiDependencyGraph graph={buildGraph()} rootArtifactId="artifact-1" />);

    fireEvent.click(await screen.findByText('depth-fn'));
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    fireEvent.click(container.querySelector('.react-flow__pane')!);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('shows a truncation notice when the graph was capped', async () => {
    renderWithProviders(<AiDependencyGraph graph={buildGraph({ truncated: true })} rootArtifactId="artifact-1" />);
    expect(await screen.findByText('Graph capped for safe rendering.')).toBeInTheDocument();
  });

  it('does not show runtime controls', () => {
    renderWithProviders(<AiDependencyGraph graph={{ nodes: [], edges: [], truncated: false }} />);
    expect(screen.queryByText('View executions')).not.toBeInTheDocument();
  });
});
