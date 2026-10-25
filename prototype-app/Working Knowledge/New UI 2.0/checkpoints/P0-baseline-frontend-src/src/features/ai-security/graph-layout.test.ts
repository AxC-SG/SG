import { describe, expect, it } from 'vitest';
import { layoutDependencyGraph } from './graph-layout';
import type { AiSecurityArtifact, AiSecurityGraph, AiSecurityRelationship } from './types';

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

function buildEdge(overrides: Partial<AiSecurityRelationship> = {}): AiSecurityRelationship {
  return {
    id: 'edge-1',
    relationshipType: 'IMPLEMENTED_BY',
    sourceArtifactId: 'artifact-1',
    sourceName: 'depth-agent',
    targetArtifactId: 'artifact-2',
    targetName: 'depth-fn',
    attributes: {},
    ...overrides,
  };
}

describe('layoutDependencyGraph', () => {
  it('positions every node and marks the requested root', () => {
    const graph: AiSecurityGraph = {
      nodes: [buildNode(), buildNode({ id: 'artifact-2', name: 'depth-fn' })],
      edges: [buildEdge()],
      truncated: false,
    };

    const { nodes } = layoutDependencyGraph(graph, 'artifact-1');

    expect(nodes).toHaveLength(2);
    const root = nodes.find((node) => node.id === 'artifact-1');
    const child = nodes.find((node) => node.id === 'artifact-2');
    expect(root?.data.isRoot).toBe(true);
    expect(child?.data.isRoot).toBe(false);
    expect(root?.position).toEqual(expect.objectContaining({ x: expect.any(Number), y: expect.any(Number) }));
    expect(child?.position).not.toEqual(root?.position);
  });

  it('formats relationship types into readable edge labels', () => {
    const graph: AiSecurityGraph = {
      nodes: [buildNode(), buildNode({ id: 'artifact-2', name: 'depth-fn' })],
      edges: [buildEdge({ relationshipType: 'IMPLEMENTED_BY' })],
      truncated: false,
    };

    const { edges } = layoutDependencyGraph(graph);

    expect(edges).toEqual([
      expect.objectContaining({ id: 'edge-1', source: 'artifact-1', target: 'artifact-2', label: 'IMPLEMENTED BY' }),
    ]);
  });

  it('drops edges that reference a node outside the returned node set', () => {
    const graph: AiSecurityGraph = {
      nodes: [buildNode()],
      edges: [buildEdge()],
      truncated: false,
    };

    const { nodes, edges } = layoutDependencyGraph(graph);

    expect(nodes).toHaveLength(1);
    expect(edges).toHaveLength(1);
    expect(Number.isFinite(nodes[0]?.position.x)).toBe(true);
    expect(Number.isFinite(nodes[0]?.position.y)).toBe(true);
  });

  it('returns no nodes or edges for an empty graph', () => {
    const graph: AiSecurityGraph = { nodes: [], edges: [], truncated: false };
    expect(layoutDependencyGraph(graph)).toEqual({ nodes: [], edges: [] });
  });

  it('ignores historical runtime overlays', () => {
    const graph: AiSecurityGraph = {
      nodes: [buildNode(), buildNode({ id: 'artifact-2', name: 'runtime-tool', artifactType: 'AI_TOOL' })],
      edges: [], truncated: false,
      runtimeOverlay: {
        status: 'AVAILABLE', diagnostic: null, windowStart: '2026-09-10T00:00:00Z', windowEnd: '2026-09-17T00:00:00Z',
        executionCount: 3, resolvedCount: 3, unresolvedCount: 0, notApplicableCount: 0, truncated: false,
        groups: [{ id: 'runtime-aggregate:abc', provider: 'AZURE', source: 'AZURE_FOUNDRY_RUNTIME', agentArtifactId: 'artifact-1', agentVersionArtifactId: null,
          executionCount: 3, successCount: 2, failureCount: 1, unknownCount: 0, resolvedCount: 3, unresolvedCount: 0, notApplicableCount: 0,
          firstEvidenceTime: '2026-09-16T00:00:00Z', lastEvidenceTime: '2026-09-17T00:00:00Z' }],
        edges: [
          { id: 'runtime-edge:executed', relationshipType: 'EXECUTED_AS', runtimeGroupId: 'runtime-aggregate:abc', artifactId: 'artifact-1', participantRole: null, executionCount: 3, firstEvidenceTime: '2026-09-16T00:00:00Z', lastEvidenceTime: '2026-09-17T00:00:00Z' },
          { id: 'runtime-edge:tool', relationshipType: 'PARTICIPATED_IN', runtimeGroupId: 'runtime-aggregate:abc', artifactId: 'artifact-2', participantRole: 'TOOL', executionCount: 2, firstEvidenceTime: '2026-09-16T00:00:00Z', lastEvidenceTime: '2026-09-17T00:00:00Z' },
        ],
      },
    };
    const layout = layoutDependencyGraph(graph, 'artifact-1');
    expect(layout.nodes).toHaveLength(2);
    expect(layout.nodes.every(node => node.data.nodeKind === 'ARTIFACT')).toBe(true);
    expect(layout.edges).toEqual([]);
  });
});
