import { useQuery } from '@tanstack/react-query';
import { Background, Controls, Handle, Position, ReactFlow, ReactFlowProvider } from '@xyflow/react';
import React from 'react';
import { api } from '../../api/client';
import { formatLabel } from '../cve-workbench/formatting';
import { layoutDependencyGraph, type DependencyGraphNodeData } from './graph-layout';
import type { AiSecurityArtifact, AiSecurityGraph, AiSecurityPolicy } from './types';

const ARTIFACT_TYPE_ICON: Record<string, string> = {
  AI_AGENT: '🤖',
  AI_AGENT_VERSION: '🧬',
  AI_PROMPT: '📝',
  AI_TOOL: '🛠️',
  AI_COMPONENT: '🧩',
  AI_MODEL: '🧠',
  OTHER_AI_ARTIFACT: '📦',
};

function formatTimestamp(value?: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatPiiStatus(artifact: AiSecurityArtifact): string {
  switch (artifact.piiScanStatus) {
    case 'NOT_APPLICABLE':
      return 'Not applicable';
    case 'NOT_SCANNED':
      return 'Not scanned';
    case 'SCANNED_CLEAN':
      return 'No PII found';
    case 'SCANNED_PII_FOUND':
      return `${artifact.piiFindingCount} finding${artifact.piiFindingCount === 1 ? '' : 's'}`
        + (artifact.piiInfoTypes.length > 0 ? ` (${artifact.piiInfoTypes.join(', ')})` : '');
    case 'LOOKUP_FAILED':
      return 'Lookup failed';
    default:
      return 'Not available';
  }
}

function countCriticalPolicyFailures(
  controls: { policyId: string; decision: string }[],
  policies: AiSecurityPolicy[],
): number {
  const severityByPolicyId = new Map(policies.map((policy) => [policy.id, policy.severity.toUpperCase()]));
  return controls.filter(
    (control) => control.decision === 'FAIL' && severityByPolicyId.get(control.policyId) === 'CRITICAL',
  ).length;
}

type GraphNodeDetailsPopupProps = {
  artifact: AiSecurityArtifact;
  isRoot: boolean;
  findingsCount: number;
  policies: AiSecurityPolicy[];
  onViewDetails: (artifactId: string) => void;
  onDismiss: () => void;
};

function GraphNodeDetailsPopup({ artifact, isRoot, findingsCount, policies, onViewDetails, onDismiss }: GraphNodeDetailsPopupProps) {
  const popupRef = React.useRef<HTMLDivElement>(null);
  // Non-modal: move focus in so keyboard and screen-reader users land on the details; Escape returns.
  React.useEffect(() => {
    popupRef.current?.focus();
  }, [artifact.id]);
  const postureQuery = useQuery({
    queryKey: ['ai-security-graph-node-posture', artifact.id],
    queryFn: () => api.getAiAssetPosture(artifact.id),
  });
  const criticalPoliciesFailed = postureQuery.data
    ? countCriticalPolicyFailures(postureQuery.data.controls, policies)
    : null;

  return (
    <div
      ref={popupRef}
      className="ai-dependency-graph-popup"
      role="dialog"
      aria-label={`${artifact.name} details`}
      tabIndex={-1}
      onKeyDown={(event) => {
        if (event.key === 'Escape') onDismiss();
      }}
    >
      <div className="ai-dependency-graph-popup-header">
        <span aria-hidden="true">{ARTIFACT_TYPE_ICON[artifact.artifactType] ?? '📦'}</span>
        <div className="ai-dependency-graph-popup-title">
          <strong>{artifact.name}</strong>
          <small>{formatLabel(artifact.artifactType)}</small>
        </div>
      </div>
      <dl className="ai-dependency-graph-popup-facts">
        <dt>Native type</dt><dd>{formatLabel(artifact.nativeKind)}</dd>
        <dt>Status</dt>
        <dd>
          <span className={`ai-dependency-graph-popup-status ${artifact.active ? 'is-active' : 'is-inactive'}`}>
            <span aria-hidden="true">{artifact.active ? '🟢' : '⚪'}</span>
            {artifact.active ? 'Active' : 'Inactive'}
          </span>
        </dd>
        <dt>Findings</dt><dd>{findingsCount}</dd>
        <dt>Criticality</dt><dd>{artifact.businessCriticality ? formatLabel(artifact.businessCriticality) : 'Not classified'}</dd>
        <dt>PII</dt><dd>{formatPiiStatus(artifact)}</dd>
        <dt>Critical policies failed</dt>
        <dd>{postureQuery.isLoading ? '…' : postureQuery.isError ? '—' : criticalPoliciesFailed}</dd>
        <dt>Last observed</dt><dd>{formatTimestamp(artifact.lastObservedAt)}</dd>
      </dl>
      <button
        type="button"
        className="btn btn-primary btn-sm ai-dependency-graph-popup-cta"
        disabled={isRoot}
        onClick={() => onViewDetails(artifact.id)}
      >
        {isRoot ? 'Currently viewing this asset' : 'View Details'}
      </button>
    </div>
  );
}

function AiArtifactNode({ data }: { data: DependencyGraphNodeData }) {
  const classes = ['ai-dependency-graph-node'];
  if (data.isRoot) classes.push('ai-dependency-graph-node--root');
  if (!data.active) classes.push('ai-dependency-graph-node--inactive');
  return (
    <div className={classes.join(' ')}>
      <Handle type="target" position={Position.Left} />
      <span aria-hidden="true">{ARTIFACT_TYPE_ICON[data.artifactType] ?? '📦'}</span>
      <div className="ai-dependency-graph-node-text">
        <strong>{data.label}</strong>
        <small>{formatLabel(data.nativeKind)}</small>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const NODE_TYPES = { aiArtifact: AiArtifactNode };

// Readable alternative to the canvas: every edge as a row, with the same destination as View Details.
function RelationshipList({ graph, rootArtifactId, onNodeClick }: {
  graph: AiSecurityGraph;
  rootArtifactId?: string;
  onNodeClick?: (artifactId: string) => void;
}) {
  const namesById = new Map(graph.nodes.map((node) => [node.id, node.name]));
  const endpoint = (artifactId: string, fallbackName: string) => {
    const name = namesById.get(artifactId) ?? fallbackName;
    if (artifactId === rootArtifactId) return <span>{name} <span className="panel-caption">(this asset)</span></span>;
    if (!onNodeClick) return <span>{name}</span>;
    return <button type="button" className="btn-link" onClick={() => onNodeClick(artifactId)}>{name}</button>;
  };
  if (graph.edges.length === 0) {
    return <div className="empty-state" role="status"><p>No relationships observed.</p></div>;
  }
  return (
    <div className="table-scroll ai-dependency-graph-list">
      <table className="data-table">
        <caption className="ui2-sr-only">AI artifact relationships</caption>
        <thead>
          <tr><th scope="col">From</th><th scope="col">Relationship</th><th scope="col">To</th></tr>
        </thead>
        <tbody>
          {graph.edges.map((edge) => (
            <tr key={edge.id}>
              <td>{endpoint(edge.sourceArtifactId, edge.sourceName)}</td>
              <td>{formatLabel(edge.relationshipType)}</td>
              <td>{endpoint(edge.targetArtifactId, edge.targetName)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type AiDependencyGraphProps = {
  graph: AiSecurityGraph;
  rootArtifactId?: string;
  onNodeClick?: (artifactId: string) => void;
  findingsCountByArtifactId?: Record<string, number>;
  policies?: AiSecurityPolicy[];
};

export function AiDependencyGraph({
  graph,
  rootArtifactId,
  onNodeClick,
  findingsCountByArtifactId = {},
  policies = [],
}: AiDependencyGraphProps) {
  const { nodes, edges } = React.useMemo(
    () => layoutDependencyGraph(graph, rootArtifactId),
    [graph, rootArtifactId],
  );
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [selectedArtifactId, setSelectedArtifactId] = React.useState<string | null>(null);
  const [view, setView] = React.useState<'graph' | 'list'>('graph');
  const selectedArtifact = React.useMemo(
    () => graph.nodes.find((node) => node.id === selectedArtifactId) ?? null,
    [graph.nodes, selectedArtifactId],
  );

  // React Flow nodes are focusable and Enter/Space selects them, but only a click reaches
  // onNodeClick; open the same details popup from the keyboard.
  const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const target = event.target as HTMLElement;
    if (!target.classList.contains('react-flow__node') || !target.dataset.id) return;
    event.preventDefault();
    setSelectedArtifactId(target.dataset.id);
  };
  const dismissPopup = () => {
    const nodeId = selectedArtifactId;
    setSelectedArtifactId(null);
    const nodes = containerRef.current?.querySelectorAll<HTMLElement>('.react-flow__node') ?? [];
    Array.from(nodes).find((node) => node.dataset.id === nodeId)?.focus();
  };

  return (
    <div className="ai-dependency-graph-view">
      <div className="ai-dependency-graph-toolbar" role="group" aria-label="Relationship view">
        <button type="button" className="btn btn-secondary btn-sm" aria-pressed={view === 'graph'} onClick={() => setView('graph')}>
          Graph
        </button>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          aria-pressed={view === 'list'}
          onClick={() => {
            setSelectedArtifactId(null);
            setView('list');
          }}
        >
          List
        </button>
      </div>
      {view === 'list' ? (
        <RelationshipList graph={graph} rootArtifactId={rootArtifactId} onNodeClick={onNodeClick} />
      ) : (
        <div
          ref={containerRef}
          className="ai-dependency-graph"
          role="region"
          aria-label="AI artifact dependency graph"
          onKeyDown={handleKeyDown}
        >
          <ReactFlowProvider>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={NODE_TYPES}
              fitView
              nodesDraggable={false}
              nodesConnectable={false}
              onNodeClick={(_event, node) => setSelectedArtifactId(node.id)}
              onPaneClick={() => setSelectedArtifactId(null)}
              proOptions={{ hideAttribution: true }}
            >
              <Background />
              <Controls showInteractive={false} />
            </ReactFlow>
          </ReactFlowProvider>
          {selectedArtifact && (
            <GraphNodeDetailsPopup
              artifact={selectedArtifact}
              isRoot={selectedArtifact.id === rootArtifactId}
              findingsCount={findingsCountByArtifactId[selectedArtifact.id] ?? 0}
              policies={policies}
              onDismiss={dismissPopup}
              onViewDetails={(artifactId) => {
                setSelectedArtifactId(null);
                onNodeClick?.(artifactId);
              }}
            />
          )}
        </div>
      )}
      {graph.truncated && <p className="panel-caption">Graph capped for safe rendering.</p>}
    </div>
  );
}
