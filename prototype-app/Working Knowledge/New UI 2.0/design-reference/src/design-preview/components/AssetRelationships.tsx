import React from 'react';
import { Background, Controls, Handle, Position, ReactFlow, ReactFlowProvider, type Node, type NodeProps, type Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Bot, Database, Server, Wrench } from 'lucide-react';
import { Alert, EmptyState, Skeleton } from './feedback';

type Resource = { label: string; kind: string; tone: 'accent' | 'neutral'; source: string };
function ResourceNode({ data }: NodeProps<Node<Resource>>) {
  const Icon = data.kind === 'Agent' ? Bot : data.kind === 'Data store' ? Database : data.kind === 'Tool' ? Wrench : Server;
  return <div className={`dp-graph-node dp-graph-node--${data.tone}`} title={data.label}><Handle type="target" position={Position.Left} /><span className="dp-graph-icon"><Icon size={14} /></span><span className="dp-graph-copy"><strong>{data.label}</strong><small>{data.kind}</small></span><Handle type="source" position={Position.Right} /></div>;
}
const TYPES = { resource: ResourceNode };
const BASE: Node<Resource>[] = [
  { id: 'agent', type: 'resource', position: { x: 0, y: 120 }, data: { label: 'support-agent', kind: 'Agent', tone: 'accent', source: 'AWS Bedrock configuration' } },
  { id: 'model', type: 'resource', position: { x: 290, y: 0 }, data: { label: 'customer-support-model', kind: 'Model', tone: 'neutral', source: 'AWS Bedrock model reference' } },
  { id: 'tool', type: 'resource', position: { x: 290, y: 120 }, data: { label: 'refund-tool', kind: 'Tool', tone: 'neutral', source: 'Agent action group definition' } },
  { id: 'knowledge', type: 'resource', position: { x: 290, y: 240 }, data: { label: 'customer-support-knowledge', kind: 'Data store', tone: 'neutral', source: 'Knowledge base association' } },
  { id: 'identity', type: 'resource', position: { x: 580, y: 120 }, data: { label: 'arn:aws:iam::412938471023:role/production-refund-execution', kind: 'Identity', tone: 'neutral', source: 'Static IAM role reference' } },
];

export type GraphFixture = 'standard' | 'dense' | 'empty' | 'loading' | 'error';

// The graph API returns static references only; finding-linked edge styling is out of scope.
export function AssetRelationships({ fixture, selected, onSelect }: { fixture: GraphFixture; selected: string; onSelect: (resource: Resource & { id: string }) => void }) {
  const nodes = React.useMemo(() => fixture === 'dense' ? [...BASE, ...Array.from({ length: 12 }, (_, i): Node<Resource> => ({ id: `tool-${i}`, type: 'resource', position: { x: 870 + (i % 3) * 280, y: Math.floor(i / 3) * 110 }, data: { label: `production-customer-support-tool-${i + 1}`, kind: 'Tool', tone: 'neutral', source: 'Static tool definition' } }))] : BASE, [fixture]);
  const edges = React.useMemo((): Edge[] => [
    { id: 'invokes', source: 'agent', target: 'model', label: 'invokes' },
    { id: 'uses', source: 'agent', target: 'tool', label: 'uses' },
    { id: 'reads', source: 'agent', target: 'knowledge', label: 'reads' },
    { id: 'assumes', source: 'tool', target: 'identity', label: 'assumes' },
    ...(fixture === 'dense' ? Array.from({ length: 12 }, (_, i) => ({ id: `reference-${i}`, source: i < 3 ? 'agent' : `tool-${i - 3}`, target: `tool-${i}` })) : []),
  ], [fixture]);
  if (fixture === 'loading') return <div className="dp-graph dp-graph--empty" aria-busy="true"><div className="dp-stack"><Skeleton width={220} height={44} /><Skeleton width={220} height={44} /><span className="dp-muted">Loading connected resources…</span></div></div>;
  if (fixture === 'error') return <div className="dp-graph dp-graph--empty"><Alert tone="danger" title="Connected resources could not be loaded.">The rest of the asset detail is still available.</Alert></div>;
  if (fixture === 'empty') return <div className="dp-graph dp-graph--empty"><EmptyState icon={<Bot size={22} />} title="No active relationships observed">A discovered asset can exist without observed references. The graph does not infer connections.</EmptyState></div>;
  return <div className="dp-graph dp-asset-graph" role="region" aria-label="Static AI resource relationships"><ReactFlowProvider><ReactFlow key={fixture} nodes={nodes.map(node => ({ ...node, selected: node.id === selected }))} edges={edges} nodeTypes={TYPES} fitView minZoom={0.15} nodesDraggable={false} onNodeClick={(_, node) => onSelect({ id: node.id, ...node.data })}><Background gap={18} size={1} /><Controls showInteractive={false} /></ReactFlow></ReactFlowProvider></div>;
}
