import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { pathForCbomComponent } from '../../app/routes';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { titleCase } from './labels';
import type { CbomGraphNode } from './types';

const SIZE = 320;
const CENTER = SIZE / 2;
const RING = 46;

/** Radial blast-radius picture: the component at the centre, rings by distance; the lists below are its text equivalent. */
function layout(nodes: CbomGraphNode[]): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  const rings = new Map<number, CbomGraphNode[]>();
  nodes.forEach((node) => rings.set(node.distance, [...(rings.get(node.distance) ?? []), node]));
  rings.forEach((ring, distance) => ring.forEach((node, index) => {
    const angle = (2 * Math.PI * index) / Math.max(1, ring.length);
    positions.set(node.id, distance === 0 ? { x: CENTER, y: CENTER }
      : { x: CENTER + distance * RING * Math.cos(angle), y: CENTER + distance * RING * Math.sin(angle) });
  }));
  return positions;
}

/** A component node links to its CBOM component page (except the one being viewed); other nodes are plain text. */
function NodeName({ node, fallback, returnTo }: { node?: CbomGraphNode; fallback: string; returnTo?: string }) {
  if (!node) return <>{fallback}</>;
  const label = node.label ?? fallback;
  if (node.type !== 'COMPONENT' || node.distance === 0) return <>{label}</>;
  return <Link to={pathForCbomComponent(node.id, returnTo)}>{label}</Link>;
}

export function CbomBlastRadius({ componentId, returnTo }: { componentId: string; returnTo?: string }) {
  const query = useQuery({ queryKey: ['cbom-blast-radius', componentId], queryFn: () => api.getCbomBlastRadius(componentId) });
  const radius = query.data;
  const positions = radius ? layout(radius.graph.nodes) : new Map();
  const severities = radius ? Object.entries(radius.openFindingsBySeverity) : [];

  return (
    <AsyncSection state={query.isPending ? 'pending' : query.isError ? 'error' : 'ready'} loadingLabel="Loading blast radius…"
      errorMessage="The blast radius could not be loaded." onRetry={() => void query.refetch()} retryLabel="Retry blast radius">
      {radius && (
        <div className="cbom-blast-radius">
          <p>
            Within {radius.graph.depth} relationship hops this asset reaches {radius.applications.length} application
            {radius.applications.length === 1 ? '' : 's'} and {radius.affectedComponents} cryptographic asset{radius.affectedComponents === 1 ? '' : 's'}
            {' '}with {radius.openFindings} open finding{radius.openFindings === 1 ? '' : 's'}
            {severities.length > 0 ? ` (${severities.map(([severity, count]) => `${titleCase(severity)} ${count}`).join(', ')})` : ''}.
            {radius.graph.truncated ? ' The graph was truncated at 500 nodes.' : ''}
          </p>
          <svg className="cbom-blast-radius-graph" viewBox={`0 0 ${SIZE} ${SIZE}`} role="img"
            aria-label={`Blast radius graph with ${radius.graph.nodes.length} nodes and ${radius.graph.edges.length} relationships; listed below`}>
            {radius.graph.edges.map((edge) => {
              const from = positions.get(edge.sourceId);
              const to = positions.get(edge.targetId);
              return from && to ? (
                <line key={edge.id} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                  className={edge.stale ? 'cbom-graph-edge cbom-graph-edge--stale' : 'cbom-graph-edge'} />
              ) : null;
            })}
            {radius.graph.nodes.map((node) => {
              const point = positions.get(node.id);
              if (!point) return null;
              const tone = node.type === 'ASSET' ? 'application' : node.highestSeverity ? node.highestSeverity.toLowerCase() : 'none';
              return <circle key={node.id} cx={point.x} cy={point.y} r={node.distance === 0 ? 9 : 6} className={`cbom-graph-node cbom-graph-node--${tone}`} />;
            })}
          </svg>
          <h4>Applications reached</h4>
          {radius.applications.length === 0 ? <p className="panel-caption">No application relationship is declared.</p> : (
            <ul>{radius.applications.map((app) => (
              <li key={app.assetId}>{app.name ?? app.assetId}{app.environment ? ` (${app.environment})` : ''} · {app.distance} hop{app.distance === 1 ? '' : 's'}</li>
            ))}</ul>
          )}
          <h4>Relationships</h4>
          <ul>
            {radius.graph.edges.slice(0, 50).map((edge) => {
              const source = radius.graph.nodes.find((node) => node.id === edge.sourceId);
              const target = radius.graph.nodes.find((node) => node.id === edge.targetId);
              return (
                <li key={edge.id}>
                  <NodeName node={source} fallback={edge.sourceType} returnTo={returnTo} />
                  {' '}{titleCase(edge.relationshipType).toLowerCase()}{' '}
                  <NodeName node={target} fallback={edge.targetType} returnTo={returnTo} />
                  {edge.stale ? ' (stale evidence)' : ''}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </AsyncSection>
  );
}
