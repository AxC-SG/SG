import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { pathForInventoryAiAsset } from '../app/routes';
import { PageFreshnessStatus } from '../components/PageFreshnessStatus';
import type { AiProvider, AiSecurityArtifact } from '../features/ai-security/types';
import { InventoryShell } from '../features/inventory/InventoryShell';

type InventoryKind = 'knowledge-data' | 'mcp';

function attribute(item: AiSecurityArtifact, key: string): string {
  const value = item.attributes[key];
  return value == null || value === '' ? 'Unknown' : String(value);
}

function sensitivityLabel(value: string): string {
  if (value === 'SCANNED_PII_FOUND') return 'Sensitive confirmed';
  if (value === 'SCANNED_CLEAN') return 'No sensitive signal';
  if (value === 'NOT_SCANNED') return 'Not scanned';
  if (value === 'NOT_APPLICABLE') return 'Not applicable';
  return 'Unknown';
}

export function AiKnowledgeMcpInventoryPage({ kind }: { kind: InventoryKind }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const [provider, setProvider] = React.useState<'' | AiProvider>('');
  const [active, setActive] = React.useState<'ALL' | 'true' | 'false'>('ALL');
  const [artifactRole, setArtifactRole] = React.useState(searchParams.get('artifactRole') ?? '');
  const [postureFilter, setPostureFilter] = React.useState('');
  const [secondaryFilter, setSecondaryFilter] = React.useState('');
  const [tertiaryFilter, setTertiaryFilter] = React.useState('');
  const [page, setPage] = React.useState(0);
  const pageSize = 50;
  const query = useQuery({
    queryKey: ['ai-inventory', kind, provider, active, artifactRole, postureFilter, secondaryFilter, tertiaryFilter, page],
    queryFn: () => kind === 'knowledge-data'
      ? api.listAiKnowledgeDataInventory(page, pageSize, provider || undefined, artifactRole || undefined, secondaryFilter || undefined, postureFilter || undefined, tertiaryFilter || undefined,
        active === 'ALL' ? undefined : active === 'true')
      : api.listAiMcpInventory(page, pageSize, provider || undefined, artifactRole || undefined, postureFilter || undefined, secondaryFilter || undefined, tertiaryFilter || undefined,
        active === 'ALL' ? undefined : active === 'true'),
  });
  const summaryQuery = useQuery({ queryKey: ['ai-security-summary'], queryFn: api.getAiSecuritySummary });
  const items = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const isKnowledge = kind === 'knowledge-data';

  React.useEffect(() => {
    setArtifactRole(searchParams.get('artifactRole') ?? '');
    setPage(0);
  }, [kind, searchParams]);

  return (
    <InventoryShell
      eyebrow="AWS and Azure AI estate"
      title={isKnowledge ? 'Knowledge & Data' : 'MCP Inventory'}
      description={isKnowledge
        ? 'Provider-observed knowledge bases, data sources, backing stores, and search indexes.'
        : 'Provider-configured MCP gateways, targets, and servers. Endpoints are never invoked.'}
      legacyClassName="ai-security-page"
    >
      <PageFreshnessStatus updatedAt={summaryQuery.data?.lastCompleteSnapshotAt} />
      <div className="inventory-fpl-toolbar">
        <label className="findings-filter-chip"><span className="panel-caption">Provider</span>
          <select value={provider} onChange={(event) => setProvider(event.target.value as '' | AiProvider)}>
            <option value="">All providers</option><option value="AWS">AWS</option><option value="AZURE">Azure</option><option value="MICROSOFT_COPILOT">Microsoft Copilot</option>
          </select>
        </label>
        <label className="findings-filter-chip"><span className="panel-caption">{isKnowledge ? 'Artifact kind' : 'MCP role'}</span>
          <select value={artifactRole} onChange={(event) => { setArtifactRole(event.target.value); setPage(0); }}>
            <option value="">All</option>
            {isKnowledge ? <><option value="KNOWLEDGE_BASE">Knowledge base</option><option value="DATA_SOURCE">Data source</option><option value="DATA_STORE">Data store</option><option value="SEARCH_INDEX">Search index</option></>
              : <><option value="MCP_GATEWAY">Gateway</option><option value="MCP_TARGET">Target</option><option value="MCP_SERVER">Server</option></>}
          </select>
        </label>
        <label className="findings-filter-chip"><span className="panel-caption">{isKnowledge ? 'Sensitivity' : 'Authentication'}</span>
          <select value={postureFilter} onChange={(event) => { setPostureFilter(event.target.value); setPage(0); }}>
            <option value="">All</option>
            {isKnowledge ? <><option value="SCANNED_PII_FOUND">Sensitive confirmed</option><option value="SCANNED_CLEAN">No sensitive signal</option><option value="NOT_SCANNED">Not scanned</option><option value="UNKNOWN">Unknown</option><option value="LOOKUP_FAILED">Lookup failed</option></>
              : <><option value="PROJECT_CONNECTION">Project connection</option><option value="CUSTOM_HEADER">Custom header</option><option value="MANAGED_IDENTITY">Managed identity</option><option value="OAUTH">OAuth</option><option value="NONE">None</option><option value="UNKNOWN">Unknown</option></>}
          </select>
        </label>
        <label className="findings-filter-chip"><span className="panel-caption">{isKnowledge ? 'Source type' : 'Endpoint exposure'}</span>
          <select value={secondaryFilter} onChange={(event) => { setSecondaryFilter(event.target.value); setPage(0); }}>
            <option value="">All</option>
            {isKnowledge ? <><option value="S3">S3</option><option value="WEB">Web</option><option value="CONFLUENCE">Confluence</option><option value="SALESFORCE">Salesforce</option><option value="SHAREPOINT">SharePoint</option><option value="UNKNOWN">Unknown</option></>
              : <><option value="PUBLIC_NETWORK_REACHABLE">Publicly reachable</option><option value="EXTERNAL_ENDPOINT">External endpoint</option><option value="UNKNOWN">Unknown</option></>}
          </select>
        </label>
        <label className="findings-filter-chip"><span className="panel-caption">{isKnowledge ? 'Public content' : 'Synchronization status'}</span>
          <select value={tertiaryFilter} onChange={(event) => { setTertiaryFilter(event.target.value); setPage(0); }}>
            <option value="">All</option>
            {isKnowledge ? <><option value="true">Confirmed public</option><option value="false">Not public</option></>
              : <><option value="FAILED">Failed</option><option value="UPDATE_UNSUCCESSFUL">Update unsuccessful</option><option value="SYNCHRONIZE_UNSUCCESSFUL">Synchronization unsuccessful</option></>}
          </select>
        </label>
        <label className="findings-filter-chip"><span className="panel-caption">State</span>
          <select value={active} onChange={(event) => setActive(event.target.value as 'ALL' | 'true' | 'false')}>
            <option value="ALL">All</option><option value="true">Active</option><option value="false">Inactive</option>
          </select>
        </label>
      </div>
      {query.isLoading ? <section className="panel"><div className="empty-state"><p>Loading inventory…</p></div></section>
        : query.isError ? <section className="panel"><div className="notice error">Inventory could not be loaded.</div></section>
          : items.length === 0 ? <section className="ai-security-empty"><div className="ai-security-empty-mark">AI</div>
            <h3>No {isKnowledge ? 'knowledge or data' : 'MCP'} artifacts discovered</h3>
            <p>Unsupported and incomplete provider coverage remains visible in the discovery run history.</p>
          </section>
            : <section className="panel ai-security-table-panel"><div className="panel-header"><p className="panel-caption">{items.length} of {total} artifacts shown</p></div><table className="data-table"><thead><tr>
              <th>Name</th><th>Type</th><th>Provider</th><th>{isKnowledge ? 'Posture' : 'Endpoint / authentication'}</th><th>Observed</th>
            </tr></thead><tbody>{items.map((item) => <tr key={item.id} onClick={() => navigate(pathForInventoryAiAsset(item.id, `${location.pathname}${location.search}`))}>
              <td><strong>{item.name}</strong></td><td>{item.artifactType.replace(/_/g, ' ')}</td><td>{item.provider}</td>
              <td>{isKnowledge ? `${attribute(item, 'sourceType')} · ${sensitivityLabel(item.piiScanStatus)}`
                : `${attribute(item, 'endpointHost')} · ${attribute(item, 'configuredAuthType') !== 'Unknown' ? attribute(item, 'configuredAuthType') : attribute(item, 'inboundAuthType')}`}</td>
              <td>{new Date(item.lastObservedAt).toLocaleString()}</td>
            </tr>)}</tbody></table><div className="pagination-row"><button type="button" className="btn btn-secondary" disabled={page === 0 || query.isFetching} onClick={() => setPage((value) => value - 1)}>Previous</button><span className="panel-caption pagination-caption">Page {page + 1} of {Math.max(1, Math.ceil(total / pageSize))}</span><button type="button" className="btn btn-secondary" disabled={query.isFetching || (page + 1) * pageSize >= total} onClick={() => setPage((value) => value + 1)}>Next</button></div></section>}
    </InventoryShell>
  );
}
