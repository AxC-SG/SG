import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  api,
  type BomDetail,
  type BomInventoryItem,
  type BomLineageItem,
  type BomWorkflowSummary,
} from '../api/client';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import { timeAgo } from '../lib/time';

function BomTypeTag({ bomType }: { bomType: string }) {
  const labels: Record<string, string> = {
    SBOM: 'SBOM',
    AI_BOM: 'AI BOM',
    CBOM: 'CBOM',
    VENDOR: 'Vendor',
  };
  return <span className={`status-badge status-badge--${bomType.toLowerCase().replace('_', '-')}`}>{labels[bomType] ?? bomType}</span>;
}

function StatusTag({ status }: { status: string }) {
  const cls = status === 'ACTIVE' ? 'active' : status === 'SUPERSEDED' ? 'suppressed' : 'inactive';
  return <span className={`status-badge status-badge--${cls}`}>{status}</span>;
}

function WorkflowTag({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  const cls = normalized === 'resolved'
    ? 'active'
    : normalized === 'remediation_open'
      ? 'danger'
      : normalized === 'patch_available' || normalized === 'under_investigation'
        ? 'warning'
        : normalized === 'correlated'
          ? 'active'
          : normalized === 'discovered'
            ? 'pending'
            : 'inactive';
  return <span className={`status-badge status-badge--${cls}`}>{status.replace(/_/g, ' ')}</span>;
}

function SupportTag({ supportLevel, supported }: { supportLevel?: string; supported?: boolean }) {
  const normalized = (supportLevel ?? '').toLowerCase();
  const cls = !supported
    ? 'danger'
    : normalized === 'current'
      ? 'active'
      : normalized === 'previous' || normalized === 'vendor_defined'
        ? 'warning'
        : normalized === 'legacy'
          ? 'pending'
          : 'inactive';
  return <span className={`status-badge status-badge--${cls}`}>{supportLevel ?? 'unknown'}</span>;
}

function WorkflowSummaryChips({ items }: { items: BomWorkflowSummary[] }) {
  if (items.length === 0) {
    return <div className="panel-caption">No workflow states recorded yet.</div>;
  }
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {items.map((item) => (
        <span key={item.workflowStatus} className="tag">
          {item.workflowStatus.replace(/_/g, ' ')} · {item.componentCount}
        </span>
      ))}
    </div>
  );
}

function LineagePanel({ items }: { items: BomLineageItem[] }) {
  return (
    <div className="panel bom-detail-meta">
      <div className="panel-header">
        <h4>Document Lineage</h4>
        <span className="panel-caption">{items.length} records in history</span>
      </div>
      {items.length === 0 ? (
        <div className="panel-caption">No previous or superseded BOM revisions recorded.</div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Spec</th>
                <th>Source</th>
                <th>Components</th>
                <th>Checksum</th>
                <th>Ingested</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td><StatusTag status={item.status} /></td>
                  <td>{item.specFamily} {item.formatVersion} · {item.documentFormat}</td>
                  <td>
                    <div>{item.sourceSystem ?? item.sourceType ?? '—'}</div>
                    <div className="panel-caption">{item.sourceReference ?? '—'}</div>
                  </td>
                  <td>{item.componentCount}</td>
                  <td className="monospace cell-truncate">{item.checksumSha256 ?? '—'}</td>
                  <td>{timeAgo(item.ingestedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function BomDetailPanel({ bomId, onClose }: { bomId: string; onClose: () => void }) {
  const detailQuery = useQuery({
    queryKey: ['bom-detail', bomId],
    queryFn: () => api.getBomDetail(bomId),
  });
  const lineageQuery = useQuery({
    queryKey: ['bom-lineage', bomId],
    queryFn: () => api.getBomLineage(bomId),
  });

  const queryClient = useQueryClient();
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteBom(bomId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['bom-inventory'] });
      void queryClient.invalidateQueries({ queryKey: ['bom-dashboard'] });
      onClose();
    },
  });

  const detail: BomDetail | undefined = detailQuery.data;
  const latestDataUpdate = latestFreshnessValue([
    detailQuery.dataUpdatedAt,
    lineageQuery.dataUpdatedAt,
    detail?.ingestedAt,
  ]);
  const detailRefreshing = (detailQuery.isFetching || lineageQuery.isFetching) && (!!detail || Boolean(lineageQuery.data));

  return (
    <div className="bom-detail-panel">
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={detailRefreshing}
        refreshLabel="Refreshing BOM detail while keeping current context visible…"
      />

      <div className="bom-detail-header">
        <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>
          ← Back
        </button>
        {detail && (
          <button
            type="button"
            className="btn btn-danger btn-sm"
            disabled={deleteMutation.isPending}
            onClick={() => {
              if (window.confirm('Remove this BOM record and all its linked components? This cannot be undone.')) {
                deleteMutation.mutate();
              }
            }}
          >
            {deleteMutation.isPending ? 'Removing…' : 'Remove'}
          </button>
        )}
      </div>

      {detailQuery.isPending && <p className="loading-text">Loading…</p>}
      {detailQuery.isError && <p className="form-error">{(detailQuery.error as Error).message}</p>}
      {lineageQuery.isError && <p className="form-error">{(lineageQuery.error as Error).message}</p>}
      {deleteMutation.isError && <p className="form-error">{(deleteMutation.error as Error).message}</p>}

      {detail && (
        <>
          {/* ── Identity header ─────────────────────────────────────────── */}
          <div className="panel" style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <BomTypeTag bomType={detail.bomType} />
                <StatusTag status={detail.status} />
                <SupportTag supportLevel={detail.supportLevel} supported={detail.supported} />
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span className="panel-caption" style={{ fontSize: 12 }}>
                  {detail.format} {detail.formatVersion} · {detail.specFamily} · {detail.documentFormat}
                </span>
              </div>
            </div>

            {detail.serialNumber && (
              <div style={{ marginTop: 12, padding: '8px 12px', background: 'var(--panel-muted)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <span className="panel-caption" style={{ fontSize: 11, display: 'block', marginBottom: 2 }}>SERIAL NUMBER</span>
                <code style={{ fontSize: 12, wordBreak: 'break-all' }}>{detail.serialNumber}</code>
              </div>
            )}

            {detail.checksumSha256 && (
              <div style={{ marginTop: 8, padding: '8px 12px', background: 'var(--panel-muted)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <span className="panel-caption" style={{ fontSize: 11, display: 'block', marginBottom: 2 }}>SHA-256 CHECKSUM</span>
                <code style={{ fontSize: 11, wordBreak: 'break-all', color: 'var(--text-secondary)' }}>{detail.checksumSha256}</code>
              </div>
            )}
          </div>

          {/* ── Stat tiles ───────────────────────────────────────────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 10, marginBottom: 12 }}>
            {[
              { label: 'Components', value: detail.componentCount },
              { label: 'Correlated', value: detail.correlatedComponentCount },
              { label: 'Vuln Links', value: detail.vulnerabilityLinkCount },
              { label: 'Evidence', value: detail.evidenceCount },
            ].map(({ label, value }) => (
              <div key={label} className="panel" style={{ padding: '14px 16px', textAlign: 'center' }}>
                <div style={{ fontSize: 26, fontWeight: 700, lineHeight: 1 }}>{value}</div>
                <div className="panel-caption" style={{ marginTop: 4, fontSize: 11 }}>{label}</div>
              </div>
            ))}
          </div>

          {/* ── Document + Source info ────────────────────────────────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12, marginBottom: 12 }}>
            <div className="panel">
              <div className="panel-header" style={{ marginBottom: 12 }}>
                <h4 style={{ margin: 0 }}>Document</h4>
              </div>
              <div style={{ display: 'grid', gap: 10 }}>
                {[
                  { label: 'Supplier', value: detail.supplier ?? '—' },
                  { label: 'Ingested', value: timeAgo(detail.ingestedAt) },
                  { label: 'Ingested by', value: detail.ingestedBy ?? '—' },
                ].map(({ label, value }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 8, paddingBottom: 8, borderBottom: '1px solid var(--border)' }}>
                    <span className="panel-caption" style={{ fontSize: 12, flexShrink: 0 }}>{label}</span>
                    <span style={{ fontSize: 13, fontWeight: 500, textAlign: 'right' }}>{value}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="panel-header" style={{ marginBottom: 12 }}>
                <h4 style={{ margin: 0 }}>Source</h4>
              </div>
              <div style={{ display: 'grid', gap: 10 }}>
                {[
                  { label: 'Method', value: detail.sourceMethod ?? '—' },
                  { label: 'Type', value: detail.sourceType ?? '—' },
                  { label: 'System', value: detail.sourceSystem ?? '—' },
                  { label: 'Reference', value: detail.sourceReference ?? '—', mono: true },
                ].map(({ label, value, mono }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 8, paddingBottom: 8, borderBottom: '1px solid var(--border)' }}>
                    <span className="panel-caption" style={{ fontSize: 12, flexShrink: 0 }}>{label}</span>
                    <span style={{ fontSize: 13, fontWeight: 500, textAlign: 'right', fontFamily: mono ? 'monospace' : undefined, wordBreak: 'break-all' }}>{value}</span>
                  </div>
                ))}
                {detail.sourceUrl && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 8 }}>
                    <span className="panel-caption" style={{ fontSize: 12, flexShrink: 0 }}>URL</span>
                    <span style={{ fontSize: 12, textAlign: 'right', wordBreak: 'break-all', color: 'var(--accent)' }}>{detail.sourceUrl}</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ── Support Inspection ────────────────────────────────────────── */}
          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="panel-header" style={{ marginBottom: 12 }}>
              <h4 style={{ margin: 0 }}>Support Inspection</h4>
              <SupportTag supportLevel={detail.inspection?.supportLevel} supported={detail.inspection?.supported} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 12 }}>
              {[
                { label: 'Parser Format', value: detail.inspection?.format ?? detail.format },
                { label: 'Spec Family', value: detail.inspection?.specFamily ?? detail.specFamily },
                { label: 'Document Format', value: detail.inspection?.documentFormat ?? detail.documentFormat },
              ].map(({ label, value }) => (
                <div key={label} style={{ padding: '10px 14px', background: 'var(--panel-muted)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div className="panel-caption" style={{ fontSize: 11, marginBottom: 4 }}>{label.toUpperCase()}</div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{value}</div>
                </div>
              ))}
            </div>
            {detail.inspection?.warnings?.length ? (
              <div style={{ marginTop: 12, display: 'grid', gap: 8 }}>
                {detail.inspection.warnings.map((warning) => (
                  <div key={warning} className="notice error">{warning}</div>
                ))}
              </div>
            ) : (
              <div className="panel-caption" style={{ marginTop: 12 }}>This BOM is within the validated parser support matrix.</div>
            )}
          </div>

          {/* ── Workflow Summary ─────────────────────────────────────────── */}
          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="panel-header" style={{ marginBottom: 12 }}>
              <h4 style={{ margin: 0 }}>Workflow Summary</h4>
            </div>
            <WorkflowSummaryChips items={detail.workflowSummary} />
          </div>

          <LineagePanel items={lineageQuery.data ?? []} />

          <div className="panel bom-components-panel">
            <div className="panel-header">
              <h4>Components ({detail.componentCount.toLocaleString()})</h4>
              <span className="panel-caption">
                {detail.correlatedComponentCount} with vulnerability links · {detail.vulnerabilityLinkCount} CVE links · {detail.components.length} shown
              </span>
            </div>
            {detail.components.length === 0 ? (
              <div className="empty-state"><p>No components recorded.</p></div>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Version</th>
                      <th>Category</th>
                      <th>Workflow</th>
                      <th>Vulns</th>
                      <th>Evidence</th>
                      <th>Type</th>
                      <th>PURL</th>
                      <th>CPE</th>
                      <th>License</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.components.map((c) => (
                      <tr key={c.id} className={c.active ? '' : 'row--inactive'}>
                        <td>{c.name}</td>
                        <td>{c.version ?? '—'}</td>
                        <td><span className="tag">{c.category}</span></td>
                        <td><WorkflowTag status={c.workflowStatus} /></td>
                        <td>{c.vulnerabilityCount}</td>
                        <td>{c.evidenceCount}</td>
                        <td>{c.componentType ?? '—'}</td>
                        <td className="monospace cell-truncate">{c.purl ?? '—'}</td>
                        <td className="monospace cell-truncate">{c.cpe ?? '—'}</td>
                        <td>{c.license ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function parseGithubOwnerRepo(sourceUrl?: string): { owner: string; repo: string } | null {
  if (!sourceUrl) return null;
  const match = sourceUrl.match(/github\.com\/repos\/([^/]+)\/([^/]+)/);
  if (match) return { owner: match[1], repo: match[2] };
  return null;
}

function OnDemandPanel({ items, onRunTriggered }: {
  items: BomInventoryItem[];
  onRunTriggered: () => void;
}) {
  const [running, setRunning] = React.useState<Set<string>>(new Set());

  const githubGroups = React.useMemo(() => {
    const groups: Map<string, { parsed: { owner: string; repo: string }; count: number }> = new Map();
    for (const item of items) {
      if (item.sourceType !== 'GITHUB_REPO') continue;
      const parsed = parseGithubOwnerRepo(item.sourceUrl ?? undefined);
      if (!parsed) continue;
      const key = `${parsed.owner}/${parsed.repo}`;
      const existing = groups.get(key);
      if (existing) {
        existing.count += 1;
      } else {
        groups.set(key, { parsed, count: 1 });
      }
    }
    return [...groups.entries()].map(([key, v]) => ({ key, ...v }));
  }, [items]);

  if (githubGroups.length === 0) return null;

  function handleRun(key: string, parsed: { owner: string; repo: string }) {
    setRunning((prev) => new Set(prev).add(key));
    api.queueGithubRepositoryRun({ owner: parsed.owner, repo: parsed.repo })
      .catch(() => {/* best-effort */})
      .finally(() => {
        setRunning((prev) => {
          const next = new Set(prev);
          next.delete(key);
          return next;
        });
        onRunTriggered();
      });
  }

  return (
    <div className="panel" style={{ marginBottom: 20 }}>
      <div className="panel-header">
        <div>
          <h4 style={{ margin: 0 }}>On-Demand Ingestion</h4>
          <span className="panel-caption">
            Trigger BOM ingestion immediately for a specific GitHub repository
          </span>
        </div>
      </div>
      <div style={{ display: 'grid', gap: 10 }}>
        {githubGroups.map(({ key, parsed, count }) => (
          <div key={key} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 14px', borderRadius: 8,
            background: 'var(--panel-muted)', border: '1px solid var(--border)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontSize: 18 }}>⬡</span>
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{key}</div>
                <div className="panel-caption" style={{ fontSize: 11 }}>
                  {count} BOM document{count > 1 ? 's' : ''} · GitHub repository
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {running.has(key) && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--accent)' }}>
                  <span style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}>↻</span>
                  Running…
                </span>
              )}
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={running.has(key)}
                onClick={() => handleRun(key, parsed)}
              >
                ▶ Run now
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function BomInventoryPage() {
  const [selectedBomId, setSelectedBomId] = React.useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = React.useState<string | null>(null);
  const [typeFilter, setTypeFilter] = React.useState('');
  const [page, setPage] = React.useState(0);

  const queryClient = useQueryClient();

  const dashboardQuery = useQuery({
    queryKey: ['bom-dashboard'],
    queryFn: () => api.getBomDashboard(),
  });
  const inventoryQuery = useQuery({
    queryKey: ['bom-inventory', page],
    queryFn: () => api.listBomInventory(page, 50),
  });

  const deleteMutation = useMutation({
    mutationFn: (bomId: string) => api.deleteBom(bomId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['bom-inventory'] });
      void queryClient.invalidateQueries({ queryKey: ['bom-dashboard'] });
      setConfirmDelete(null);
    },
  });

  const allItems: BomInventoryItem[] = inventoryQuery.data ?? [];
  const filtered = typeFilter ? allItems.filter((r) => r.bomType === typeFilter) : allItems;
  const summary = dashboardQuery.data;
  const latestDataUpdate = React.useMemo(() => latestFreshnessValue([
    dashboardQuery.dataUpdatedAt,
    inventoryQuery.dataUpdatedAt
  ]), [
    dashboardQuery.dataUpdatedAt,
    inventoryQuery.dataUpdatedAt
  ]);
  const refreshing = (dashboardQuery.isFetching || inventoryQuery.isFetching) && (allItems.length > 0 || Boolean(summary));

  if (selectedBomId) {
    return (
      <BomDetailPanel
        bomId={selectedBomId}
        onClose={() => setSelectedBomId(null)}
      />
    );
  }

  return (
    <div className="bom-inventory-page">
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={refreshing}
        refreshLabel="Refreshing BOM inventory while keeping current results visible…"
      />

      {/* Delete confirmation modal */}
      {confirmDelete && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 999,
          background: 'rgba(0,0,0,0.45)', display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <div className="panel" style={{ padding: 28, maxWidth: 420, width: '90%' }}>
            <h4 style={{ marginBottom: 10 }}>Remove BOM record?</h4>
            <p className="panel-caption" style={{ marginBottom: 20 }}>
              This will remove the BOM record and all linked components. This cannot be undone.
            </p>
            {deleteMutation.isError && (
              <p className="form-error" style={{ marginBottom: 12 }}>
                {(deleteMutation.error as Error).message}
              </p>
            )}
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button type="button" className="btn btn-ghost" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                disabled={deleteMutation.isPending}
                onClick={() => deleteMutation.mutate(confirmDelete)}
              >
                {deleteMutation.isPending ? 'Removing…' : 'Remove'}
              </button>
            </div>
          </div>
        </div>
      )}

      {!inventoryQuery.isPending && allItems.length > 0 && summary && (
        <div style={{ display: 'grid', gap: 16, marginBottom: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 12 }}>
            {[
              ['BOM documents', summary.documentCount],
              ['Components', summary.componentCount],
              ['Components with CVE links', summary.correlatedComponentCount],
              ['Component–CVE links', summary.vulnerabilityLinkCount],
              ['Source systems', summary.sourceSystemCount],
            ].map(([label, value]) => (
              <div key={label} className="panel" style={{ padding: 16 }}>
                <div className="panel-caption" style={{ marginBottom: 6 }}>{label}</div>
                <div style={{ fontSize: 28, fontWeight: 700 }}>{Number(value).toLocaleString()}</div>
              </div>
            ))}
          </div>
          <p className="panel-caption" style={{ margin: 0 }}>
            Totals cover all active BOM types. The type filter changes the table only. CVE links are matching evidence;
            findings are created after applicability, source, and policy checks.
          </p>
        </div>
      )}

      {inventoryQuery.isPending && <p className="loading-text">Loading…</p>}
      {inventoryQuery.isError && (
        <p className="form-error">{(inventoryQuery.error as Error).message}</p>
      )}

      {!inventoryQuery.isPending && allItems.length === 0 && (
        <div className="empty-state">
          <p>No BOM records ingested yet. Use the BOM Ingestion connector to get started.</p>
        </div>
      )}

      {allItems.length > 0 && (
        <>
          <OnDemandPanel
            items={allItems}
            onRunTriggered={() => {
              void queryClient.invalidateQueries({ queryKey: ['bom-inventory'] });
            }}
          />

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>BOM Inventory</h3>
                <span className="panel-caption">All ingested BOM records — SBOM, AI BOM, CBOM, and Vendor BOMs</span>
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <select className="filter-input" style={{ width: 'auto' }} value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}>
                  <option value="">All BOM types</option>
                  <option value="SBOM">SBOM</option>
                  <option value="AI_BOM">AI BOM</option>
                  <option value="CBOM">CBOM</option>
                  <option value="VENDOR">Vendor</option>
                </select>
              </div>
            </div>

            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Supplier / Source</th>
                    <th>Format</th>
                    <th>Support</th>
                    <th>Components</th>
                    <th>Correlated</th>
                    <th>Vuln Links</th>
                    <th>Status</th>
                    <th>Ingested</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((item) => (
                    <tr key={item.id}>
                      <td><BomTypeTag bomType={item.bomType} /></td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{item.supplier ?? '—'}</div>
                        {item.sourceSystem && (
                          <div className="panel-caption" style={{ fontSize: 11 }}>
                            {item.sourceSystem === 'github' ? '⬡ ' : ''}{item.sourceSystem}
                          </div>
                        )}
                        <div className="panel-caption" style={{ fontSize: 11 }}>
                          <span className="tag" style={{ fontSize: 10 }}>{item.sourceMethod}</span>
                        </div>
                      </td>
                      <td>
                        <div>{item.format} {item.formatVersion}</div>
                        <div className="panel-caption" style={{ fontSize: 11 }}>{item.specFamily} · {item.documentFormat}</div>
                      </td>
                      <td><SupportTag supportLevel={item.supportLevel} supported={item.supported} /></td>
                      <td style={{ fontWeight: 600 }}>{item.componentCount}</td>
                      <td>{item.correlatedComponentCount}</td>
                      <td>{item.vulnerabilityLinkCount}</td>
                      <td><StatusTag status={item.status} /></td>
                      <td>{timeAgo(item.ingestedAt)}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            title="View BOM detail"
                            style={{ padding: '3px 8px', fontSize: 13 }}
                            onClick={() => setSelectedBomId(item.id)}
                          >
                            ⊞
                          </button>
                          <button
                            type="button"
                            title="Delete this BOM record"
                            style={{
                              padding: '3px 8px', fontSize: 13, cursor: 'pointer',
                              background: 'none', border: '1px solid var(--border)',
                              borderRadius: 6, color: 'var(--critical)',
                            }}
                            onClick={() => setConfirmDelete(item.id)}
                          >
                            ✕
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {filtered.length === 0 && (
              <div className="empty-state"><p>No BOM records match the current filter.</p></div>
            )}

            {allItems.length === 50 && (
              <div className="pagination-row">
                {page > 0 && (
                  <button type="button" className="btn btn-ghost btn-sm" onClick={() => setPage(page - 1)}>
                    Previous
                  </button>
                )}
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => setPage(page + 1)}>
                  Next
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
