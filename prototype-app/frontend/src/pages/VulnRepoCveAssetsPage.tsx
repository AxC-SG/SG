import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { pathForFindingDetail, pathForVulnRepoView, pathForVulnRepoHostAsset } from '../app/routes';
import { buildAssetRowsFromMatchedSoftware } from '../features/cve-workbench/asset-report';
import {
  loadPersistedInvestigationRunbookState,
  buildPersistedInvestigationSoftwareRows,
} from '../features/cve-workbench/investigation-context';
import { useCveDetailQuery } from '../features/cve-workbench/queries';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { useFindingsQuery } from '../features/findings/queries';
import type { Finding } from '../features/findings/types';
import type { ExistingFindingBehavior, FindingCreationMode } from '../features/cve-workbench/types';
import { ownershipAssignedTo, ownershipSupportGroup } from '../features/cve-workbench/vendor-helpers';
import { useActor } from '../features/auth/context';

const PRIORITY_COLORS: Record<string, { bg: string; color: string; border: string }> = {
  CRITICAL: { bg: '#9b233522', color: '#9b2335', border: '#9b233544' },
  HIGH:     { bg: '#c5303022', color: '#c53030', border: '#c5303044' },
  MEDIUM:   { bg: '#b7791f22', color: '#b7791f', border: '#b7791f44' },
  LOW:      { bg: '#2d6a4f22', color: '#2d6a4f', border: '#2d6a4f44' },
};

const INPUT_STYLE: React.CSSProperties = {
  width: '100%', fontSize: 12, padding: '3px 6px',
  background: 'var(--input-bg, var(--panel-muted))',
  border: '1px solid var(--border)', borderRadius: 4,
  color: 'var(--text)', outline: 'none',
};

const TH_STYLE: React.CSSProperties = {
  padding: '8px 10px', textAlign: 'left',
  fontWeight: 600, color: 'var(--muted)',
  fontSize: 11, letterSpacing: '0.06em',
  whiteSpace: 'nowrap',
};

function PriorityBadge({ priority }: { priority: string }) {
  const label = priority.toUpperCase();
  const style = PRIORITY_COLORS[label];
  if (!style) return <span style={{ color: 'var(--muted)' }}>—</span>;
  return (
    <span style={{
      display: 'inline-block', padding: '2px 10px', borderRadius: 12,
      fontSize: 11, fontWeight: 700, letterSpacing: '0.04em',
      background: style.bg, color: style.color, border: `1px solid ${style.border}`,
    }}>
      {label}
    </span>
  );
}

export function VulnRepoCveAssetsPage() {
  const navigate = useNavigate();
  const actor = useActor();
  const params = useParams<{ cveId?: string }>();
  const cveId = params.cveId ?? null;

  const detailQuery = useCveDetailQuery(cveId);
  const findingsQuery = useFindingsQuery({ vulnerabilityId: cveId ?? '', size: 1000 });

  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(new Set());
  const [creating, setCreating] = React.useState(false);
  const [createMsg, setCreateMsg] = React.useState<string | null>(null);

  // Finding Configuration modal state
  const [showConfigModal, setShowConfigModal] = React.useState(false);
  const [cfgCreationMode, setCfgCreationMode] = React.useState<FindingCreationMode>('ASSET_CVE');
  const [cfgTitle, setCfgTitle] = React.useState('');
  const [cfgPriority, setCfgPriority] = React.useState('Medium');
  const [cfgDueDate, setCfgDueDate] = React.useState('');
  const [cfgTags, setCfgTags] = React.useState('');
  const [cfgAssignment, setCfgAssignment] = React.useState('Assign to lead analyst');
  const [cfgServiceNow, setCfgServiceNow] = React.useState(false);
  const [cfgNotes, setCfgNotes] = React.useState('');
  const [existingFindingBehavior, setExistingFindingBehavior] = React.useState<ExistingFindingBehavior>('ADD_TO_EXISTING');

  const [filterAsset, setFilterAsset] = React.useState('');
  const [filterFinding, setFilterFinding] = React.useState('');
  const [filterSoftware, setFilterSoftware] = React.useState('');
  const [filterFalsePositive, setFilterFalsePositive] = React.useState('All');
  const [filterSupportGroup, setFilterSupportGroup] = React.useState('');
  const [filterPriority, setFilterPriority] = React.useState('All');

  // Load investigation assets from localStorage
  const persistedRunbookState = React.useMemo(
    () => (cveId ? loadPersistedInvestigationRunbookState(cveId) : null),
    [cveId],
  );

  const severity = detailQuery.data?.summary.severity ?? 'Unknown';

  const allAssetRows = React.useMemo(() => {
    const backendRows = buildAssetRowsFromMatchedSoftware(
      (detailQuery.data?.matchedSoftware ?? []).filter((sw) => sw.assetId != null),
      severity,
    );
    const backendIds = new Set(backendRows.map((r) => r.id));

    // Build rows from investigation state and merge in any not already present
    const invSoftwareRows = buildPersistedInvestigationSoftwareRows(persistedRunbookState);
    const invAssetRows = buildAssetRowsFromMatchedSoftware(invSoftwareRows, severity);
    const extraRows = invAssetRows.filter((r) => !backendIds.has(r.id));

    return [...backendRows, ...extraRows].sort((a, b) => a.entity.localeCompare(b.entity));
  }, [detailQuery.data?.matchedSoftware, severity, persistedRunbookState]);

  // Map assetIdentifier → first finding for this CVE
  const findingsByAsset = React.useMemo(() => {
    const map = new Map<string, Finding>();
    for (const f of findingsQuery.data?.items ?? []) {
      if (!map.has(f.assetIdentifier)) map.set(f.assetIdentifier, f);
    }
    return map;
  }, [findingsQuery.data?.items]);

  // For grouped (CVE+Fix) findings: map each componentId, assetId, and assetIdentifier
  // in evidence.affectedAssets → the finding so any asset in the group can resolve it.
  const groupedFindingsByComponentId = React.useMemo(() => {
    const map = new Map<string, Finding>();
    for (const f of findingsQuery.data?.items ?? []) {
      try {
        const ev = JSON.parse(f.evidence ?? '{}') as {
          groupedFinding?: boolean;
          affectedAssets?: Array<{ componentId?: string; assetId?: string; assetIdentifier?: string }>;
        };
        if (ev.groupedFinding && Array.isArray(ev.affectedAssets)) {
          for (const a of ev.affectedAssets) {
            if (a.componentId) map.set(a.componentId, f);
            if (a.assetId) map.set(a.assetId, f);
            if (a.assetIdentifier) map.set(a.assetIdentifier, f);
          }
        }
      } catch { /* ignore */ }
    }
    return map;
  }, [findingsQuery.data?.items]);

  // Map assetIdentifier → componentIds (for Create Findings)
  // Include all correlated components regardless of applicabilityState — the backend
  // eligibility filter and override logic handle which ones are actually created.
  const componentsByAsset = React.useMemo(() => {
    const map = new Map<string, string[]>();
    // Backend-correlated components
    for (const sw of (detailQuery.data?.matchedSoftware ?? []).filter(
      (s) => s.assetId != null
    )) {
      const key = sw.assetIdentifier ?? sw.assetId ?? sw.componentId;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(sw.componentId);
    }
    // Investigation-resolved inventory components (have real UUIDs)
    for (const row of persistedRunbookState?.resolvedInventory ?? []) {
      for (const asset of row.assets) {
        if (!asset.componentId) continue;
        const key = asset.assetIdentifier ?? asset.assetId ?? asset.componentId;
        if (!map.has(key)) map.set(key, []);
        if (!map.get(key)!.includes(asset.componentId)) {
          map.get(key)!.push(asset.componentId);
        }
      }
    }
    return map;
  }, [detailQuery.data?.matchedSoftware, persistedRunbookState]);

  // Track which components are already eligible (vs need IMPACTED override)
  const componentEligibility = React.useMemo(() => {
    const map = new Map<string, boolean>();
    for (const sw of detailQuery.data?.matchedSoftware ?? []) {
      map.set(sw.componentId, sw.eligibleForFinding);
    }
    return map;
  }, [detailQuery.data?.matchedSoftware]);

  const enrichedRows = React.useMemo(() => (
    allAssetRows.map((asset) => {
      // Primary lookup: by assetIdentifier. Fallback: grouped finding evidence indexed by
      // assetIdentifier, assetId, or componentId — covers all assets in a CVE+Fix group.
      const componentIds = componentsByAsset.get(asset.id) ?? [];
      const finding = findingsByAsset.get(asset.identifier)
        ?? groupedFindingsByComponentId.get(asset.identifier)
        ?? (asset.assetId ? groupedFindingsByComponentId.get(asset.assetId) : undefined)
        ?? componentIds.map(cid => groupedFindingsByComponentId.get(cid)).find(Boolean)
        ?? undefined;
      return {
        ...asset,
        finding,
        softwareLabel: asset.matchedSoftware.map((s) => `${s.software} ${s.version}`.trim()).join(', ') || '—',
        falsePositive: finding?.vexStatus === 'not_affected' ? 'Yes' : '—',
        supportGroup: finding?.ownership?.supportGroup ?? asset.supportGroup ?? '—',
        owner: finding?.ownership?.ownerTeam ?? finding?.ownership?.displayName ?? '—',
        priority: finding?.severity ?? detailQuery.data?.summary.severity ?? '—',
        incidentId: finding?.incidentId ?? '—',
      };
    })
  ), [allAssetRows, findingsByAsset, groupedFindingsByComponentId, componentsByAsset, detailQuery.data?.summary.severity]);

  const filteredRows = React.useMemo(() => (
    enrichedRows.filter((row) => {
      if (filterAsset && !row.entity.toLowerCase().includes(filterAsset.toLowerCase())) return false;
      if (filterFinding && !(row.finding?.displayId ?? '—').toLowerCase().includes(filterFinding.toLowerCase())) return false;
      if (filterSoftware && !row.softwareLabel.toLowerCase().includes(filterSoftware.toLowerCase())) return false;
      if (filterFalsePositive !== 'All' && row.falsePositive !== filterFalsePositive) return false;
      if (filterSupportGroup && !(row.supportGroup).toLowerCase().includes(filterSupportGroup.toLowerCase())) return false;
      if (filterPriority !== 'All' && row.priority.toUpperCase() !== filterPriority) return false;
      return true;
    })
  ), [enrichedRows, filterAsset, filterFinding, filterSoftware, filterFalsePositive, filterSupportGroup, filterPriority]);

  const allSelected = filteredRows.length > 0 && filteredRows.every((r) => selectedIds.has(r.id));

  // For CVE+Fix mode: check if a grouped finding already exists for this CVE at all.
  // One CVE should have at most one grouped (CVE+Fix) finding.
  const selectedRowsHaveGroupedFinding = React.useMemo(() => {
    if (cfgCreationMode !== 'CVE_FIX') return false;
    return (findingsQuery.data?.items ?? []).some((f) => {
      try {
        return JSON.parse(f.evidence ?? '{}').groupedFinding === true;
      } catch { return false; }
    });
  }, [cfgCreationMode, findingsQuery.data?.items]);

  const toggleAll = () => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allSelected) {
        filteredRows.forEach((r) => next.delete(r.id));
      } else {
        filteredRows.forEach((r) => next.add(r.id));
      }
      return next;
    });
  };

  const toggleRow = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const openConfigModal = () => {
    if (selectedIds.size === 0) {
      setCreateMsg('Select at least one asset to create findings.');
      return;
    }
    setCfgTitle(cveId ?? '');
    const defaultSeverity = severity.toLowerCase();
    setCfgPriority(defaultSeverity.charAt(0).toUpperCase() + defaultSeverity.slice(1));
    setCfgDueDate('');
    setCfgTags('');
    setCfgNotes('');
    setCreateMsg(null);
    setShowConfigModal(true);
  };

  const handleCreateFindings = async () => {
    if (!cveId) return;
    // Build component IDs for all selected assets.
    // Primary source: matchedSoftware from backend (real UUIDs, matches by assetIdentifier/assetId/componentId).
    // Fallback: componentsByAsset for investigation-resolved assets.
    const seenComponentIds = new Set<string>();
    const componentIds: string[] = [];
    const addComponentId = (id: string) => {
      if (id && !seenComponentIds.has(id)) {
        seenComponentIds.add(id);
        componentIds.push(id);
      }
    };
    // Direct lookup from matchedSoftware — avoids any key mismatch in the intermediate map.
    for (const sw of detailQuery.data?.matchedSoftware ?? []) {
      const rowKey = sw.assetIdentifier ?? sw.assetId ?? sw.componentId;
      if (selectedIds.has(rowKey) && sw.componentId) {
        addComponentId(sw.componentId);
      }
    }
    // Fallback: investigation-resolved components not in matchedSoftware.
    for (const id of Array.from(selectedIds)) {
      for (const cid of componentsByAsset.get(id) ?? []) {
        addComponentId(cid);
      }
    }
    if (componentIds.length === 0) {
      setCreateMsg('None of the selected assets have eligible components. Components need confirmed impact (IMPACTED disposition or no available patch) to create findings.');
      setShowConfigModal(false);
      return;
    }
    // For components not yet eligible, pass APPLICABLE + IMPACTED overrides — the analyst
    // explicitly requesting finding creation is an implicit confirmation of impact.
    const componentAnalystDispositions: Record<string, 'IMPACTED' | 'NOT_IMPACTED' | 'UNKNOWN'> = {};
    const componentApplicabilityDecisions: Record<string, 'APPLICABLE' | 'NOT_APPLICABLE' | 'NEEDS_REVIEW'> = {};
    componentIds.forEach((id) => {
      if (!componentEligibility.get(id)) {
        componentAnalystDispositions[id] = 'IMPACTED';
        componentApplicabilityDecisions[id] = 'APPLICABLE';
      }
    });
    const dispositions = Object.keys(componentAnalystDispositions).length > 0
      ? componentAnalystDispositions : undefined;
    const applicability = Object.keys(componentApplicabilityDecisions).length > 0
      ? componentApplicabilityDecisions : undefined;

    setCreating(true);
    setCreateMsg(null);
    setShowConfigModal(false);
    const justification = [
      cfgNotes.trim(),
      cfgTitle.trim() ? `Title: ${cfgTitle.trim()}` : '',
      cfgTags.trim() ? `Tags: ${cfgTags.trim()}` : '',
      `Ownership: ${cfgAssignment}`,
    ].filter(Boolean).join('\n');
    try {
      const result = await cveWorkbenchApi.createManualFindings(cveId, {
        justification,
        componentIds,
        componentApplicabilityDecisions: applicability,
        componentAnalystDispositions: dispositions,
        severity: cfgPriority.toUpperCase(),
        dueDate: cfgDueDate || undefined,
        findingCreationMode: cfgCreationMode,
        existingFindingBehavior: cfgCreationMode === 'CVE_FIX' ? existingFindingBehavior : 'ADD_TO_EXISTING',
      });
      await findingsQuery.refetch();
      const parts: string[] = [];
      if (result.createdCount > 0) parts.push(`Created ${result.createdCount} finding(s).`);
      if (result.reopenedCount > 0) parts.push(`Reopened ${result.reopenedCount}.`);
      if (result.alreadyOpenCount > 0) parts.push(`${result.alreadyOpenCount} already open.`);
      if (cfgServiceNow && result.createdCount + result.reopenedCount > 0) {
        try {
          const response = await cveWorkbenchApi.createServiceNowIncident(cveId, {
            findingTitle: cfgTitle.trim() || cveId,
            severity: cfgPriority.toUpperCase(),
            priority: cfgPriority.toUpperCase(),
            inKev: detailQuery.data?.summary.inKev ?? false,
            cvssScore: detailQuery.data?.summary.cvssScore,
            epssScore: detailQuery.data?.summary.epssScore,
            dueDate: cfgDueDate || undefined,
            taskSlaDueDate: cfgDueDate || undefined,
            notes: justification,
            solutionInfo: detailQuery.data?.fixes?.map((fix) => fix.summary).join('\n'),
            assignedTo: cfgAssignment === 'Assign to lead analyst' ? persistedRunbookState?.leadAnalyst || actor?.userId || undefined : undefined,
            affectedAssets: (detailQuery.data?.matchedSoftware ?? []).filter((sw) => seenComponentIds.has(sw.componentId)).map((sw) => ({
              componentId: sw.componentId,
              assetName: sw.assetName,
              assetIdentifier: sw.assetIdentifier,
              assetType: sw.assetType,
              packageName: sw.packageName,
              packageVersion: sw.version ?? undefined,
              assignmentGroup: cfgAssignment === 'Assign by support group' ? ownershipSupportGroup(sw) : undefined,
              assignedTo: cfgAssignment === 'Assign by asset owner' ? ownershipAssignedTo(sw) : undefined,
            })),
          });
          const incidents = Array.isArray(response) ? response : [response];
          parts.push(...incidents.map((incident) => incident.status === 'error'
            ? `ServiceNow ticket failed: ${incident.message}`
            : `ServiceNow incident ${incident.incidentNumber} created.`));
          await findingsQuery.refetch();
        } catch (error) {
          parts.push(`ServiceNow ticket failed: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      setCreateMsg(parts.length > 0 ? parts.join(' ') : 'No eligible components found for the selected assets.');
    } catch (error) {
      await findingsQuery.refetch();
      setCreateMsg(`Failed to create findings: ${error instanceof Error ? error.message : 'Please try again.'}`);
    } finally {
      setCreating(false);
    }
  };

  return (
    <>
    <section className="panel vuln-repo-assets-shell">
      <div className="panel-header" style={{ borderBottom: '1px solid var(--border)', paddingBottom: 12 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => navigate(pathForVulnRepoView('org-cves', cveId))}
              disabled={!cveId}
            >
              Back to CVE
            </button>
          </div>
          <div className="org-cve-back-link">Affected Entities</div>
          <h3>{cveId ?? 'CVE Assets'}</h3>
          <span className="panel-caption">
            {allAssetRows.length.toLocaleString()} entities matched to this CVE.
          </span>
        </div>
      </div>

      {/* Action bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
        <span style={{ fontSize: 13, color: 'var(--muted)' }}>
          Total Assets: <strong style={{ color: 'var(--text)' }}>{filteredRows.length}</strong>
          &nbsp;&nbsp;Selected Assets: <strong style={{ color: 'var(--text)' }}>{selectedIds.size}</strong>
        </span>
        <div style={{ flex: 1 }} />
        <button
          type="button"
          className="btn btn-primary"
          onClick={openConfigModal}
          disabled={creating || selectedIds.size === 0}
        >
          {creating ? 'Creating…' : 'Create Findings'}
        </button>
      </div>

      {createMsg && (
        <div style={{ padding: '6px 0', fontSize: 13, color: createMsg.startsWith('Failed') ? '#c53030' : '#2d6a4f' }}>
          {createMsg}
        </div>
      )}

      {detailQuery.isLoading || detailQuery.isFetching ? (
        <div className="notice">Loading affected entities...</div>
      ) : detailQuery.error instanceof Error ? (
        <div className="notice error">{detailQuery.error.message}</div>
      ) : allAssetRows.length === 0 ? (
        <div className="empty-state"><p>No affected entities were found for this CVE.</p></div>
      ) : (
        <div className="table-scroll">
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ background: 'var(--panel-muted)', borderBottom: '1px solid var(--border)' }}>
                <th style={{ width: 36, padding: '8px 10px' }}>
                  <input type="checkbox" checked={allSelected} onChange={toggleAll} />
                </th>
                <th style={TH_STYLE}>ASSET / CI</th>
                <th style={TH_STYLE}>FINDING ID</th>
                <th style={TH_STYLE}>SOFTWARE</th>
                <th style={TH_STYLE}>FALSE POSITIVE</th>
                <th style={TH_STYLE}>SUPPORT GROUP</th>
                <th style={TH_STYLE}>OWNER</th>
                <th style={TH_STYLE}>PRIORITY</th>
                <th style={TH_STYLE}>INCIDENT ID</th>
              </tr>
              <tr style={{ background: 'var(--panel-muted)', borderBottom: '2px solid var(--border)' }}>
                <td />
                <td style={{ padding: '4px 10px' }}>
                  <input style={INPUT_STYLE} placeholder="Filter asset..." value={filterAsset} onChange={(e) => setFilterAsset(e.target.value)} />
                </td>
                <td style={{ padding: '4px 10px' }}>
                  <input style={INPUT_STYLE} placeholder="Filter ID..." value={filterFinding} onChange={(e) => setFilterFinding(e.target.value)} />
                </td>
                <td style={{ padding: '4px 10px' }}>
                  <input style={INPUT_STYLE} placeholder="Filter software..." value={filterSoftware} onChange={(e) => setFilterSoftware(e.target.value)} />
                </td>
                <td style={{ padding: '4px 10px' }}>
                  <select style={INPUT_STYLE} value={filterFalsePositive} onChange={(e) => setFilterFalsePositive(e.target.value)}>
                    <option>All</option>
                    <option>Yes</option>
                    <option value="—">No</option>
                  </select>
                </td>
                <td style={{ padding: '4px 10px' }}>
                  <input style={INPUT_STYLE} placeholder="Filter group..." value={filterSupportGroup} onChange={(e) => setFilterSupportGroup(e.target.value)} />
                </td>
                <td />
                <td style={{ padding: '4px 10px' }}>
                  <select style={INPUT_STYLE} value={filterPriority} onChange={(e) => setFilterPriority(e.target.value)}>
                    <option>All</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </td>
                <td />
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row) => (
                <tr key={row.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px', textAlign: 'center' }}>
                    <input type="checkbox" checked={selectedIds.has(row.id)} onChange={() => toggleRow(row.id)} />
                  </td>
                  <td style={{ padding: '10px' }}>
                    <button
                      type="button"
                      style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--accent)', fontWeight: 600, fontSize: 13, textAlign: 'left' }}
                      onClick={() => {
                        const navId = row.assetId ?? row.id;
                        navigate(pathForVulnRepoHostAsset(navId, `/vuln-repo/org-cves/${encodeURIComponent(cveId ?? '')}/assets`));
                      }}
                    >
                      {row.entity}
                    </button>
                    <div style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace', marginTop: 2 }}>{row.identifier}</div>
                    <div style={{ marginTop: 3 }}>
                      <span style={{ fontSize: 11, padding: '1px 6px', borderRadius: 4, background: 'var(--panel-muted)', border: '1px solid var(--border)', color: 'var(--muted)' }}>
                        {row.owner === '—' ? 'Unassigned' : row.owner}
                      </span>
                    </div>
                  </td>
                  <td style={{ padding: '10px' }}>
                    {row.finding ? (
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--accent)', fontFamily: 'monospace', fontSize: 13 }}
                        onClick={() => navigate(
                          pathForFindingDetail(row.finding!.displayId, `/vuln-repo/org-cves/${encodeURIComponent(cveId ?? '')}/assets`),
                          { state: { finding: row.finding } }
                        )}
                      >
                        {row.finding.displayId}
                      </button>
                    ) : <span style={{ color: 'var(--muted)' }}>—</span>}
                  </td>
                  <td style={{ padding: '10px', color: 'var(--text)' }}>{row.softwareLabel}</td>
                  <td style={{ padding: '10px', color: 'var(--muted)' }}>{row.falsePositive}</td>
                  <td style={{ padding: '10px', color: 'var(--muted)' }}>{row.supportGroup}</td>
                  <td style={{ padding: '10px', color: 'var(--muted)' }}>{row.owner}</td>
                  <td style={{ padding: '10px' }}>
                    {row.priority !== '—' ? <PriorityBadge priority={row.priority} /> : <span style={{ color: 'var(--muted)' }}>—</span>}
                  </td>
                  <td style={{ padding: '10px', color: 'var(--muted)', fontFamily: 'monospace', fontSize: 12 }}>{row.incidentId}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>

      {/* Finding Configuration Modal */}
      {showConfigModal && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 1000,
            background: 'rgba(0,0,0,0.45)', display: 'flex',
            alignItems: 'flex-start', justifyContent: 'flex-end',
          }}
          onClick={(e) => { if (e.target === e.currentTarget) setShowConfigModal(false); }}
        >
          <div style={{
            width: 560, maxHeight: '100vh', overflowY: 'auto',
            background: 'var(--panel)', borderLeft: '1px solid var(--border)',
            padding: '28px 28px 24px', display: 'flex', flexDirection: 'column', gap: 20,
          }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
              <div>
                <h2 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Finding Configuration</h2>
                <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 6, lineHeight: 1.5 }}>
                  Configure due date, tags, and assignment logic for the selected impacted assets without leaving the current findings workspace.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowConfigModal(false)}
                style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, width: 32, height: 32, cursor: 'pointer', fontSize: 16, color: 'var(--text)', flexShrink: 0 }}
              >
                ×
              </button>
            </div>

            <div style={{ borderTop: '1px solid var(--border)' }} />

            {/* Finding Title */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>FINDING TITLE</label>
              <input
                aria-label="Finding title"
                style={{ width: '100%', padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', boxSizing: 'border-box' }}
                value={cfgTitle}
                onChange={(e) => setCfgTitle(e.target.value)}
              />
            </div>

            {/* Priority + Due Date */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>SEVERITY</label>
                <select
                  aria-label="Finding severity"
                  style={{ padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
                  value={cfgPriority}
                  onChange={(e) => setCfgPriority(e.target.value)}
                >
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>DUE DATE</label>
                <input
                  aria-label="Finding due date"
                  type="date"
                  style={{ padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
                  value={cfgDueDate}
                  onChange={(e) => setCfgDueDate(e.target.value)}
                />
              </div>
            </div>

            {/* Tags */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>TAGS</label>
              <input
                aria-label="Finding tags"
                style={{ width: '100%', padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', boxSizing: 'border-box' }}
                placeholder="e.g. internet-facing, zero-day, patching"
                value={cfgTags}
                onChange={(e) => setCfgTags(e.target.value)}
              />
              {cfgTags.split(',').map(t => t.trim()).filter(t => t.length > 0).length > 0 && (
                <div className="cve-findings-tag-list">
                  {cfgTags.split(',').map(t => t.trim()).filter(t => t.length > 0).map((tag) => (
                    <span key={tag} className="cve-findings-tag-chip">{tag}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Assignment */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>ASSIGNMENT / OWNERSHIP LOGIC</label>
              <select
                aria-label="Finding ownership"
                style={{ padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
                value={cfgAssignment}
                onChange={(e) => setCfgAssignment(e.target.value)}
              >
                <option>Assign to lead analyst</option>
                <option>Assign by support group</option>
                <option>Assign by asset owner</option>
                <option>Leave unassigned</option>
              </select>
            </div>

            {/* ServiceNow */}
            <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 14, fontWeight: 600, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={cfgServiceNow}
                onChange={(e) => setCfgServiceNow(e.target.checked)}
                style={{ width: 16, height: 16, accentColor: 'var(--accent)' }}
              />
              Create tickets in ServiceNow
            </label>

            {/* Finding Creation Mode */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>FINDING CREATION MODE</label>
              {(
                [
                  {
                    value: 'ASSET_CVE' as FindingCreationMode,
                    label: 'Asset + CVE',
                    description: 'Create one unique finding per selected asset, with the CVE linked as a dependency.',
                  },
                  {
                    value: 'CVE_FIX' as FindingCreationMode,
                    label: 'CVE + Fix',
                    description: 'Create one finding per available fix for this CVE, with all selected assets and the CVE as dependent elements.',
                  },
                ] as const
              ).map(({ value, label, description }) => {
                const active = cfgCreationMode === value;
                return (
                  <label
                    key={value}
                    style={{
                      display: 'flex', alignItems: 'flex-start', gap: 12, padding: '12px 14px',
                      borderRadius: 8, cursor: 'pointer',
                      border: `1.5px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                      background: active ? 'color-mix(in srgb, var(--accent) 6%, var(--panel-muted))' : 'var(--panel-muted)',
                      transition: 'border-color 0.15s, background 0.15s',
                    }}
                  >
                    <input
                      type="radio"
                      name="findingCreationMode"
                      value={value}
                      checked={active}
                      onChange={() => setCfgCreationMode(value)}
                      style={{ marginTop: 2, accentColor: 'var(--accent)', flexShrink: 0 }}
                    />
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 2 }}>{label}</div>
                      <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>{description}</div>
                    </div>
                  </label>
                );
              })}
            </div>

            {/* Notes */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>NOTES</label>
              <textarea
                rows={4}
                style={{ width: '100%', padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', resize: 'vertical', boxSizing: 'border-box', fontFamily: 'inherit' }}
                placeholder="Describe the remediation approach or ticket creation context..."
                value={cfgNotes}
                onChange={(e) => setCfgNotes(e.target.value)}
              />
            </div>

            <div style={{ borderTop: '1px solid var(--border)' }} />

            {selectedRowsHaveGroupedFinding && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>WHEN FINDING EXISTS</label>
                {(
                  [
                    { value: 'ADD_TO_EXISTING' as ExistingFindingBehavior, label: 'Add to existing finding', description: 'Update the existing finding\'s evidence to include all currently selected assets.' },
                    { value: 'CREATE_NEW' as ExistingFindingBehavior, label: 'Create new finding', description: 'Create a new separate finding for the selected assets.' },
                  ] as const
                ).map(({ value, label, description }) => {
                  const active = existingFindingBehavior === value;
                  return (
                    <label
                      key={value}
                      style={{
                        display: 'flex', alignItems: 'flex-start', gap: 12, padding: '10px 14px',
                        borderRadius: 8, cursor: 'pointer',
                        border: `1.5px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                        background: active ? 'color-mix(in srgb, var(--accent) 6%, var(--panel-muted))' : 'var(--panel-muted)',
                        transition: 'border-color 0.15s, background 0.15s',
                      }}
                    >
                      <input
                        type="radio"
                        name="existingFindingBehavior"
                        value={value}
                        checked={active}
                        onChange={() => setExistingFindingBehavior(value)}
                        style={{ marginTop: 2, flexShrink: 0, accentColor: 'var(--accent)' }}
                      />
                      <div>
                        <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 2 }}>{label}</div>
                        <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.4 }}>{description}</div>
                      </div>
                    </label>
                  );
                })}
              </div>
            )}

            {/* Footer */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowConfigModal(false)}
              >
                Close
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleCreateFindings}
                disabled={creating}
              >
                {creating ? 'Creating…' : `Create Findings (${selectedIds.size})`}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
