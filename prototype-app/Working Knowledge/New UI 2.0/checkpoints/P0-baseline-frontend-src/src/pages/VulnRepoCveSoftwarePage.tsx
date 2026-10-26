import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForVulnRepoView } from '../app/routes';
import { useCveDetailQuery } from '../features/cve-workbench/queries';
import type { CveMatchedSoftware } from '../features/cve-workbench/types';
import {
  buildPersistedSoftwareSummaryRows,
  loadPersistedInvestigationRunbookState,
} from '../features/cve-workbench/investigation-context';

type SoftwareRow = {
  id: string;
  software: string;
  vendor: string;
  version: string;
  evidenceSource: string;
};

const SOFTWARE_COLUMNS: DataTableColumn[] = [
  { id: 'software', label: 'Software', header: 'Software', initialSize: 260 },
  { id: 'vendor', label: 'Vendor', header: 'Vendor', initialSize: 180 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 220 },
  { id: 'evidence', label: 'Evidence', header: 'Evidence', initialSize: 180 },
];

function buildSoftwareRows(matchedSoftware: CveMatchedSoftware[], persistedRows: Array<{ software: string; vendor: string; version: string; assetCount: number }> = []): SoftwareRow[] {
  const vendorByPackage = new Map<string, string>();
  const evidenceByPackageVersion = new Map<string, Set<string>>();
  matchedSoftware.forEach((software) => {
    const pkgKey = software.packageName?.trim().toLowerCase();
    const vendor = software.vexSource?.trim() || software.ecosystem?.trim();
    if (pkgKey && vendor && !vendorByPackage.has(pkgKey)) {
      vendorByPackage.set(pkgKey, vendor);
    }
    const packageName = software.packageName?.trim() || 'Unknown';
    const version = software.version?.trim() || '-';
    const key = `${packageName.toLowerCase()}|${version.toLowerCase()}`;
    const sources = evidenceByPackageVersion.get(key) ?? new Set<string>();
    sources.add(software.matchedBy === 'BOM_CORRELATION' ? 'BOM evidence' : 'Inventory correlation');
    evidenceByPackageVersion.set(key, sources);
  });

  const unique = new Map<string, SoftwareRow>();
  matchedSoftware.forEach((software) => {
    const packageName = software.packageName?.trim() || 'Unknown';
    const version = software.version?.trim() || '-';
    const vendor = software.vexSource?.trim()
      || vendorByPackage.get(packageName.toLowerCase())
      || software.ecosystem?.trim()
      || 'Unknown';
    const key = `${packageName.toLowerCase()}|${version.toLowerCase()}`;
    if (!unique.has(key)) {
      unique.set(key, {
        id: key,
        software: packageName,
        vendor,
        version,
        evidenceSource: Array.from(evidenceByPackageVersion.get(key) ?? ['Inventory correlation']).join(', '),
      });
    }
  });

  persistedRows.forEach((software) => {
    const packageName = software.software?.trim() || 'Unknown';
    const version = software.version?.trim() || '-';
    const vendor = software.vendor?.trim() || vendorByPackage.get(packageName.toLowerCase()) || 'Inventory';
    const key = `${packageName.toLowerCase()}|${version.toLowerCase()}`;
    const existing = unique.get(key);
    if (existing) {
      existing.vendor = existing.vendor === 'Unknown' ? vendor : existing.vendor;
      if (!existing.evidenceSource.includes('Inventory correlation')) {
        existing.evidenceSource = `${existing.evidenceSource}, Inventory correlation`;
      }
      return;
    }
    unique.set(key, {
      id: key,
      software: packageName,
      vendor,
      version,
      evidenceSource: 'Inventory correlation',
    });
  });

  return Array.from(unique.values()).sort((left, right) => (
    left.software.localeCompare(right.software)
    || left.version.localeCompare(right.version)
    || left.vendor.localeCompare(right.vendor)
  ));
}

export function VulnRepoCveSoftwarePage() {
  const navigate = useNavigate();
  const params = useParams<{ cveId?: string }>();
  const cveId = params.cveId ?? null;
  const detailQuery = useCveDetailQuery(cveId);
  const persistedRunbookState = React.useMemo(
    () => (cveId ? loadPersistedInvestigationRunbookState(cveId) : null),
    [cveId]
  );
  const softwareRows = React.useMemo(() => buildSoftwareRows(
    detailQuery.data?.matchedSoftware ?? [],
    buildPersistedSoftwareSummaryRows(persistedRunbookState)
  ), [detailQuery.data?.matchedSoftware, persistedRunbookState]);

  const rows = React.useMemo<DataTableRow[]>(() => (
    softwareRows.map((software) => ({
      id: software.id,
      cells: {
        software: { content: <span className="mono">{software.software}</span> },
        vendor: { content: software.vendor },
        version: { content: <span className="mono">{software.version}</span> },
        evidence: {
          content: (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                padding: '4px 10px',
                borderRadius: 999,
                fontSize: 12,
                fontWeight: 600,
                background: software.evidenceSource.includes('BOM') ? 'rgba(59, 130, 246, 0.12)' : 'rgba(107, 114, 128, 0.12)',
                color: software.evidenceSource.includes('BOM') ? '#2563eb' : 'var(--muted)',
                border: software.evidenceSource.includes('BOM') ? '1px solid rgba(59, 130, 246, 0.24)' : '1px solid var(--border)',
              }}
            >
              {software.evidenceSource}
            </span>
          ),
        },
      },
    }))
  ), [softwareRows]);

  return (
    <section className="panel vuln-repo-assets-shell">
      <div className="panel-header">
        <div>
          <div className="org-cve-back-link">Impacted Software</div>
          <h3>{cveId ?? 'CVE Software'}</h3>
          <span className="panel-caption">
            {softwareRows.length.toLocaleString()} matched software entries correlated to this CVE&apos;s CPE targets.
          </span>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate(pathForVulnRepoView('org-cves', cveId))}
            disabled={!cveId}
          >
            Back to CVE
          </button>
        </div>
      </div>

      {detailQuery.isLoading || detailQuery.isFetching ? (
        <div className="notice">Loading impacted software...</div>
      ) : detailQuery.error instanceof Error ? (
        <div className="notice error">{detailQuery.error.message}</div>
      ) : softwareRows.length === 0 ? (
        <div className="empty-state"><p>No impacted software was found for this CVE.</p></div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey={`vuln-repo-cve-software:${cveId ?? 'unknown'}`}
            columns={SOFTWARE_COLUMNS}
            rows={rows}
          />
        </div>
      )}
    </section>
  );
}
