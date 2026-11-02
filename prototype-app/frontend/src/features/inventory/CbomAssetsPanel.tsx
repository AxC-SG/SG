import { useQuery } from '@tanstack/react-query';
import { api, type CbomBomAsset } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';

function severityClass(severity: string): string {
  const value = severity.toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(value) ? `status-badge--${value}` : 'status-badge--info';
}

function assetTypeLabel(assetType: string): string {
  const words = assetType.toLowerCase().replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// The algorithm, protocol or key properties a CBOM asset declares, whichever it has.
function cryptoProperties({ asset }: CbomBomAsset): string {
  const parts = [
    asset.primitive,
    asset.curve,
    asset.keySize ? `${asset.keySize}-bit` : null,
    asset.protocolVersion,
    asset.padding && asset.padding !== 'none' ? `padding ${asset.padding}` : null,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(' · ') : '—';
}

export function CbomAssetsPanel({ bomId }: { bomId: string }) {
  const assetsQuery = useQuery({
    queryKey: ['bom-cbom-assets', bomId],
    queryFn: () => api.listCbomAssetsForBom(bomId),
  });
  const rows = assetsQuery.data ?? [];
  const state = assetsQuery.isPending ? 'pending'
    : assetsQuery.isError ? 'error'
      : rows.length === 0 ? 'empty'
        : 'ready';

  return (
    <div className="panel bom-components-panel">
      <div className="panel-header">
        <h4>Cryptographic assets ({rows.length.toLocaleString()})</h4>
        <span className="panel-caption">
          {rows.reduce((total, row) => total + row.findings.length, 0)} findings linked to these assets
        </span>
      </div>
      <AsyncSection
        state={state}
        loadingLabel="Loading cryptographic assets…"
        errorMessage="Cryptographic assets could not be loaded."
        onRetry={() => void assetsQuery.refetch()}
        retryLabel="Retry cryptographic assets"
        retrying={assetsQuery.isFetching}
        emptyMessage="This CBOM has no active cryptographic assets."
      >
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Asset type</th>
                <th>Algorithm / protocol / key</th>
                <th>State</th>
                <th>Risk</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.asset.id}>
                  <td>{row.asset.name}</td>
                  <td><span className="tag">{assetTypeLabel(row.asset.assetType)}</span></td>
                  <td>{cryptoProperties(row)}</td>
                  <td>{row.asset.state ?? '—'}</td>
                  <td>{row.asset.riskScore == null ? '—' : row.asset.riskScore.toFixed(2)}</td>
                  <td>
                    {row.findings.length === 0 ? '—' : (
                      <div style={{ display: 'grid', gap: 4 }}>
                        {row.findings.map((finding) => (
                          <div key={finding.id}>
                            <span className={`status-badge ${severityClass(finding.severity)}`}>{finding.severity}</span>{' '}
                            {finding.title}
                          </div>
                        ))}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AsyncSection>
    </div>
  );
}
