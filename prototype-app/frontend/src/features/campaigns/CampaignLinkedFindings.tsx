import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { pathForFindingDetail } from '../../app/routes';
import { api } from '../../api/client';

/** Canonical findings (for example CRYPTO findings) linked to a campaign without a CVE; hidden when there are none. */
export function CampaignLinkedFindings({ campaignId }: { campaignId: string }) {
  const query = useQuery({ queryKey: ['campaign-findings', campaignId], queryFn: () => api.listCampaignFindings(campaignId) });
  if (query.isPending) return null;
  if (query.isError) return <div className="notice error" role="status">Linked findings could not be loaded.</div>;
  const rows = query.data ?? [];
  if (rows.length === 0) return null;
  const open = rows.filter((row) => row.status === 'OPEN').length;
  return (
    <section className="panel campaign-linked-findings" aria-labelledby="campaign-linked-findings">
      <h3 id="campaign-linked-findings">Linked findings ({rows.length}, {open} open)</h3>
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>Finding</th><th>Kind</th><th>Severity</th><th>Status</th><th>Owner</th><th>Due</th><th>Verification</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.findingId}>
                <td><Link to={pathForFindingDetail(row.findingId)}>{row.displayId}</Link> {row.title}</td>
                <td>{row.findingKind}</td>
                <td>{row.severity ?? '—'}</td>
                <td>{row.status}</td>
                <td>{row.assignedTo ?? row.ownerGroup ?? 'Unassigned'}</td>
                <td>{row.dueAt ? new Date(row.dueAt).toLocaleDateString() : '—'}</td>
                <td>{row.verificationStatus ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
