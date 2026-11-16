import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { pathForFindingDetail } from '../../app/routes';
import { api } from '../../api/client';
import { campaignOwnerLabel } from './ownership';

/**
 * Members of a campaign created from findings (for example CRYPTO findings), first page of the campaign ledger
 * (Phase 0B §4.5); hidden when there are none. The owner column is the member's current owner, not a free-text group.
 */
export function CampaignLinkedFindings({ campaignId }: { campaignId: string }) {
  const query = useQuery({
    queryKey: ['campaign-members', campaignId],
    queryFn: () => api.listCampaignMembers(campaignId, { limit: 200, includeHidden: true }),
  });
  if (query.isPending) return null;
  if (query.isError) return <div className="notice error" role="status">Linked findings could not be loaded.</div>;
  const rows = query.data?.items ?? [];
  if (rows.length === 0) return null;
  const open = rows.filter((row) => row.outcome === 'OPEN' || row.outcome === 'REOPENED').length;
  return (
    <section className="panel campaign-linked-findings" aria-labelledby="campaign-linked-findings">
      <h3 id="campaign-linked-findings">Linked findings ({rows.length}{query.data?.nextCursor ? '+' : ''}, {open} open)</h3>
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>Finding</th><th>Kind</th><th>Severity</th><th>Outcome</th><th>Owner</th><th>Due</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.findingId}>
                <td><Link to={pathForFindingDetail(row.displayId)}>{row.displayId}</Link> {row.title}</td>
                <td>{row.findingKind}</td>
                <td>{row.severity ?? '—'}</td>
                <td>{row.outcome}</td>
                <td>{campaignOwnerLabel(row.currentOwnership)}</td>
                <td>{row.dueAt ? new Date(row.dueAt).toLocaleDateString() : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
