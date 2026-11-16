import { EMPTY_OWNER_FILTER, type OwnerFilterValue, type OwnerStatus } from './ownerFilterValue';
import { useOwnershipTeamsQuery } from './queries';


/**
 * Owner team and status filters for BOM occurrence lists (Phase 0B §3.7). Offered only once rows show canonical
 * ownership; the server answers 409 before CLOUD_BOM is canonical, which is shown as a plain state, never an error.
 */
export function OwnerFilters({ value, onChange, offered, notCanonical }: {
  value: OwnerFilterValue; onChange: (next: OwnerFilterValue) => void; offered: boolean; notCanonical: boolean;
}) {
  const active = value.ownerTeamId !== '' || value.ownershipStatus !== '';
  const visible = offered || active || notCanonical;
  const teams = useOwnershipTeamsQuery('', 'ACTIVE', visible);
  if (!visible) return null;
  return (
    <div className="inventory-filter-row" role="group" aria-label="Owner filters">
      <div className="inventory-filter-field">
        <label className="panel-caption" htmlFor="owner-filter-team">Owner team</label>
        <select id="owner-filter-team" value={value.ownerTeamId} onChange={(event) => onChange({ ...value, ownerTeamId: event.target.value })}>
          <option value="">Any team</option>
          {(teams.data ?? []).map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
        </select>
      </div>
      <div className="inventory-filter-field">
        <label className="panel-caption" htmlFor="owner-filter-status">Ownership status</label>
        <select id="owner-filter-status" value={value.ownershipStatus} onChange={(event) => onChange({ ...value, ownershipStatus: event.target.value as OwnerStatus })}>
          <option value="">Any status</option>
          <option value="OWNED">Owned</option>
          <option value="UNOWNED">Unowned</option>
          <option value="CONFLICT">Conflict</option>
        </select>
      </div>
      {active && (
        <div className="inventory-filter-field inventory-filter-clear">
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => onChange(EMPTY_OWNER_FILTER)}>Clear owner filters</button>
        </div>
      )}
      {notCanonical && (
        <p className="panel-caption" role="status">Owner filters are available once BOM ownership is canonical.</p>
      )}
    </div>
  );
}
