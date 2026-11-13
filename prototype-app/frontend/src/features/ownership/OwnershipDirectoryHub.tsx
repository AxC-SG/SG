import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { SegmentedControl } from '../../components/SegmentedControl';
import { useActor } from '../auth/context';
import { GroupsPanel } from './GroupsPanel';
import { ImportsPanel } from './ImportsPanel';
import { OverviewPanel } from './OverviewPanel';
import { PeoplePanel } from './PeoplePanel';
import { ReviewPanel } from './ReviewPanel';
import { TeamsPanel } from './TeamsPanel';
import {
  canImportDirectory,
  canManageOwnershipAuthority,
  canManageOwnershipEncryption,
  canResolveReview,
  canViewDirectory,
  canWriteDirectory,
  canWriteTeams
} from './permissions';
import { useOwnershipCoverageQuery } from './queries';

export type OwnershipHubView = 'overview' | 'teams' | 'people' | 'groups' | 'imports' | 'review' | 'legacy';

const VIEW_PARAM = 'view';

/**
 * Ownership & Directory hub (plan §9.1), the Configurations Ownership section. Release 1 covers teams and aliases,
 * manual and CSV people/groups, review and the core cutover. Provider sources and group-to-team mappings arrive with
 * the ServiceNow directory, Entra and Okta work. The legacy rule editor stays available, labelled as pending
 * migration, until inventory ownership is canonical (user decision, November 9, 2026; removed in the §15.5 cleanup).
 */
export function OwnershipDirectoryHub({ legacyRules }: { legacyRules: React.ReactNode }) {
  const actor = useActor();
  const [searchParams, setSearchParams] = useSearchParams();
  const coverage = useOwnershipCoverageQuery('INVENTORY');
  // Keep the legacy editor reachable unless the server says inventory ownership is canonical.
  const legacyActive = coverage.data?.authorityState !== 'CANONICAL';

  const options: Array<{ value: OwnershipHubView; label: string }> = [
    { value: 'overview', label: 'Overview' },
    { value: 'teams', label: 'Teams' },
    ...(canViewDirectory(actor) ? [{ value: 'people' as const, label: 'People' }, { value: 'groups' as const, label: 'Groups' }] : []),
    ...(canImportDirectory(actor) ? [{ value: 'imports' as const, label: 'Imports' }] : []),
    { value: 'review', label: 'Review' },
    ...(legacyActive ? [{ value: 'legacy' as const, label: 'Legacy rules' }] : [])
  ];
  const requested = searchParams.get(VIEW_PARAM) as OwnershipHubView | null;
  const view: OwnershipHubView = options.some((option) => option.value === requested) ? (requested as OwnershipHubView) : 'overview';

  const select = (next: OwnershipHubView) => {
    const params = new URLSearchParams(searchParams);
    if (next === 'overview') params.delete(VIEW_PARAM);
    else params.set(VIEW_PARAM, next);
    setSearchParams(params, { replace: true });
  };

  return (
    <div className="config-section-body ownership-hub">
      <div className="config-section-intro">
        <p>
          Ownership resolves each asset to one accountable <strong>team</strong> from reviewed source evidence. People and
          groups are directory records; they never grant Scoutgrid access.
        </p>
      </div>
      <SegmentedControl<OwnershipHubView> ariaLabel="Ownership & Directory views" value={view} onChange={select} options={options} />
      <div className="ownership-hub-view">
        {view === 'overview' && (
          <OverviewPanel canManageEncryption={canManageOwnershipEncryption(actor)} canManageAuthority={canManageOwnershipAuthority(actor)} />
        )}
        {view === 'teams' && <TeamsPanel canWrite={canWriteTeams(actor)} />}
        {view === 'people' && <PeoplePanel canWrite={canWriteDirectory(actor)} />}
        {view === 'groups' && <GroupsPanel canWrite={canWriteDirectory(actor)} />}
        {view === 'imports' && <ImportsPanel />}
        {view === 'review' && <ReviewPanel canResolve={canResolveReview(actor)} />}
        {view === 'legacy' && (
          <>
            <div className="notice warning" role="status">
              <strong>Legacy ownership rules — pending migration.</strong> These rules still set the owner group on findings
              until core ownership switches to canonical. They are removed after cutover.
            </div>
            {legacyRules}
          </>
        )}
      </div>
    </div>
  );
}
