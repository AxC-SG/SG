import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { StatCard } from '../../components/StatCard';
import { CutoverPanel } from './CutoverPanel';
import { ownershipErrorText } from './errors';
import { useOwnershipCoverageQuery, useOwnershipEncryptionQuery, useProvisionEncryptionMutation } from './queries';
import type { OwnershipCoverage } from './types';

function CoverageCards({ title, consumer }: { title: string; consumer: 'INVENTORY' | 'FINDINGS' }) {
  const coverage = useOwnershipCoverageQuery(consumer);
  const data: OwnershipCoverage | undefined = coverage.data;
  const caption = data?.authorityState === 'CANONICAL' ? 'Canonical ownership' : 'Canonical model (not yet authoritative)';
  return (
    <section className="ownership-coverage" aria-label={`${title} ownership coverage`}>
      <h3>{title}</h3>
      <AsyncSection
        state={coverage.isPending ? 'pending' : coverage.isError && !data ? 'error' : 'ready'}
        loadingLabel={`Loading ${title.toLowerCase()} coverage…`}
        errorMessage={ownershipErrorText(coverage.error, 'Coverage could not be loaded.')}
        onRetry={() => void coverage.refetch()}
        retrying={coverage.isFetching}
        refreshError={coverage.isError && data ? 'The latest coverage could not be loaded; showing the previous counts.' : undefined}
      >
        {data && (
          <>
            {data.authorityState !== 'CANONICAL' && (
              <p className="panel-caption">
                Ownership shown elsewhere in the product still comes from the legacy model. These counts are what the
                canonical model resolves today, for review before cutover.
              </p>
            )}
            <div className="ownership-stat-grid">
              <StatCard title="Owned" value={data.owned} caption={caption} />
              <StatCard title="Unowned" value={data.unowned} tone={data.unowned > 0 ? 'warn' : 'neutral'} caption={caption} />
              <StatCard title="Conflict" value={data.conflict} tone={data.conflict > 0 ? 'critical' : 'neutral'} caption={caption} />
              <StatCard title="Not linked yet" value={data.unlinked} caption="No ownership subject" />
              {data.refreshing > 0 && <StatCard title="Refreshing" value={data.refreshing} caption="Cached result pending" />}
            </div>
          </>
        )}
      </AsyncSection>
    </section>
  );
}

function EncryptionCard() {
  const status = useOwnershipEncryptionQuery(true);
  const provision = useProvisionEncryptionMutation();
  return (
    <section className="ownership-coverage" aria-label="Tenant encryption">
      <h3>Directory encryption</h3>
      <AsyncSection
        state={status.isPending ? 'pending' : status.isError ? 'error' : 'ready'}
        loadingLabel="Checking tenant encryption…"
        errorMessage={ownershipErrorText(status.error, 'Encryption status could not be loaded.')}
        onRetry={() => void status.refetch()}
      >
        {status.data?.ready ? (
          <div className="notice success" role="status">Tenant key ready. People and groups can be added and imported.</div>
        ) : (
          <>
            <div className="notice warning" role="status">
              People and group writes are blocked until this tenant has an encryption key
              {status.data?.reason ? ` (${status.data.reason.toLowerCase().replace(/_/g, ' ')})` : ''}.
            </div>
            {provision.isError && (
              <div className="notice error" role="alert">{ownershipErrorText(provision.error, 'The tenant key could not be created.')}</div>
            )}
            <button type="button" className="btn btn-secondary" disabled={provision.isPending} onClick={() => provision.mutate()}>
              {provision.isPending ? 'Creating key…' : 'Create tenant key'}
            </button>
          </>
        )}
      </AsyncSection>
    </section>
  );
}

/** Coverage for each consumer, then the tenant-admin-only readiness and cutover controls. Each card loads on its own. */
export function OverviewPanel({ canManageEncryption, canManageAuthority }: { canManageEncryption: boolean; canManageAuthority: boolean }) {
  return (
    <div className="ownership-panel">
      <CoverageCards title="Inventory (applications and hosts)" consumer="INVENTORY" />
      <CoverageCards title="Open vulnerability findings" consumer="FINDINGS" />
      {canManageEncryption && <EncryptionCard />}
      {canManageAuthority && <CutoverPanel />}
    </div>
  );
}
