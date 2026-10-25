import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiRequest } from '../../api/client';
type SyncStatus = { status: string; advisoriesSynced?: number; lastFullSyncAt?: string; lastError?: string };
type ComponentAdvisory = { id: string; advisoryId: string; componentId: string; installedVersion: string; recommendedFixedVersion?: string; upgradeAvailable?: boolean };
import './github-advisory-status.css';

type Props = {
  sourceId?: string;
  tenantId: string;
};

export function GithubAdvisoryStatus({ sourceId, tenantId }: Props) {
  const syncStatusQuery = useQuery({
    queryKey: ['github-advisory-sync-status'],
    queryFn: () => apiRequest<SyncStatus>('/platform/ghsa/sync-status'),
    refetchInterval: 60000
  });

  const advisoriesQuery = useQuery({
    queryKey: ['github-advisories-for-source', tenantId, sourceId],
    queryFn: () => apiRequest<ComponentAdvisory[]>(`/tenants/${encodeURIComponent(tenantId)}/ghsa/component-advisories/${encodeURIComponent(sourceId!)}`),
    enabled: !!sourceId,
    refetchInterval: 300000
  });

  if (syncStatusQuery.isPending) {
    return <div className="advisory-status advisory-status--loading">Loading GHSA status...</div>;
  }

  if (syncStatusQuery.isError) {
    return <div className="advisory-status advisory-status--error">Failed to load advisory status</div>;
  }

  const syncStatus = syncStatusQuery.data;
  const advisories = advisoriesQuery.data ?? [];

  return (
    <div className="advisory-status">
      <div className="advisory-status__header">
        <h3>GitHub Security Advisories</h3>
        <div className={`status-badge status-badge--${syncStatus.status.toLowerCase()}`}>
          {syncStatus.status}
        </div>
      </div>

      <div className="advisory-status__stats">
        <div className="stat">
          <span className="stat__label">Cached:</span>
          <span className="stat__value">{(syncStatus.advisoriesSynced ?? 0).toLocaleString()}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Affected Repos:</span>
          <span className="stat__value">{advisories.length}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Last Sync:</span>
          <span className="stat__value">{formatTime(syncStatus.lastFullSyncAt)}</span>
        </div>
      </div>

      {advisories.length > 0 && (
        <div className="advisory-status__findings">
          <h4>{advisories.length} Security Advisories Found</h4>
          <ul className="advisory-list">
            {advisories.map((advisory) => (
              <li key={advisory.advisoryId} className={`advisory-item advisory-item--${'affected'}`}>
                <div className="advisory-item__header">
                  <code className="advisory-id">{advisory.advisoryId}</code>
                </div>
                <div className="advisory-item__title">{advisory.componentId}</div>
                <div className="advisory-item__package">
                  {advisory.installedVersion}
                </div>
                {advisory.upgradeAvailable && advisory.recommendedFixedVersion && (
                  <div className="advisory-item__fix">
                    ✓ Upgrade to {advisory.recommendedFixedVersion}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {!advisories.length && sourceId && (
        <div className="advisory-status__empty">
          No vulnerabilities found in this repository's components.
        </div>
      )}

      {syncStatus.lastError && (
        <div className="advisory-status__error">
          ⚠ Last error: {syncStatus.lastError}
        </div>
      )}
    </div>
  );
}

function formatTime(instant?: string): string {
  if (!instant) return 'Never';
  const date = new Date(instant);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 365) return `${diffDays}d ago`;

  return date.toLocaleDateString();
}
