import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { useActor } from '../auth/context';
import { canApproveFixControls, canManageFixControls } from '../auth/roles';
import { ApiError } from '../../api/client';
import { formatTimestamp } from '../../lib/time';
import { fixIntelligenceApi } from './api';
import { FixControlForm } from './FixControlForm';
import {
  coverageLabel,
  ecosystemLabel,
  fixTypeLabel,
  isControlType,
  providerLabel,
  severityClass,
  titleCase
} from './format';
import type { ControlFixType, FixDetail } from './types';

export function FixDetailPage(): React.ReactElement {
  const { fixId = '' } = useParams();
  const actor = useActor();
  const queryClient = useQueryClient();
  const [editing, setEditing] = React.useState(false);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const detailQuery = useQuery({
    queryKey: ['fix-intelligence', 'detail', fixId],
    queryFn: () => fixIntelligenceApi.detail(fixId),
    enabled: !!fixId
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['fix-intelligence'] });
  const approve = useMutation({
    mutationFn: () => fixIntelligenceApi.approve(fixId),
    onSuccess: () => { setActionError(null); void refresh(); },
    onError: (failure: Error) => setActionError(failure.message)
  });
  const retire = useMutation({
    mutationFn: () => fixIntelligenceApi.retire(fixId),
    onSuccess: () => { setActionError(null); void refresh(); },
    onError: (failure: Error) => setActionError(failure.message)
  });

  if (detailQuery.isLoading) return <div className="page-grid fi-page ui2-fix-family"><p className="muted" role="status">Loading fix…</p></div>;
  if (detailQuery.isError || !detailQuery.data) {
    return (
      <div className="page-grid fi-page ui2-fix-family">
        <div className="notice error fi-error" role="alert">
          <span>{detailQuery.error instanceof ApiError && detailQuery.error.status === 404 ? 'This fix was not found.' : 'This fix could not be loaded.'}</span>
          <button type="button" className="btn" disabled={detailQuery.isFetching} onClick={() => void detailQuery.refetch()}>Retry fix</button>
        </div>
        <Link to="/fix-intelligence/all">Back to Fix Intelligence</Link>
      </div>
    );
  }

  const fix = detailQuery.data;
  const isOwnProposal = !!fix.proposedBy && fix.proposedBy === actor?.userId;
  const canEdit = fix.editable && fix.status !== 'RETIRED' && canManageFixControls(actor);
  const canApprove = fix.editable && fix.status === 'PROPOSED' && canApproveFixControls(actor);
  const canRetire = fix.editable && fix.status !== 'RETIRED' && canApproveFixControls(actor);

  return (
    <div className="page-grid fi-page ui2-fix-family">
      <Link className="fi-back" to="/fix-intelligence/all">← All fixes</Link>
      <header className="fi-header">
        <div>
          <span className="fi-eyebrow mono">{fix.displayId}</span>
          <h2>{fix.title}</h2>
          <div className="fi-tags">
            <span className={severityClass(fix.severity)}>{fix.severity ? titleCase(fix.severity) : 'Unrated'}</span>
            <span className="status-pill">{fixTypeLabel(fix.fixType)}</span>
            <span className="status-pill">{titleCase(fix.status)}</span>
            <span className="status-pill">{ecosystemLabel(fix.ecosystem)}</span>
            <span className="status-pill">Origin: {providerLabel(fix.origin)}</span>
          </div>
        </div>
        <div className="fi-actions">
          {canEdit && !editing && <button type="button" className="btn" onClick={() => setEditing(true)}>Edit</button>}
          {canApprove && (
            <button
              type="button"
              className="btn btn-primary"
              disabled={isOwnProposal || approve.isPending}
              title={isOwnProposal ? 'Another administrator must approve your proposal' : undefined}
              onClick={() => approve.mutate()}
            >
              Approve
            </button>
          )}
          {canRetire && (
            <button type="button" className="btn" disabled={retire.isPending} onClick={() => retire.mutate()}>Retire</button>
          )}
        </div>
      </header>
      {actionError && <div className="notice error" role="alert">{actionError}</div>}
      {!fix.editable && (
        <p className="muted">
          {fix.origin === 'PATCH_TOOL'
            ? 'Imported from your patch tools and refreshed on each sync; it cannot be edited here.'
            : 'Generated from the CVE Workbench recommendation; edit it there.'}
        </p>
      )}

      {editing && (
        <FixControlForm
          defaultType={isControlType(fix.fixType) ? fix.fixType as ControlFixType : 'WORKAROUND'}
          existing={fix}
          onCancel={() => setEditing(false)}
          onSaved={() => setEditing(false)}
        />
      )}

      <div className="fi-detail-grid">
        <section className="panel">
          <h3>Overview</h3>
          {/* Imported and analyst text is rendered as plain text, never as HTML. */}
          <TextBlock label="Description" value={fix.description} />
          <TextBlock label="How to apply" value={fix.installationInstructions} />
          <TextBlock label="Rollback" value={fix.rollbackInstructions} />
          <TextBlock label="Known limitations" value={fix.knownLimitations} />
          {fix.control && (
            <>
              <TextBlock label="How to verify" value={fix.control.verificationMethod} />
              <TextBlock label="Scope" value={fix.control.scopeDescription} />
              <TextBlock label="Residual risk" value={fix.control.residualRisk ? titleCase(fix.control.residualRisk) : null} />
            </>
          )}
          <dl className="fi-meta">
            <dt>Coverage</dt><dd>{coverageLabel(fix.remediatedAssets, fix.applicableAssets, fix.coveragePercent)}</dd>
            {fix.requiresReboot != null && (<><dt>Reboot</dt><dd>{fix.requiresReboot ? 'Required' : 'Not required'}</dd></>)}
            {fix.proposedBy && (<><dt>Proposed by</dt><dd>{fix.proposedBy}</dd></>)}
            {fix.approvedBy && (<><dt>Approved by</dt><dd>{fix.approvedBy} · {formatTimestamp(fix.approvedAt)}</dd></>)}
            <dt>Updated</dt><dd>{formatTimestamp(fix.updatedAt)}</dd>
          </dl>
        </section>

        <section className="panel">
          <h3>CVEs ({fix.cves.length})</h3>
          {fix.cves.length === 0 && <p className="muted">No CVEs linked.</p>}
          <ul className="fi-cve-list">
            {fix.cves.map((cve) => (
              <li key={cve.cveId}>
                <Link className="mono" to={`/vuln-repo/org-cves/${encodeURIComponent(cve.cveId)}`}>{cve.cveId}</Link>
                {cve.inKev && <span className="fi-kev">KEV</span>}
                <span className="muted"> · {titleCase(cve.source)}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      {fix.patchSources.length > 0 && <PatchSources fix={fix} />}

      <section className="panel">
        <h3>Assets ({fix.assetTotal})</h3>
        {fix.assets.length === 0 && <p className="muted">No assets are tracked for this fix.</p>}
        {fix.assets.length > 0 && (
          <div className="fi-table-scroll" role="region" aria-label="Assets for this fix" tabIndex={0}>
            <table className="data-table">
              <thead>
                <tr><th>Asset</th><th>Status</th><th>Source</th><th>Deployment</th><th>Scheduled</th><th>Deadline</th><th>Installed</th></tr>
              </thead>
              <tbody>
                {fix.assets.map((asset) => (
                  <tr key={`${asset.assetId}-${asset.provider}`}>
                    <td><Link to={`/inventory/hosts/${encodeURIComponent(asset.assetId)}`}>{asset.assetName ?? asset.assetIdentifier ?? asset.assetId}</Link></td>
                    <td>{titleCase(asset.status)}{asset.errorCode && <span className="muted"> ({asset.errorCode})</span>}</td>
                    <td>{providerLabel(asset.provider)}</td>
                    <td>{asset.deploymentName ?? '—'}</td>
                    <td>{asset.scheduledAt ? formatTimestamp(asset.scheduledAt) : '—'}</td>
                    <td>{asset.deadlineAt ? formatTimestamp(asset.deadlineAt) : '—'}</td>
                    <td>{asset.installedAt ? formatTimestamp(asset.installedAt) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {fix.assetTotal > fix.assets.length && <p className="muted">Showing the first {fix.assets.length} assets.</p>}
      </section>
    </div>
  );
}

function PatchSources({ fix }: { fix: FixDetail }): React.ReactElement {
  return (
    <section className="panel">
      <h3>Patch sources</h3>
      <div className="fi-table-scroll" role="region" aria-label="Patch sources" tabIndex={0}>
        <table className="data-table">
          <thead><tr><th>Tool</th><th>Tool ID</th><th>KB</th><th>Vendor severity</th><th>Released</th><th>Link</th></tr></thead>
          <tbody>
            {fix.patchSources.map((source) => (
              <tr key={`${source.provider}-${source.externalId}`}>
                <td>{providerLabel(source.provider)}{source.superseded && <span className="muted"> (superseded)</span>}</td>
                <td className="mono">{source.externalId}</td>
                <td className="mono">{source.kbArticle ? `KB${source.kbArticle.replace(/^KB/i, '')}` : '—'}</td>
                <td>{source.vendorSeverity ?? '—'}</td>
                <td>{source.releaseDate ? formatTimestamp(source.releaseDate) : '—'}</td>
                <td>
                  {source.infoUrl?.startsWith('https://')
                    ? <a href={source.infoUrl} target="_blank" rel="noopener noreferrer">Advisory</a>
                    : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function TextBlock({ label, value }: { label: string; value: string | null | undefined }): React.ReactElement | null {
  if (!value) return null;
  return (
    <div className="fi-text-block">
      <h4>{label}</h4>
      <p className="fi-plain-text">{value}</p>
    </div>
  );
}
