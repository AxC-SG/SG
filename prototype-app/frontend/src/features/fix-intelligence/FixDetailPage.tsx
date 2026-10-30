import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { usePageHeader } from '../../app/pageHeaderState';
import { AsyncSection } from '../../components/AsyncSection';
import { ConfirmDialog } from '../../components/ConfirmDialog';
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
  const [actionResult, setActionResult] = React.useState<string | null>(null);
  const [confirmingRetire, setConfirmingRetire] = React.useState(false);
  const [retireError, setRetireError] = React.useState<string | null>(null);

  const detailQuery = useQuery({
    queryKey: ['fix-intelligence', 'detail', fixId],
    queryFn: () => fixIntelligenceApi.detail(fixId),
    enabled: !!fixId
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['fix-intelligence'] });
  const approve = useMutation({
    mutationFn: () => fixIntelligenceApi.approve(fixId),
    onMutate: () => { setActionError(null); setActionResult(null); },
    onSuccess: (updated) => { setActionResult(`Fix approved. Status: ${titleCase(updated.status)}.`); void refresh(); },
    onError: (failure: Error) => setActionError(failure.message)
  });
  // A failed retire keeps the dialog open with the server's reason; success closes it and reports the result.
  const retire = useMutation({
    mutationFn: () => fixIntelligenceApi.retire(fixId),
    onMutate: () => { setRetireError(null); setActionError(null); setActionResult(null); },
    onSuccess: (updated) => {
      setConfirmingRetire(false);
      setActionResult(`Fix retired. Status: ${titleCase(updated.status)}.`);
      void refresh();
    },
    onError: (failure: Error) => setRetireError(failure.message)
  });

  // The shell owns the route H1; the fix title replaces the fallback once the record is known.
  usePageHeader(detailQuery.data ? { title: detailQuery.data.title } : null);

  if (!detailQuery.data) {
    const notFound = detailQuery.error instanceof ApiError && detailQuery.error.status === 404;
    return (
      <div className="page-grid fi-page ui2-fix-family">
        <AsyncSection
          state={detailQuery.isError ? 'error' : 'pending'}
          loadingLabel="Loading fix…"
          errorMessage={notFound ? 'This fix was not found.' : 'This fix could not be loaded.'}
          onRetry={() => void detailQuery.refetch()}
          retryLabel="Retry fix"
          retrying={detailQuery.isFetching}
        />
        {detailQuery.isError && <Link to="/fix-intelligence/all">Back to Fix Intelligence</Link>}
      </div>
    );
  }

  const fix = detailQuery.data;
  const isOwnProposal = !!fix.proposedBy && fix.proposedBy === actor?.userId;
  const canEdit = fix.editable && fix.status !== 'RETIRED' && canManageFixControls(actor);
  const canApprove = fix.editable && fix.status === 'PROPOSED' && canApproveFixControls(actor);
  const canRetire = fix.editable && fix.status !== 'RETIRED' && canApproveFixControls(actor);
  const eligibility = lifecycleEligibility(fix, isOwnProposal, canApproveFixControls(actor));

  return (
    <div className="page-grid fi-page ui2-fix-family">
      <Link className="fi-back" to="/fix-intelligence/all">← All fixes</Link>
      <header className="fi-header">
        <div>
          <span className="fi-eyebrow mono">{fix.displayId}</span>
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
              aria-describedby={eligibility ? 'fi-lifecycle-eligibility' : undefined}
              onClick={() => approve.mutate()}
            >
              {approve.isPending ? 'Approving…' : 'Approve'}
            </button>
          )}
          {canRetire && (
            <button type="button" className="btn" disabled={retire.isPending} onClick={() => { setRetireError(null); setConfirmingRetire(true); }}>Retire</button>
          )}
        </div>
      </header>
      {eligibility && <p id="fi-lifecycle-eligibility" className="fi-eligibility">{eligibility}</p>}
      {actionError && <div className="notice error" role="alert">{actionError}</div>}
      {actionResult && <div className="notice success" role="status">{actionResult}</div>}
      <ConfirmDialog
        isOpen={confirmingRetire}
        title="Retire this fix?"
        message={(
          <>
            <p>
              {fix.title} will be retired. A retired fix can no longer be edited, approved or retired from this page.
              Fixes are remediation context only, so no finding status changes.
            </p>
            {retireError && <div className="notice error" role="alert">{retireError}</div>}
          </>
        )}
        confirmLabel="Retire fix"
        busy={retire.isPending}
        busyMessage="Retiring fix…"
        onConfirm={() => retire.mutate()}
        onCancel={() => setConfirmingRetire(false)}
      />
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
          onSaved={(saved) => {
            setEditing(false);
            setActionError(null);
            setActionResult(`Changes saved. Status: ${titleCase(saved.status)}.`);
          }}
        />
      )}

      <div className="fi-detail-grid">
        <section className="panel">
          <h2>Overview</h2>
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
          <h2>CVEs ({fix.cves.length})</h2>
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
        <h2>Assets ({fix.assetTotal})</h2>
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
      <h2>Patch sources</h2>
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

/** Why lifecycle actions are or are not available, stated up front instead of only in a tooltip. */
function lifecycleEligibility(fix: FixDetail, isOwnProposal: boolean, isTenantAdmin: boolean): string | null {
  if (!fix.editable) return null;
  if (fix.status === 'RETIRED') return 'This fix is retired. It can no longer be edited, approved or retired.';
  if (fix.status === 'DRAFT') return 'Draft. Submit it for approval before it can be approved.';
  if (fix.status !== 'PROPOSED') return null;
  if (isOwnProposal) return 'You proposed this fix, so another tenant administrator must approve it.';
  if (!isTenantAdmin) return 'Awaiting approval. A tenant administrator other than the proposer can approve it.';
  return null;
}

function TextBlock({ label, value }: { label: string; value: string | null | undefined }): React.ReactElement | null {
  if (!value) return null;
  return (
    <div className="fi-text-block">
      <h3>{label}</h3>
      <p className="fi-plain-text">{value}</p>
    </div>
  );
}
