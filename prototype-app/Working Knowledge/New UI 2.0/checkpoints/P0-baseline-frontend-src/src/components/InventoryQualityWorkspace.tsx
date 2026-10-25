import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from './DataTable';
import { EolMappingReviewPanel } from './EolMappingReviewPanel';
import type {
  OperationalQualityIssue,
  OperationalQualityIssueDetail,
  SoftwareIdentitySearchResult
} from '../features/operations/types';
import {
  useApplyCorrelationOverrideMutation,
  useApplyNormalizationOverrideMutation,
  useClusterImpactQuery,
  useOperationalQualityFiltersQuery,
  useOperationalQualityIssueDetailQuery,
  useOperationalQualityIssuesQuery,
  useOperationalQualitySummaryQuery,
  useRevokeCorrelationOverrideMutation,
  useRevokeNormalizationOverrideMutation,
  useSoftwareIdentitySearchQuery
} from '../features/operations/queries';

const PAGE_SIZE = 25;

type InventoryQualityWorkspaceProps = {
  embedded?: boolean;
  forcedDomain?: string;
  showPanelHeader?: boolean;
  storageKeyPrefix?: string;
};

const DOMAIN_LABELS: Record<string, string> = {
  NORMALIZATION: 'Normalization',
  CORRELATION: 'Correlation',
  VEX: 'VEX',
  EOL: 'EOL'
};

const DOMAIN_DESCRIPTIONS: Record<string, string> = {
  NORMALIZATION: 'Components missing normalized names, versions, or software identity mappings.',
  CORRELATION: 'Components with no candidates, low-confidence matches, or fallback-only coverage.',
  VEX: 'Components awaiting exact VEX, stale matches, or conflicts with open findings.',
  EOL: 'Software identities with unresolved lifecycle mappings or unknown end-of-life status.'
};

const HIDDEN_DOMAINS = new Set(['INGESTION', 'PROJECTION_FRESHNESS']);

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'severity-pill severity-critical',
  HIGH: 'severity-pill severity-high',
  MEDIUM: 'severity-pill severity-medium',
  LOW: 'severity-pill severity-low'
};

function formatLabel(value: string): string {
  return value
    .trim()
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatDomain(value: string): string {
  return DOMAIN_LABELS[value] ?? formatLabel(value);
}

function formatInstant(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function scopeLabel(issue: OperationalQualityIssue): string {
  if (issue.affectedAssetCount > 0) {
    return `${issue.affectedAssetCount} asset${issue.affectedAssetCount !== 1 ? 's' : ''}`;
  }
  return `${issue.affectedComponentCount} component${issue.affectedComponentCount !== 1 ? 's' : ''}`;
}

function exposureLabel(issue: OperationalQualityIssue): string {
  return `${issue.openFindingCount} findings · ${issue.openVulnerabilityCount} vulns`;
}

function inventoryHref(issue: OperationalQualityIssue): string {
  const { sourceObjectType, sourceObjectId, primaryLabel, assetType, ecosystem } = issue;
  if (sourceObjectType === 'CLUSTER_DISCOVERY_MODEL') {
    const params = new URLSearchParams();
    if (sourceObjectId) params.set('query', sourceObjectId);
    return `/inventory/hosts?${params}`;
  }
  if (sourceObjectType === 'CLUSTER_PACKAGE_PATTERN') {
    const colonIndex = (sourceObjectId ?? '').indexOf(':');
    const eco = colonIndex >= 0 ? sourceObjectId!.slice(0, colonIndex) : '';
    const pkg = colonIndex >= 0 ? sourceObjectId!.slice(colonIndex + 1) : sourceObjectId ?? '';
    const params = new URLSearchParams();
    if (eco) params.set('ecosystem', eco);
    if (pkg) params.set('query', pkg);
    return `/inventory/sbom?${params}`;
  }
  if (assetType === 'HOST') {
    const params = new URLSearchParams();
    if (sourceObjectId) params.set('query', sourceObjectId);
    return `/inventory/hosts?${params}`;
  }
  const params = new URLSearchParams();
  if (ecosystem) params.set('ecosystem', ecosystem);
  const label = primaryLabel ?? sourceObjectId;
  if (label) params.set('query', label);
  return `/inventory/sbom?${params}`;
}

const NORMALIZATION_OVERRIDE_ISSUE_TYPES = new Set([
  'component_missing_software_identity',
  'COMPONENT_MISSING_SOFTWARE_IDENTITY',
  'host_discovery_model_review',
  'HOST_DISCOVERY_MODEL_REVIEW'
]);

const CORRELATION_OVERRIDE_ISSUE_TYPES = new Set([
  'component_no_correlation_candidates',
  'COMPONENT_NO_CORRELATION_CANDIDATES',
  'component_low_confidence_match',
  'COMPONENT_LOW_CONFIDENCE_MATCH',
  'component_fallback_only_correlation',
  'COMPONENT_FALLBACK_ONLY_CORRELATION'
]);

// VEX issues that are per-(component, vulnerability) and benefit from CVE-level grouping.
const VEX_GROUPABLE_ISSUE_TYPES = new Set([
  'awaiting_exact_vex',
  'AWAITING_EXACT_VEX',
  'stale_vex_match',
  'STALE_VEX_MATCH',
  'open_finding_conflicts_with_vex',
  'OPEN_FINDING_CONFLICTS_WITH_VEX'
]);

// INVENTORY_COMPONENT normalization issues are emitted one per component/asset,
// so multiple assets with the same package generate separate rows that need collapsing.
const INVENTORY_COMPONENT_GROUPABLE_ISSUE_TYPES = new Set([
  'component_missing_version', 'COMPONENT_MISSING_VERSION',
  'component_missing_normalized_name', 'COMPONENT_MISSING_NORMALIZED_NAME'
]);

const CLUSTER_SOURCE_TYPES = new Set(['CLUSTER_DISCOVERY_MODEL', 'CLUSTER_PACKAGE_PATTERN']);

// ─── Grouping helpers ─────────────────────────────────────────────────────

// Returns the portion of a discovery-model label before the embedded version
// number, e.g. "microsoft office 365 - en - us 16.0.7766.2092 el"
//           → "microsoft office 365 - en - us"
function extractLabelPrefix(label: string): string {
  const match = label.match(/\b\d+\.\d+(?:\.\d+)+\b/);
  if (!match || match.index === undefined) return label;
  return label.slice(0, match.index).replace(/[.\s-]+$/, '').trim();
}

// Extracts just the version number embedded in a discovery-model label.
function extractVersionFromLabel(label: string): string {
  const match = label.match(/\b\d+\.\d+(?:\.\d+)+\b/);
  return match ? match[0] : '';
}

// Only CLUSTER_DISCOVERY_MODEL normalization issues carry embedded versions.
function isVersionGroupable(issue: OperationalQualityIssue): boolean {
  return issue.sourceObjectType === 'CLUSTER_DISCOVERY_MODEL'
    && NORMALIZATION_OVERRIDE_ISSUE_TYPES.has(issue.issueType);
}

// Stable group key: issueType + sourceSystem + base label (version-stripped).
function versionGroupKey(issue: OperationalQualityIssue): string {
  const prefix = extractLabelPrefix(issue.primaryLabel ?? issue.sourceObjectId ?? '');
  return `norm::${issue.issueType}::${issue.sourceSystem ?? ''}::${prefix}`;
}

// INVENTORY_COMPONENT normalization issues: group by issueType + sourceSystem + packageName.
function isInventoryNormGroupable(issue: OperationalQualityIssue): boolean {
  return issue.sourceObjectType === 'INVENTORY_COMPONENT'
    && INVENTORY_COMPONENT_GROUPABLE_ISSUE_TYPES.has(issue.issueType);
}

function inventoryNormGroupKey(issue: OperationalQualityIssue): string {
  return `norm-inv::${issue.issueType}::${issue.sourceSystem ?? ''}::${issue.primaryLabel ?? ''}::${issue.ecosystem ?? ''}`;
}

// Correlation: one row per package+ecosystem+issueType (all assets/versions collapsed).
function isCorrelationGroupable(issue: OperationalQualityIssue): boolean {
  return CORRELATION_OVERRIDE_ISSUE_TYPES.has(issue.issueType);
}

function correlationGroupKey(issue: OperationalQualityIssue): string {
  return `corr::${issue.issueType}::${issue.ecosystem ?? ''}::${issue.primaryLabel ?? ''}`;
}

// VEX: one row per CVE+issueType (all affected components collapsed).
function isVexGroupable(issue: OperationalQualityIssue): boolean {
  return VEX_GROUPABLE_ISSUE_TYPES.has(issue.issueType);
}

function vexGroupKey(issue: OperationalQualityIssue): string {
  return `vex::${issue.issueType}::${issue.primaryLabel ?? ''}`;
}


function InlineNormalizationQuickOverridePanel({
  issue,
  onClose
}: {
  issue: OperationalQualityIssue;
  onClose: () => void;
}) {
  const [identityQuery, setIdentityQuery] = useState('');
  const debouncedQuery = useDebouncedValue(identityQuery, 300);
  const [selectedIdentity, setSelectedIdentity] = useState<SoftwareIdentitySearchResult | null>(null);
  const [reason, setReason] = useState('');
  const [applyToFuture, setApplyToFuture] = useState(true);
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const isCluster = CLUSTER_SOURCE_TYPES.has(issue.sourceObjectType);
  const impactQuery = useClusterImpactQuery(issue.id, isCluster);
  const searchQuery = useSoftwareIdentitySearchQuery(debouncedQuery);
  const applyMutation = useApplyNormalizationOverrideMutation(issue.id);
  const busy = applyMutation.isPending;

  function handleApply() {
    if (!selectedIdentity || !reason.trim()) return;
    setNotice(null);
    applyMutation.mutate(
      { softwareIdentityId: selectedIdentity.id, reason: reason.trim(), applyToFuture },
      {
        onSuccess: () => {
          setNotice({ type: 'success', message: 'Override applied. Quality projection will refresh shortly.' });
          setTimeout(onClose, 1500);
        },
        onError: (err) => setNotice({ type: 'error', message: err instanceof Error ? err.message : 'Failed to apply override' })
      }
    );
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel quality-inline-override-panel" onClick={(e) => e.stopPropagation()}>
        <div className="panel-header">
          <div>
            <h3>Set Software Identity</h3>
            <div className="panel-caption">{issue.primaryLabel ?? issue.sourceObjectId}</div>
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close">×</button>
        </div>

        {isCluster && impactQuery.data && (
          <div className="quality-cluster-impact-callout">
            Resolves issues for <strong>{impactQuery.data.affectedAssetCount.toLocaleString()} asset{impactQuery.data.affectedAssetCount !== 1 ? 's' : ''}</strong>
          </div>
        )}

        <div className="quality-override-form">
          <label className="quality-override-label" htmlFor="inline-identity-search">
            Search for a software identity
          </label>
          <input
            id="inline-identity-search"
            type="text"
            className="quality-override-input"
            placeholder="Type a package or product name…"
            value={identityQuery}
            onChange={(e) => { setIdentityQuery(e.target.value); setSelectedIdentity(null); }}
            disabled={busy}
            autoFocus
          />
          {searchQuery.data && searchQuery.data.length > 0 && !selectedIdentity && (
            <ul className="quality-identity-suggestions">
              {searchQuery.data.map((match) => (
                <li key={match.id}>
                  <button
                    type="button"
                    className="quality-identity-suggestion-btn"
                    onClick={() => { setSelectedIdentity(match); setIdentityQuery(match.displayName ?? match.canonicalKey); }}
                  >
                    <strong>{match.displayName ?? match.canonicalKey}</strong>
                    {match.canonicalKey && match.displayName !== match.canonicalKey && (
                      <span className="panel-caption"> · {match.canonicalKey}</span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {selectedIdentity && (
            <div className="quality-identity-selected">
              Selected: <strong>{selectedIdentity.displayName ?? selectedIdentity.canonicalKey}</strong>
              <button type="button" className="quality-identity-clear-btn" onClick={() => { setSelectedIdentity(null); setIdentityQuery(''); }}>×</button>
            </div>
          )}

          <label className="quality-override-label" htmlFor="inline-override-reason">
            Reason <span className="quality-override-required">*</span>
          </label>
          <textarea
            id="inline-override-reason"
            className="quality-override-textarea"
            placeholder="Explain why this identity is the correct match…"
            rows={2}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={busy}
          />

          {isCluster && (
            <label className="quality-override-future-toggle">
              <input
                type="checkbox"
                checked={applyToFuture}
                onChange={(e) => setApplyToFuture(e.target.checked)}
                disabled={busy}
              />
              {' '}Apply to new records too <span className="quality-override-recommended">(recommended)</span>
            </label>
          )}

          <div className="button-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!selectedIdentity || !reason.trim() || busy}
              onClick={handleApply}
            >
              {busy ? 'Applying…' : 'Apply Override'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={busy}>
              Cancel
            </button>
          </div>
        </div>

        {notice && (
          <div className={`notice${notice.type === 'error' ? ' error' : ''}`}>{notice.message}</div>
        )}
      </div>
    </div>
  );
}

function NormalizationOverridePanel({ issueId, detail }: { issueId: string; detail: OperationalQualityIssueDetail }) {
  const [identityQuery, setIdentityQuery] = useState('');
  const debouncedQuery = useDebouncedValue(identityQuery, 300);
  const [selectedIdentity, setSelectedIdentity] = useState<SoftwareIdentitySearchResult | null>(null);
  const [reason, setReason] = useState('');
  const [applyToFuture, setApplyToFuture] = useState(true);
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const isCluster = CLUSTER_SOURCE_TYPES.has(detail.sourceObjectType);
  const impactQuery = useClusterImpactQuery(issueId, isCluster && !detail.hasActiveOverride);

  const searchQuery = useSoftwareIdentitySearchQuery(debouncedQuery);
  const applyMutation = useApplyNormalizationOverrideMutation(issueId);
  const revokeMutation = useRevokeNormalizationOverrideMutation(issueId);

  function handleApply() {
    if (!selectedIdentity || !reason.trim()) return;
    setNotice(null);
    applyMutation.mutate(
      { softwareIdentityId: selectedIdentity.id, reason: reason.trim(), applyToFuture },
      {
        onSuccess: () => setNotice({ type: 'success', message: 'Override applied. The quality projection will refresh shortly.' }),
        onError: (err) => setNotice({ type: 'error', message: err instanceof Error ? err.message : 'Failed to apply override' })
      }
    );
  }

  function handleRevoke() {
    setNotice(null);
    revokeMutation.mutate(undefined, {
      onSuccess: () => { setNotice({ type: 'success', message: 'Override revoked.' }); setSelectedIdentity(null); setReason(''); },
      onError: (err) => setNotice({ type: 'error', message: err instanceof Error ? err.message : 'Failed to revoke override' })
    });
  }

  const busy = applyMutation.isPending || revokeMutation.isPending;

  return (
    <section className="quality-drawer-section">
      <div className="quality-drawer-section-title">Go fix it — Normalization Override</div>

      {detail.hasActiveOverride && (
        <div className="quality-override-active-badge">
          Override active{detail.overrideActor ? ` · applied by ${detail.overrideActor}` : ''}
          {detail.overrideAt ? ` on ${new Date(detail.overrideAt).toLocaleDateString()}` : ''}
        </div>
      )}

      <p className="quality-drawer-text">{detail.recommendedAction}</p>

      {!detail.hasActiveOverride && isCluster && impactQuery.data && (
        <div className="quality-cluster-impact-callout">
          This override will resolve issues for{' '}
          <strong>{impactQuery.data.affectedAssetCount.toLocaleString()} asset{impactQuery.data.affectedAssetCount !== 1 ? 's' : ''}</strong>
        </div>
      )}

      {!detail.hasActiveOverride && (
        <div className="quality-override-form">
          <label className="quality-override-label" htmlFor="identity-search">
            Search for a software identity
          </label>
          <input
            id="identity-search"
            type="text"
            className="quality-override-input"
            placeholder="Type a package or product name…"
            value={identityQuery}
            onChange={(e) => { setIdentityQuery(e.target.value); setSelectedIdentity(null); }}
            disabled={busy}
          />
          {searchQuery.data && searchQuery.data.length > 0 && !selectedIdentity && (
            <ul className="quality-identity-suggestions">
              {searchQuery.data.map((match) => (
                <li key={match.id}>
                  <button
                    type="button"
                    className="quality-identity-suggestion-btn"
                    onClick={() => { setSelectedIdentity(match); setIdentityQuery(match.displayName ?? match.canonicalKey); }}
                  >
                    <strong>{match.displayName ?? match.canonicalKey}</strong>
                    {match.canonicalKey && match.displayName !== match.canonicalKey && (
                      <span className="panel-caption"> · {match.canonicalKey}</span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          )}

          {selectedIdentity && (
            <div className="quality-identity-selected">
              Selected: <strong>{selectedIdentity.displayName ?? selectedIdentity.canonicalKey}</strong>
              <button type="button" className="quality-identity-clear-btn" onClick={() => { setSelectedIdentity(null); setIdentityQuery(''); }}>
                ×
              </button>
            </div>
          )}

          <label className="quality-override-label" htmlFor="override-reason">
            Reason <span className="quality-override-required">*</span>
          </label>
          <textarea
            id="override-reason"
            className="quality-override-textarea"
            placeholder="Explain why this identity is the correct match…"
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={busy}
          />

          {isCluster && (
            <label className="quality-override-future-toggle">
              <input
                type="checkbox"
                checked={applyToFuture}
                onChange={(e) => setApplyToFuture(e.target.checked)}
                disabled={busy}
              />
              {' '}Also apply to new records with this software key <span className="quality-override-recommended">(recommended)</span>
            </label>
          )}

          <div className="button-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!selectedIdentity || !reason.trim() || busy}
              onClick={handleApply}
            >
              {applyMutation.isPending ? 'Applying…' : 'Apply Override'}
            </button>
          </div>
        </div>
      )}

      {detail.hasActiveOverride && (
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy}
            onClick={handleRevoke}
          >
            {revokeMutation.isPending ? 'Revoking…' : 'Revoke Override'}
          </button>
        </div>
      )}

      {notice && (
        <div className={`notice${notice.type === 'error' ? ' error' : ''}`}>{notice.message}</div>
      )}

      <div className="button-row quality-drawer-links">
        {detail.drilldownTargets.map((target) => (
          <a key={`${target.label}-${target.href}`} className="btn btn-secondary" href={target.href}>
            {target.label}
          </a>
        ))}
      </div>
    </section>
  );
}

const DISPOSITION_OPTIONS: { value: 'IMPACTED' | 'NOT_IMPACTED' | 'UNKNOWN'; label: string }[] = [
  { value: 'IMPACTED', label: 'Affected' },
  { value: 'NOT_IMPACTED', label: 'Not Affected' },
  { value: 'UNKNOWN', label: 'Under Investigation' }
];

const CORRELATION_REASON_OPTIONS = [
  'Wrong CPE',
  'Version out of range',
  'Vendor advisory supersedes',
  'False positive — unrelated package',
  'Confirmed affected — manual verification',
  'Other'
];

function CorrelationOverridePanel({ issueId, detail }: { issueId: string; detail: OperationalQualityIssueDetail }) {
  const [disposition, setDisposition] = useState<'IMPACTED' | 'NOT_IMPACTED' | 'UNKNOWN' | ''>('');
  const [reasonPreset, setReasonPreset] = useState('');
  const [reasonFreeText, setReasonFreeText] = useState('');
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const applyMutation = useApplyCorrelationOverrideMutation(issueId);
  const revokeMutation = useRevokeCorrelationOverrideMutation(issueId);

  const combinedReason = reasonPreset && reasonPreset !== 'Other'
    ? reasonFreeText.trim() ? `${reasonPreset}: ${reasonFreeText.trim()}` : reasonPreset
    : reasonFreeText.trim();

  function handleApply() {
    if (!disposition || !combinedReason) return;
    setNotice(null);
    applyMutation.mutate(
      { disposition, reason: combinedReason },
      {
        onSuccess: () => setNotice({ type: 'success', message: 'Override applied. The quality projection will refresh shortly.' }),
        onError: (err) => setNotice({ type: 'error', message: err instanceof Error ? err.message : 'Failed to apply override' })
      }
    );
  }

  function handleRevoke() {
    setNotice(null);
    revokeMutation.mutate(undefined, {
      onSuccess: () => { setNotice({ type: 'success', message: 'Override revoked.' }); setDisposition(''); setReasonPreset(''); setReasonFreeText(''); },
      onError: (err) => setNotice({ type: 'error', message: err instanceof Error ? err.message : 'Failed to revoke override' })
    });
  }

  const busy = applyMutation.isPending || revokeMutation.isPending;

  return (
    <section className="quality-drawer-section">
      <div className="quality-drawer-section-title">Go fix it — Correlation Override</div>

      {detail.hasActiveOverride && (
        <div className="quality-override-active-badge">
          Override active{detail.overrideActor ? ` · applied by ${detail.overrideActor}` : ''}
          {detail.overrideAt ? ` on ${new Date(detail.overrideAt).toLocaleDateString()}` : ''}
        </div>
      )}

      <p className="quality-drawer-text">{detail.recommendedAction}</p>

      {!detail.hasActiveOverride && (
        <div className="quality-override-form">
          <fieldset className="quality-override-fieldset">
            <legend className="quality-override-label">Disposition</legend>
            <div className="quality-disposition-options">
              {DISPOSITION_OPTIONS.map((opt) => (
                <label key={opt.value} className="quality-disposition-option">
                  <input
                    type="radio"
                    name={`disposition-${issueId}`}
                    value={opt.value}
                    checked={disposition === opt.value}
                    onChange={() => setDisposition(opt.value)}
                    disabled={busy}
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </fieldset>

          <label className="quality-override-label" htmlFor="reason-preset">
            Reason <span className="quality-override-required">*</span>
          </label>
          <select
            id="reason-preset"
            className="quality-override-select"
            value={reasonPreset}
            onChange={(e) => setReasonPreset(e.target.value)}
            disabled={busy}
          >
            <option value="">Select a reason…</option>
            {CORRELATION_REASON_OPTIONS.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>

          {(reasonPreset === 'Other' || reasonPreset) && (
            <textarea
              className="quality-override-textarea"
              placeholder={reasonPreset === 'Other' ? 'Describe the reason…' : 'Optional — add more detail…'}
              rows={2}
              value={reasonFreeText}
              onChange={(e) => setReasonFreeText(e.target.value)}
              disabled={busy}
            />
          )}

          <div className="button-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!disposition || !combinedReason || busy}
              onClick={handleApply}
            >
              {applyMutation.isPending ? 'Applying…' : 'Apply Override'}
            </button>
          </div>
        </div>
      )}

      {detail.hasActiveOverride && (
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy}
            onClick={handleRevoke}
          >
            {revokeMutation.isPending ? 'Revoking…' : 'Revoke Override'}
          </button>
        </div>
      )}

      {notice && (
        <div className={`notice${notice.type === 'error' ? ' error' : ''}`}>{notice.message}</div>
      )}

      <div className="button-row quality-drawer-links">
        {detail.drilldownTargets.map((target) => (
          <a key={`${target.label}-${target.href}`} className="btn btn-secondary" href={target.href}>
            {target.label}
          </a>
        ))}
      </div>
    </section>
  );
}

function GoFixItSection({ issueId, detail }: { issueId: string; detail: OperationalQualityIssueDetail }) {
  if (detail.domain === 'NORMALIZATION' && NORMALIZATION_OVERRIDE_ISSUE_TYPES.has(detail.issueType)) {
    return <NormalizationOverridePanel issueId={issueId} detail={detail} />;
  }
  if (detail.domain === 'CORRELATION' && CORRELATION_OVERRIDE_ISSUE_TYPES.has(detail.issueType)) {
    return <CorrelationOverridePanel issueId={issueId} detail={detail} />;
  }
  return (
    <section className="quality-drawer-section">
      <div className="quality-drawer-section-title">Go fix it</div>
      <p className="quality-drawer-text">{detail.recommendedAction}</p>
      <div className="button-row quality-drawer-links">
        {detail.drilldownTargets.map((target) => (
          <a key={`${target.label}-${target.href}`} className="btn btn-secondary" href={target.href}>
            {target.label}
          </a>
        ))}
      </div>
    </section>
  );
}

function DetailDrawer({
  issueId,
  onClose
}: {
  issueId: string;
  onClose: () => void;
}) {
  const detailQuery = useOperationalQualityIssueDetailQuery(issueId);
  const detail = detailQuery.data ?? null;
  const error = detailQuery.error instanceof Error ? detailQuery.error.message : null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel modal-panel-wide quality-issue-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="panel-header">
          <div>
            <h3>Quality Issue Detail</h3>
            {detail && (
              <>
                <div>{detail.title}</div>
                <div className="panel-caption">
                  {formatDomain(detail.domain)} · {formatLabel(detail.issueType)} · {detail.reasonCode}
                </div>
              </>
            )}
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close quality issue detail">
            x
          </button>
        </div>

        {error && <div className="notice error">Unable to load quality issue detail: {error}</div>}
        {!detail && !error && <div className="notice">Loading quality issue detail...</div>}

        {detail && (
          <div className="quality-drawer-body">
            <GoFixItSection issueId={issueId} detail={detail} />

            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">What failed</div>
              <div className="quality-drawer-card-grid">
                <div className="summary-card">
                  <strong>Issue</strong>
                  <span>{detail.title}</span>
                  <span className="panel-caption">{detail.primaryLabel || detail.sourceObjectType}</span>
                </div>
                <div className="summary-card">
                  <strong>Severity</strong>
                  <span className={SEVERITY_CLASS[detail.severity] ?? 'quality-severity'}>{detail.severity}</span>
                  <span className="panel-caption">{detail.affectsActiveFindings ? 'Affects active findings' : 'No active finding impact'}</span>
                </div>
                <div className="summary-card">
                  <strong>Affected scope</strong>
                  <a href={inventoryHref(detail)} className="quality-scope-link">{scopeLabel(detail)}</a>
                  <span className="panel-caption">{exposureLabel(detail)}</span>
                </div>
              </div>
            </section>

            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">Why it matters</div>
              <p className="quality-drawer-text">{detail.whyThisMatters}</p>
            </section>

            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">Affected scope</div>
              <div className="quality-sample-list">
                {detail.sampleRecords.map((sample) => (
                  <div key={`${sample.label}-${sample.primaryValue}`} className="quality-sample-row">
                    <div className="quality-sample-label">{sample.label}</div>
                    <div className="quality-sample-value">{sample.primaryValue}</div>
                    {sample.secondaryValue && <div className="quality-sample-secondary">{sample.secondaryValue}</div>}
                  </div>
                ))}
              </div>
            </section>

            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">Evidence</div>
              <pre className="quality-evidence-block">{detail.evidenceJson}</pre>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}

export function InventoryQualityWorkspace({
  embedded = false,
  forcedDomain,
  showPanelHeader = true,
  storageKeyPrefix = 'operations-quality'
}: InventoryQualityWorkspaceProps = {}) {
  const [searchParams] = useSearchParams();
  const normalizedForcedDomain = forcedDomain?.trim().toUpperCase() ?? '';
  const forcedDomainValue = normalizedForcedDomain in DOMAIN_LABELS ? normalizedForcedDomain : '';
  const requestedDomainParam = (searchParams.get('domain') ?? '').trim().toUpperCase();
  const requestedDomain = forcedDomainValue || (requestedDomainParam in DOMAIN_LABELS ? requestedDomainParam : '');
  const [queryInput, setQueryInput] = React.useState('');
  const [domain, setDomain] = React.useState(requestedDomain);
  const [issueType, setIssueType] = React.useState('');
  const [severity, setSeverity] = React.useState('');
  const [affectsActiveFindings, setAffectsActiveFindings] = React.useState<'all' | 'yes' | 'no'>('all');
  const [assetType, setAssetType] = React.useState('');
  const [sourceSystem, setSourceSystem] = React.useState('');
  const [ecosystem, setEcosystem] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [selectedIssueId, setSelectedIssueId] = React.useState<string | null>(null);
  const [inlineOverrideIssue, setInlineOverrideIssue] = React.useState<OperationalQualityIssue | null>(null);
  const [expandedGroups, setExpandedGroups] = React.useState<Set<string>>(new Set());
  const activeDomain = forcedDomainValue || domain;
  const query = useDebouncedValue(queryInput.trim());
  const summaryQuery = useOperationalQualitySummaryQuery();
  const filtersQuery = useOperationalQualityFiltersQuery();
  const issuesQuery = useOperationalQualityIssuesQuery({
    domain: activeDomain || undefined,
    issueType: issueType || undefined,
    severity: severity || undefined,
    affectsActiveFindings: affectsActiveFindings === 'all'
      ? undefined
      : affectsActiveFindings === 'yes',
    assetType: assetType ? [assetType as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'] : undefined,
    sourceSystem: sourceSystem ? [sourceSystem] : undefined,
    ecosystem: ecosystem ? [ecosystem] : undefined,
    query: query || undefined,
    page,
    size: PAGE_SIZE
  });
  const summary = summaryQuery.data ?? null;
  const filters = filtersQuery.data ?? null;
  const pageData = issuesQuery.data ?? null;
  const loading = summaryQuery.isLoading || filtersQuery.isLoading || issuesQuery.isLoading || issuesQuery.isFetching;
  const error = issuesQuery.error instanceof Error
    ? issuesQuery.error.message
    : summaryQuery.error instanceof Error
      ? summaryQuery.error.message
      : filtersQuery.error instanceof Error
        ? filtersQuery.error.message
        : null;

  React.useEffect(() => {
    setDomain(requestedDomain);
  }, [requestedDomain]);

  React.useEffect(() => {
    setPage(0);
  }, [activeDomain, issueType, severity, affectsActiveFindings, assetType, sourceSystem, ecosystem, query]);

  const issues = React.useMemo(
    () => (pageData?.items ?? []).filter(i => !HIDDEN_DOMAINS.has(i.domain.toUpperCase())),
    [pageData?.items]
  );
  const eolReviewFilters = React.useMemo(() => ({
    issueType: issueType || undefined,
    severity: severity || undefined,
    affectsActiveFindings: affectsActiveFindings === 'all'
      ? undefined
      : affectsActiveFindings === 'yes',
    assetType: assetType ? [assetType as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'] : undefined,
    sourceSystem: sourceSystem ? [sourceSystem] : undefined,
    ecosystem: ecosystem ? [ecosystem] : undefined,
    query: query || undefined
  }), [affectsActiveFindings, assetType, ecosystem, issueType, query, severity, sourceSystem]);
  const issueColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'issue', label: 'Issue', header: 'Issue', initialSize: 240 },
    { id: 'domain', label: 'Domain', header: 'Domain', initialSize: 140 },
    { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
    { id: 'source', label: 'Source / Object', header: 'Source / Object', initialSize: 200 },
    { id: 'scope', label: 'Affected Scope', header: 'Affected Scope', initialSize: 150 },
    { id: 'lastSeen', label: 'Last Seen', header: 'Last Seen', initialSize: 160 },
    { id: 'actions', label: 'Actions', header: 'Actions', initialSize: 130 }
  ], []);
  const issueRows = React.useMemo<DataTableRow[]>(() => {
    // Pre-build group maps for all groupable domains
    const groupMap = new Map<string, OperationalQualityIssue[]>();
    issues.forEach(issue => {
      let key: string | null = null;
      if (isVersionGroupable(issue)) key = versionGroupKey(issue);
      else if (isInventoryNormGroupable(issue)) key = inventoryNormGroupKey(issue);
      else if (isCorrelationGroupable(issue)) key = correlationGroupKey(issue);
      else if (isVexGroupable(issue)) key = vexGroupKey(issue);
      if (!key) return;
      const arr = groupMap.get(key) ?? [];
      arr.push(issue);
      groupMap.set(key, arr);
    });

    const processedGroupKeys = new Set<string>();
    const rows: DataTableRow[] = [];

    function buildIssueRow(issue: OperationalQualityIssue, isChild = false): DataTableRow {
      const isNormalizationOverride = NORMALIZATION_OVERRIDE_ISSUE_TYPES.has(issue.issueType);
      // INVENTORY_COMPONENT children don't carry an embedded version — the meaningful
      // differentiator between children in the same group is the affected asset.
      const version = isChild
        ? issue.sourceObjectType === 'INVENTORY_COMPONENT'
          ? (issue.secondaryLabel || issue.primaryLabel || '-')
          : (extractVersionFromLabel(issue.primaryLabel ?? issue.sourceObjectId ?? '') || (issue.primaryLabel ?? issue.sourceObjectId ?? '-'))
        : '';
      return {
        id: issue.id,
        rowProps: {
          className: isChild ? 'quality-table-row si-version-row' : 'quality-table-row',
          onClick: () => setSelectedIssueId(issue.id)
        },
        cells: {
          issue: {
            content: isChild ? (
              <div className="quality-version-child-cell">
                <span className="si-version-indent">↳</span>
                <span className="mono si-version-tag">{version}</span>
              </div>
            ) : (
              <button type="button" className="quality-row-button" onClick={() => setSelectedIssueId(issue.id)}>
                <span>{issue.title}</span>
                <span className="panel-caption">{issue.primaryLabel || issue.reasonCode}</span>
              </button>
            )
          },
          domain: { content: isChild ? null : formatDomain(issue.domain) },
          severity: {
            content: isChild ? null : <span className={SEVERITY_CLASS[issue.severity] ?? 'quality-severity'}>{issue.severity}</span>
          },
          source: {
            content: isChild ? null : (
              <div className="software-identity-row-stack">
                <span>{issue.sourceSystem ? formatLabel(issue.sourceSystem) : issue.sourceObjectType}</span>
                {!CLUSTER_SOURCE_TYPES.has(issue.sourceObjectType) && (
                  <span className="panel-caption">{issue.secondaryLabel || issue.sourceObjectId || '-'}</span>
                )}
              </div>
            )
          },
          scope: {
            content: (
              <a href={inventoryHref(issue)} className="quality-scope-link" onClick={e => e.stopPropagation()}>
                {scopeLabel(issue)}
              </a>
            )
          },
          lastSeen: { content: formatInstant(issue.lastSeenAt) },
          actions: {
            content: isNormalizationOverride ? (
              <button
                type="button"
                className="btn btn-xs quality-inline-override-btn"
                onClick={e => { e.stopPropagation(); setInlineOverrideIssue(issue); }}
              >
                Set Identity
              </button>
            ) : (
              <button
                type="button"
                className="btn btn-xs quality-inline-detail-btn"
                onClick={e => { e.stopPropagation(); setSelectedIssueId(issue.id); }}
              >
                View Detail
              </button>
            )
          }
        }
      };
    }

    function buildGroupParentRow(groupKey: string, groupIssues: OperationalQualityIssue[]): DataTableRow {
      const rep = groupIssues[0];
      const isExpanded = expandedGroups.has(groupKey);
      // INVENTORY_COMPONENT issues are per-asset (no embedded version in the label).
      // CLUSTER_DISCOVERY_MODEL labels embed version strings that need stripping.
      const isInventoryNorm = rep.sourceObjectType === 'INVENTORY_COMPONENT';
      const baseLabel = isInventoryNorm
        ? (rep.primaryLabel ?? rep.sourceObjectId ?? '')
        : extractLabelPrefix(rep.primaryLabel ?? rep.sourceObjectId ?? '');
      const totalAssets = groupIssues.reduce((sum, i) => sum + i.affectedAssetCount, 0);
      const mostRecentSeen = groupIssues.map(i => i.lastSeenAt).filter(Boolean).sort().pop();

      // INVENTORY_COMPONENT: link using the existing inventoryHref logic (handles HOST vs SBOM).
      // CLUSTER_DISCOVERY_MODEL: link to hosts by cluster key.
      const parentHref = isInventoryNorm
        ? inventoryHref(rep)
        : `/inventory/hosts?${new URLSearchParams({ query: baseLabel })}`;

      return {
        id: `group::${groupKey}`,
        rowProps: {
          className: `quality-table-row si-identity-row${isExpanded ? ' si-identity-row-expanded' : ''}`,
          onClick: () => setExpandedGroups(prev => {
            const next = new Set(prev);
            if (next.has(groupKey)) next.delete(groupKey); else next.add(groupKey);
            return next;
          })
        },
        cells: {
          issue: {
            content: (
              <div className="si-identity-name-cell">
                <span className={`si-expand-toggle${isExpanded ? ' si-expand-toggle-open' : ''}`}>▶</span>
                <div>
                  <div>{rep.title}</div>
                  <div className="panel-caption">{baseLabel}</div>
                  <div className="panel-caption si-version-count">
                    {isInventoryNorm
                      ? `${groupIssues.length} asset${groupIssues.length !== 1 ? 's' : ''}`
                      : `${groupIssues.length} versions`}
                  </div>
                </div>
              </div>
            )
          },
          domain: { content: formatDomain(rep.domain) },
          severity: { content: <span className={SEVERITY_CLASS[rep.severity] ?? 'quality-severity'}>{rep.severity}</span> },
          source: {
            content: (
              <div className="software-identity-row-stack">
                <span>{rep.sourceSystem ? formatLabel(rep.sourceSystem) : rep.sourceObjectType}</span>
              </div>
            )
          },
          scope: {
            content: (
              <a href={parentHref} className="quality-scope-link" onClick={e => e.stopPropagation()}>
                {totalAssets.toLocaleString()} asset{totalAssets !== 1 ? 's' : ''}
              </a>
            )
          },
          lastSeen: { content: formatInstant(mostRecentSeen) },
          actions: {
            content: (
              <button
                type="button"
                className="btn btn-xs quality-inline-override-btn"
                onClick={e => { e.stopPropagation(); setInlineOverrideIssue(rep); }}
              >
                Set Identity
              </button>
            )
          }
        }
      };
    }

    // Flat (no expand) group row for Correlation and VEX domains.
    function buildFlatGroupRow(groupKey: string, groupIssues: OperationalQualityIssue[]): DataTableRow {
      const rep = groupIssues[0];
      const mostRecentSeen = groupIssues.map(i => i.lastSeenAt).filter(Boolean).sort().pop();
      // Each correlation/VEX issue has affectedAssetCount=1 and affectedComponentCount=1 (one per
      // component×asset pair), so summing them does not yield a meaningful unique-asset count.
      // No inventory filter exists that returns exactly the components with quality issues, so we
      // show a plain instance count instead of a potentially misleading linked scope count.
      return {
        id: `flat-group::${groupKey}`,
        rowProps: {
          className: 'quality-table-row',
          onClick: () => setSelectedIssueId(rep.id)
        },
        cells: {
          issue: {
            content: (
              <button type="button" className="quality-row-button" onClick={() => setSelectedIssueId(rep.id)}>
                <span>{rep.title}</span>
                <span className="panel-caption">
                  {rep.primaryLabel || rep.reasonCode}
                  {groupIssues.length > 1 && (
                    <span className="panel-caption si-version-count"> · {groupIssues.length} instances</span>
                  )}
                </span>
              </button>
            )
          },
          domain: { content: formatDomain(rep.domain) },
          severity: {
            content: <span className={SEVERITY_CLASS[rep.severity] ?? 'quality-severity'}>{rep.severity}</span>
          },
          source: {
            content: (
              <div className="software-identity-row-stack">
                <span>{rep.sourceSystem ? formatLabel(rep.sourceSystem) : rep.sourceObjectType}</span>
                {rep.ecosystem && <span className="panel-caption">{rep.ecosystem}</span>}
              </div>
            )
          },
          scope: {
            content: (
              <span className="quality-scope-plain">
                {groupIssues.length.toLocaleString()} instance{groupIssues.length !== 1 ? 's' : ''}
              </span>
            )
          },
          lastSeen: { content: formatInstant(mostRecentSeen) },
          actions: {
            content: (
              <button
                type="button"
                className="btn btn-xs quality-inline-detail-btn"
                onClick={e => { e.stopPropagation(); setSelectedIssueId(rep.id); }}
              >
                View Detail
              </button>
            )
          }
        }
      };
    }

    issues.forEach(issue => {
      if (isVersionGroupable(issue)) {
        const key = versionGroupKey(issue);
        if (processedGroupKeys.has(key)) return;
        processedGroupKeys.add(key);
        const groupIssues = groupMap.get(key)!;
        if (groupIssues.length > 1) {
          rows.push(buildGroupParentRow(key, groupIssues));
          if (expandedGroups.has(key)) {
            groupIssues.forEach(child => rows.push(buildIssueRow(child, true)));
          }
        } else {
          rows.push(buildIssueRow(groupIssues[0]));
        }
      } else if (isInventoryNormGroupable(issue)) {
        const key = inventoryNormGroupKey(issue);
        if (processedGroupKeys.has(key)) return;
        processedGroupKeys.add(key);
        const groupIssues = groupMap.get(key)!;
        if (groupIssues.length > 1) {
          rows.push(buildGroupParentRow(key, groupIssues));
          if (expandedGroups.has(key)) {
            groupIssues.forEach(child => rows.push(buildIssueRow(child, true)));
          }
        } else {
          rows.push(buildIssueRow(groupIssues[0]));
        }
      } else if (isCorrelationGroupable(issue) || isVexGroupable(issue)) {
        const key = isCorrelationGroupable(issue) ? correlationGroupKey(issue) : vexGroupKey(issue);
        if (processedGroupKeys.has(key)) return;
        processedGroupKeys.add(key);
        const groupIssues = groupMap.get(key)!;
        if (groupIssues.length > 1) {
          rows.push(buildFlatGroupRow(key, groupIssues));
        } else {
          rows.push(buildIssueRow(groupIssues[0]));
        }
      } else {
        rows.push(buildIssueRow(issue));
      }
    });

    return rows;
  }, [issues, expandedGroups]);

  return (
    <div className={`page-grid${embedded ? ' page-grid-embedded' : ''}`}>
      <section className="panel">
        {showPanelHeader && (
          <div className="panel-header">
            <div>
              <h3>Quality</h3>
            </div>
            {summary && <span className="panel-caption">Last updated {formatInstant(summary.generatedAt)}</span>}
          </div>
        )}

        {activeDomain === '' ? (
          // Hub: no domain selected — show one card per domain
          <div className="quality-domain-hub">
            {summary
              ? summary.domainCounts
                  .filter(e => !HIDDEN_DOMAINS.has(e.domain.toUpperCase()))
                  .map((entry) => (
                    <button
                      key={entry.domain}
                      type="button"
                      className="quality-domain-hub-card"
                      onClick={() => setDomain(entry.domain)}
                    >
                      <span className="quality-domain-hub-label">{formatDomain(entry.domain)}</span>
                      <span className="quality-domain-hub-count">{entry.issueCount.toLocaleString()}</span>
                      <span className="quality-domain-hub-desc">
                        {DOMAIN_DESCRIPTIONS[entry.domain.toUpperCase()] ?? ''}
                      </span>
                    </button>
                  ))
              : <div className="empty-state"><p>Loading quality summary…</p></div>
            }
          </div>
        ) : (
          // Workspace: a domain is selected
          <>
            <div className="quality-domain-workspace-header">
              {!forcedDomainValue && (
                <button
                  type="button"
                  className="quality-domain-back-btn"
                  onClick={() => {
                    setDomain('');
                    setIssueType('');
                    setSeverity('');
                    setAffectsActiveFindings('all');
                    setAssetType('');
                    setSourceSystem('');
                    setEcosystem('');
                    setQueryInput('');
                  }}
                >
                  ← Quality
                </button>
              )}
              <h4 className="quality-domain-workspace-title">{formatDomain(activeDomain)}</h4>
              {summary && (
                <span className="panel-caption">
                  {(summary.domainCounts.find(e => e.domain === activeDomain)?.issueCount ?? 0).toLocaleString()} issues
                </span>
              )}
            </div>

            <div className={`toolbar quality-filter-toolbar${embedded ? ' quality-filter-toolbar-embedded' : ''}`}>
              <label className="software-identity-filter software-identity-filter--search">
                <span className="panel-caption">Search issues</span>
                <input
                  value={queryInput}
                  onChange={(event) => setQueryInput(event.target.value)}
                  placeholder="Title, reason code, label, source"
                />
              </label>

              <label className="software-identity-filter">
                <span className="panel-caption">Issue Type</span>
                <select value={issueType} onChange={(event) => setIssueType(event.target.value)}>
                  <option value="">All Issue Types</option>
                  {filters?.issueTypes.map((value) => (
                    <option key={value} value={value}>{formatLabel(value)}</option>
                  ))}
                </select>
              </label>

              <label className="software-identity-filter">
                <span className="panel-caption">Severity</span>
                <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
                  <option value="">All Severities</option>
                  {filters?.severities.map((value) => (
                    <option key={value} value={value}>{formatLabel(value)}</option>
                  ))}
                </select>
              </label>

              <label className="software-identity-filter">
                <span className="panel-caption">Active Findings</span>
                <select value={affectsActiveFindings} onChange={(event) => setAffectsActiveFindings(event.target.value as 'all' | 'yes' | 'no')}>
                  <option value="all">All</option>
                  <option value="yes">Affects findings</option>
                  <option value="no">No finding impact</option>
                </select>
              </label>

              <label className="software-identity-filter">
                <span className="panel-caption">Asset Type</span>
                <select value={assetType} onChange={(event) => setAssetType(event.target.value)}>
                  <option value="">All Asset Types</option>
                  {filters?.assetTypes.map((value) => (
                    <option key={value} value={value}>{formatLabel(value)}</option>
                  ))}
                </select>
              </label>

              <label className="software-identity-filter">
                <span className="panel-caption">Source</span>
                <select value={sourceSystem} onChange={(event) => setSourceSystem(event.target.value)}>
                  <option value="">All Sources</option>
                  {filters?.sourceSystems.map((value) => (
                    <option key={value} value={value}>{formatLabel(value)}</option>
                  ))}
                </select>
              </label>

              <label className="software-identity-filter">
                <span className="panel-caption">Ecosystem</span>
                <select value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}>
                  <option value="">All Ecosystems</option>
                  {filters?.ecosystems.map((value) => (
                    <option key={value} value={value}>{formatLabel(value)}</option>
                  ))}
                </select>
              </label>
            </div>

            {activeDomain === 'EOL' ? (
              <EolMappingReviewPanel qualityFilters={eolReviewFilters} />
            ) : (
              <>
                {error && <div className="notice error">Failed to load quality issues: {error}</div>}
                {loading && !pageData && <div className="notice">Loading quality issues...</div>}

                {!loading && issues.length === 0 && !error && (
                  <div className="empty-state">
                    <p>No quality issues match the current filters.</p>
                  </div>
                )}

                {issues.length > 0 && (
                  <>
                    <div className="table-scroll">
                      <DataTable
                        storageKey={`${storageKeyPrefix}-issues`}
                        columns={issueColumns}
                        rows={issueRows}
                      />
                    </div>

                    <div className="pagination quality-pagination">
                      <button type="button" onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={page === 0}>
                        Previous
                      </button>
                      <span>
                        Page {(pageData?.page ?? 0) + 1} of {Math.max(1, pageData?.totalPages ?? 1)}
                      </span>
                      <button
                        type="button"
                        onClick={() => setPage((current) => (pageData && current + 1 < pageData.totalPages ? current + 1 : current))}
                        disabled={!pageData || page + 1 >= pageData.totalPages}
                      >
                        Next
                      </button>
                    </div>
                  </>
                )}
              </>
            )}
          </>
        )}
      </section>

      {selectedIssueId && <DetailDrawer issueId={selectedIssueId} onClose={() => setSelectedIssueId(null)} />}
      {inlineOverrideIssue && (
        <InlineNormalizationQuickOverridePanel
          issue={inlineOverrideIssue}
          onClose={() => setInlineOverrideIssue(null)}
        />
      )}
    </div>
  );
}
