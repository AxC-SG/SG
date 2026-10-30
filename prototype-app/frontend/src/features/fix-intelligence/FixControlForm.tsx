import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { fixIntelligenceApi } from './api';
import { ECOSYSTEM_ORDER, SEVERITY_ORDER, ecosystemLabel, fixTypeLabel, titleCase } from './format';
import type { ControlFixType, FixControlRequest, FixDetail } from './types';

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const ASSET_LIST_LIMIT = 50;

type Props = {
  defaultType: ControlFixType;
  /** Present when editing; the type is then fixed. */
  existing?: FixDetail;
  onCancel: () => void;
  onSaved: (fix: FixDetail) => void;
};

/** Create or edit a workaround, configuration change or compensating control. */
export function FixControlForm({ defaultType, existing, onCancel, onSaved }: Props): React.ReactElement {
  const queryClient = useQueryClient();
  const [fixType, setFixType] = React.useState<ControlFixType>((existing?.fixType as ControlFixType) ?? defaultType);
  const [title, setTitle] = React.useState(existing?.title ?? '');
  const [description, setDescription] = React.useState(existing?.description ?? '');
  const [severity, setSeverity] = React.useState(existing?.severity ?? '');
  const [ecosystem, setEcosystem] = React.useState(existing?.ecosystem ?? 'CROSS_PLATFORM');
  const [instructions, setInstructions] = React.useState(existing?.installationInstructions ?? '');
  const [rollback, setRollback] = React.useState(existing?.rollbackInstructions ?? '');
  const [verification, setVerification] = React.useState(existing?.control?.verificationMethod ?? '');
  const [residualRisk, setResidualRisk] = React.useState(existing?.control?.residualRisk ?? '');
  const [cveText, setCveText] = React.useState(
    (existing?.cves ?? []).filter((cve) => cve.source === 'ANALYST').map((cve) => cve.cveId).join(', ')
  );
  const [assetIds, setAssetIds] = React.useState<string[]>(
    (existing?.assets ?? []).filter((asset) => asset.provider === 'ANALYST').map((asset) => asset.assetId)
  );
  const [assetSearch, setAssetSearch] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [invalidField, setInvalidField] = React.useState<'title' | 'cves' | null>(null);
  const [confirmingDiscard, setConfirmingDiscard] = React.useState(false);
  const errorId = React.useId();
  const activeNoticeId = React.useId();

  // Dirty compares the editable values with what the form opened with; the asset filter is not a change.
  const values = JSON.stringify([fixType, title, description, severity, ecosystem, instructions, rollback, verification, residualRisk, cveText, [...assetIds].sort()]);
  const [initialValues] = React.useState(values);
  const dirty = values !== initialValues;
  const editingActive = existing?.status === 'ACTIVE';

  const assetsQuery = useQuery({ queryKey: ['fix-intelligence', 'scope-assets'], queryFn: api.listAssets });
  const matchingAssets = React.useMemo(() => {
    const term = assetSearch.trim().toLowerCase();
    return (assetsQuery.data ?? [])
      .filter((asset) => !term || asset.name.toLowerCase().includes(term) || asset.identifier.toLowerCase().includes(term))
      .slice(0, ASSET_LIST_LIMIT);
  }, [assetSearch, assetsQuery.data]);

  const mutation = useMutation({
    mutationFn: (payload: FixControlRequest) =>
      existing ? fixIntelligenceApi.update(existing.id, payload) : fixIntelligenceApi.create(payload),
    onSuccess: (fix) => {
      void queryClient.invalidateQueries({ queryKey: ['fix-intelligence'] });
      onSaved(fix);
    },
    onError: (failure: Error) => setError(failure.message)
  });

  const submit = (propose: boolean) => {
    const cveIds = cveText.split(/[\s,]+/).map((value) => value.trim().toUpperCase()).filter(Boolean);
    const invalid = cveIds.find((cve) => !CVE_PATTERN.test(cve));
    if (!title.trim()) { setInvalidField('title'); return setError('A title is required.'); }
    if (invalid) { setInvalidField('cves'); return setError(`${invalid} is not a CVE ID.`); }
    setError(null);
    setInvalidField(null);
    mutation.mutate({
      fixType,
      title: title.trim(),
      description: description || null,
      severity: severity || null,
      ecosystem: ecosystem || null,
      installationInstructions: instructions || null,
      rollbackInstructions: rollback || null,
      verificationMethod: verification || null,
      residualRisk: residualRisk || null,
      cveIds,
      assetIds,
      submit: propose,
      version: existing?.version ?? null
    });
  };

  const toggleAsset = (id: string) =>
    setAssetIds((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);

  return (
    <section className="panel fi-form" aria-label={existing ? 'Edit fix' : 'New fix'}>
      <h2>{existing ? `Edit ${fixTypeLabel(existing.fixType).toLowerCase()}` : 'New fix'}</h2>
      {editingActive && (
        <p id={activeNoticeId} className="notice warning">
          This control is active. Saving any change returns it to Proposed, and it must be approved again by a tenant administrator.
        </p>
      )}
      <div className="fi-form-grid">
        <label className="fi-field">Type
          <select className="input" value={fixType} disabled={!!existing}
                  onChange={(event) => setFixType(event.target.value as ControlFixType)}>
            {(['WORKAROUND', 'CONFIGURATION_CHANGE', 'COMPENSATING_CONTROL'] as const).map((type) => (
              <option key={type} value={type}>{fixTypeLabel(type)}</option>
            ))}
          </select>
        </label>
        <label className="fi-field fi-field--wide">
          <span>Title <span className="muted">(required)</span></span>
          <input className="input" value={title} maxLength={500} aria-required="true"
                 aria-invalid={invalidField === 'title' || undefined}
                 aria-describedby={invalidField === 'title' ? errorId : undefined}
                 onChange={(event) => setTitle(event.target.value)} />
        </label>
        <label className="fi-field">Severity
          <select className="input" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">Unrated</option>
            {SEVERITY_ORDER.map((key) => <option key={key} value={key}>{titleCase(key)}</option>)}
          </select>
        </label>
        <label className="fi-field">Ecosystem
          <select className="input" value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}>
            {ECOSYSTEM_ORDER.map((key) => <option key={key} value={key}>{ecosystemLabel(key)}</option>)}
          </select>
        </label>
        <label className="fi-field">Residual risk
          <select className="input" value={residualRisk} onChange={(event) => setResidualRisk(event.target.value)}>
            <option value="">Not assessed</option>
            {['HIGH', 'MEDIUM', 'LOW'].map((key) => <option key={key} value={key}>{titleCase(key)}</option>)}
          </select>
        </label>
        <label className="fi-field fi-field--wide">CVEs (comma separated)
          <input className="input" value={cveText} placeholder="CVE-2024-21412, CVE-2024-21413"
                 aria-invalid={invalidField === 'cves' || undefined}
                 aria-describedby={invalidField === 'cves' ? errorId : undefined}
                 onChange={(event) => setCveText(event.target.value)} />
        </label>
        <label className="fi-field fi-field--wide">Description
          <textarea className="input" rows={3} value={description} onChange={(event) => setDescription(event.target.value)} />
        </label>
        <label className="fi-field fi-field--wide">How to apply
          <textarea className="input" rows={3} value={instructions} onChange={(event) => setInstructions(event.target.value)} />
        </label>
        <label className="fi-field fi-field--wide">Rollback
          <textarea className="input" rows={2} value={rollback} onChange={(event) => setRollback(event.target.value)} />
        </label>
        <label className="fi-field fi-field--wide">How to verify
          <textarea className="input" rows={2} value={verification} onChange={(event) => setVerification(event.target.value)} />
        </label>
      </div>

      <fieldset className="fi-asset-scope">
        <legend>Assets in scope ({assetIds.length} selected)</legend>
        <input className="input" type="search" placeholder="Filter assets" aria-label="Filter assets"
               value={assetSearch} onChange={(event) => setAssetSearch(event.target.value)} />
        {assetsQuery.isLoading && <p className="muted" role="status">Loading assets…</p>}
        {assetsQuery.isError && <div className="notice error fi-error" role="alert">
          <span>Assets could not be loaded. Retry before changing the scope.</span>
          <button type="button" className="btn" onClick={() => void assetsQuery.refetch()}>Retry assets</button>
        </div>}
        <div className="fi-asset-list">
          {matchingAssets.map((asset) => (
            <label key={asset.id} className="fi-asset-option">
              <input type="checkbox" checked={assetIds.includes(asset.id)} onChange={() => toggleAsset(asset.id)} />
              {asset.name} <span className="muted mono">{asset.identifier}</span>
            </label>
          ))}
          {assetsQuery.isSuccess && matchingAssets.length === 0 && <span className="muted">No matching assets.</span>}
        </div>
      </fieldset>

      {error && <div id={errorId} className="notice error" role="alert">{error}</div>}
      <div className="fi-form-actions">
        {mutation.isPending
          ? <span className="fi-dirty" role="status">Saving…</span>
          : dirty && <span className="fi-dirty">Unsaved changes</span>}
        <button type="button" className="btn" onClick={() => (dirty ? setConfirmingDiscard(true) : onCancel())} disabled={mutation.isPending}>Cancel</button>
        <button type="button" className="btn" onClick={() => submit(false)} disabled={mutation.isPending}
                aria-describedby={editingActive ? activeNoticeId : undefined}>Save draft</button>
        <button type="button" className="btn btn-primary" onClick={() => submit(true)} disabled={mutation.isPending}
                aria-describedby={editingActive ? activeNoticeId : undefined}>
          Submit for approval
        </button>
      </div>
      <ConfirmDialog
        isOpen={confirmingDiscard}
        title="Discard unsaved changes?"
        message="Your changes to this fix have not been saved."
        confirmLabel="Discard changes"
        cancelLabel="Keep editing"
        onConfirm={() => { setConfirmingDiscard(false); onCancel(); }}
        onCancel={() => setConfirmingDiscard(false)}
      />
    </section>
  );
}
