import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type BomIngestKey } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { DataTable, type DataTableColumn, type DataTableRow } from '../../components/DataTable';
import { canManageServiceAccounts } from '../auth/roles';
import { useActor } from '../auth/context';
import { formatTimestamp } from '../../lib/time';

const KEYS_QUERY_KEY = ['bom-ingest-keys'];

const COLUMNS: DataTableColumn[] = [
  { id: 'name', label: 'Name', header: 'Name', initialSize: 200, priority: 'essential' },
  { id: 'prefix', label: 'Key', header: 'Key', initialSize: 190 },
  { id: 'state', label: 'State', header: 'State', initialSize: 110 },
  { id: 'created', label: 'Created', header: 'Created', initialSize: 170 },
  { id: 'expires', label: 'Expires', header: 'Expires', initialSize: 170 },
  { id: 'lastUsed', label: 'Last used', header: 'Last used', initialSize: 170 },
  { id: 'actions', label: 'Actions', header: 'Actions', initialSize: 110, priority: 'essential' },
];

const EXPIRY_OPTIONS: { value: string; label: string }[] = [
  { value: '30', label: '30 days' },
  { value: '90', label: '90 days' },
  { value: '365', label: '1 year' },
  { value: '', label: 'Never' },
];

function stateClass(state: BomIngestKey['state']): string {
  if (state === 'ACTIVE') return 'status-pill inv-status-applicable';
  return state === 'REVOKED' ? 'status-pill status-suppressed' : 'status-pill status-unknown';
}

export function BomIngestKeysSection() {
  const actor = useActor();
  const canCreate = canManageServiceAccounts(actor);
  const queryClient = useQueryClient();
  const [name, setName] = React.useState('');
  const [expiresInDays, setExpiresInDays] = React.useState('90');
  const [newToken, setNewToken] = React.useState<string | null>(null);
  const [copied, setCopied] = React.useState(false);
  const [actionError, setActionError] = React.useState('');

  const keysQuery = useQuery({ queryKey: KEYS_QUERY_KEY, queryFn: () => api.listBomIngestKeys() });

  const createMutation = useMutation({
    mutationFn: () => api.createBomIngestKey({
      name: name.trim(),
      ...(expiresInDays ? { expiresInDays: Number(expiresInDays) } : {}),
    }),
    onSuccess: (created) => {
      setNewToken(created.token);
      setName('');
      setActionError('');
      void queryClient.invalidateQueries({ queryKey: KEYS_QUERY_KEY });
    },
    onError: (error: Error) => setActionError(error.message),
  });

  const revokeMutation = useMutation({
    mutationFn: (keyId: string) => api.revokeBomIngestKey(keyId),
    onSuccess: () => {
      setActionError('');
      void queryClient.invalidateQueries({ queryKey: KEYS_QUERY_KEY });
    },
    onError: (error: Error) => setActionError(error.message),
  });

  const copyToken = async () => {
    if (!newToken) return;
    try {
      await navigator.clipboard.writeText(newToken);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  const rows = React.useMemo<DataTableRow[]>(() => (keysQuery.data ?? []).map((key) => ({
    id: key.id,
    cells: {
      name: { content: <strong>{key.name}</strong> },
      prefix: { content: <span className="mono">sgk_{key.keyPrefix}…</span> },
      state: { content: <span className={stateClass(key.state)}>{key.state}</span> },
      created: { content: formatTimestamp(key.createdAt) },
      expires: { content: key.expiresAt ? formatTimestamp(key.expiresAt) : 'Never' },
      lastUsed: { content: key.lastUsedAt ? formatTimestamp(key.lastUsedAt) : 'Never used' },
      actions: {
        content: key.state === 'ACTIVE' && canCreate ? (
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            aria-label={`Revoke ${key.name}`}
            disabled={revokeMutation.isPending}
            onClick={() => revokeMutation.mutate(key.id)}
          >
            Revoke
          </button>
        ) : null,
      },
    },
  })), [canCreate, keysQuery.data, revokeMutation]);

  const state = keysQuery.isPending ? 'pending'
    : keysQuery.isError ? 'error'
      : rows.length === 0 ? 'empty' : 'ready';

  return (
    <div className="form-section">
      <p className="form-section-title">Ingest keys</p>
      <p className="panel-caption">
        A key can push BOMs to this workspace and nothing else. It is shown once, so store it as a pipeline secret.
      </p>

      {newToken && (
        <div className="notice success" role="status" style={{ marginBottom: 12 }}>
          <p><strong>Copy this key now.</strong> It will not be shown again.</p>
          <code className="mono" style={{ wordBreak: 'break-all' }}>{newToken}</code>
          <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => void copyToken()}>
              {copied ? 'Copied' : 'Copy key'}
            </button>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => { setNewToken(null); setCopied(false); }}>
              I have stored it
            </button>
          </div>
        </div>
      )}

      {actionError && <div className="notice error" role="alert" style={{ marginBottom: 8 }}>{actionError}</div>}

      {canCreate ? (
        <form
          className="form-row-2col"
          onSubmit={(event) => { event.preventDefault(); if (name.trim()) createMutation.mutate(); }}
        >
          <label className="form-label">Key name
            <input
              type="text"
              className="form-input"
              value={name}
              maxLength={120}
              placeholder="e.g. payments-api production pipeline"
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label className="form-label">Expires
            <select className="form-select" value={expiresInDays} onChange={(event) => setExpiresInDays(event.target.value)}>
              {EXPIRY_OPTIONS.map((option) => <option key={option.label} value={option.value}>{option.label}</option>)}
            </select>
          </label>
          <div>
            <button type="submit" className="btn btn-primary" disabled={!name.trim() || createMutation.isPending}>
              {createMutation.isPending ? 'Creating…' : 'Create key'}
            </button>
          </div>
        </form>
      ) : (
        <p className="panel-caption">Only a tenant administrator can create or revoke ingest keys.</p>
      )}

      <AsyncSection
        state={state}
        loadingLabel="Loading ingest keys…"
        emptyMessage="No ingest keys yet."
        errorMessage="Ingest keys could not be loaded."
        onRetry={() => void keysQuery.refetch()}
        retryLabel="Retry ingest keys"
        retrying={keysQuery.isFetching}
      >
        <div className="table-scroll">
          <DataTable storageKey="bom-ingest-keys-table" label="Ingest keys" columns={COLUMNS} rows={rows} />
        </div>
      </AsyncSection>
    </div>
  );
}
