import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { DataTable, type DataTableColumn } from '../../components/DataTable';
import { ownershipErrorText } from './errors';
import {
  type IdentitySourceAction,
  type SourceCheck,
  useIdentitySourceActionMutation,
  useIdentitySourcesQuery,
  useSourceCheckMutation
} from './queries';
import { SourceCheckDialog } from './SourceCheckDialog';
import { SourceFormDialog } from './SourceFormDialog';
import type { IdentitySource } from './types';

const COLUMNS: DataTableColumn[] = [
  { id: 'name', label: 'Source', header: 'Source', priority: 'essential', initialSize: 260, minWidth: 180 },
  { id: 'state', label: 'State', header: 'State', priority: 'essential', initialSize: 120 },
  { id: 'health', label: 'Health', header: 'Health', initialSize: 110 },
  { id: 'lastSuccess', label: 'Last success', header: 'Last success', initialSize: 170 },
  { id: 'lastError', label: 'Last error', header: 'Last error', priority: 'optional', initialSize: 260 },
  { id: 'actions', label: 'Actions', header: 'Actions', priority: 'essential', initialSize: 360, minWidth: 240 }
];

const STATE_LABELS: Record<IdentitySource['state'], { label: string; tone: string }> = {
  ENABLED: { label: 'Enabled', tone: 'status-success' },
  DISABLED: { label: 'Disabled', tone: 'status-unknown' },
  PAUSED: { label: 'Paused', tone: 'status-warning' },
  ERROR: { label: 'Error', tone: 'status-warning' }
};

const HEALTH_LABELS: Record<IdentitySource['health'], string> = {
  UNKNOWN: 'Not run yet', HEALTHY: 'Healthy', DEGRADED: 'Degraded', FAILING: 'Failing'
};

const ACTION_COPY: Record<IdentitySourceAction, { title: string; message: string; confirm: string; done: string }> = {
  sync: { title: 'Sync now', message: 'Queues an incremental sync from the stored cursor. The worker starts it within five minutes.', confirm: 'Queue sync', done: 'Sync queued.' },
  fullScan: {
    title: 'Run a complete scan',
    message: 'Reads every row in scope. Only a complete scan that finishes without an error marks absent people, groups and memberships inactive; people created manually or by CSV are never deactivated.',
    confirm: 'Queue complete scan',
    done: 'Complete scan queued.'
  },
  pause: { title: 'Pause', message: 'Stops scheduled and queued runs for this source. Existing directory data is kept.', confirm: 'Pause source', done: 'Source paused.' },
  resume: {
    title: 'Resume',
    message: 'Resumes the schedule and queues a run. If the source was paused by an anomaly, resuming approves it: the next run applies the held changes for those tables.',
    confirm: 'Resume source',
    done: 'Source resumed.'
  },
  disable: { title: 'Disable', message: 'Turns the source off. Enabling it again needs a new preview.', confirm: 'Disable source', done: 'Source disabled.' }
};

function formatTime(value: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

type Props = { canConfigure: boolean; canPause: boolean };

/**
 * Identity sources (Phase 0B contract §1.1–§1.7): ServiceNow directory sources with their lifecycle, plus the
 * tenant's manual and CSV sources, which are listed but not configured here. Every action is enforced by the server;
 * the buttons shown follow the role matrix and the source's state.
 */
export function SourcesPanel({ canConfigure, canPause }: Props) {
  const sources = useIdentitySourcesQuery();
  const action = useIdentitySourceActionMutation();
  const runCheck = useSourceCheckMutation();
  const [editing, setEditing] = React.useState<IdentitySource | 'new' | null>(null);
  const [check, setCheck] = React.useState<SourceCheck | null>(null);
  const [pending, setPending] = React.useState<{ source: IdentitySource; action: IdentitySourceAction } | null>(null);
  const [message, setMessage] = React.useState('');

  const openCheck = (next: SourceCheck) => {
    setCheck(next);
    runCheck.reset();
    runCheck.mutate(next);
  };
  const closeCheck = () => {
    setCheck(null);
    runCheck.reset(); // drops preview samples from memory
  };
  const ask = (source: IdentitySource, next: IdentitySourceAction) => {
    action.reset();
    setPending({ source, action: next });
  };

  const rows = (sources.data ?? []).map((source) => {
    const serviceNow = source.kind === 'SERVICENOW';
    const state = STATE_LABELS[source.state];
    return {
      id: source.id,
      cells: {
        name: {
          content: (
            <div>
              <strong>{source.displayName}</strong>
              <div className="ownership-wrap">{serviceNow ? source.instanceUrl : source.kind === 'MANUAL' ? 'Manual entry' : 'CSV import'}</div>
            </div>
          )
        },
        state: { content: <span className={`status-pill ${state.tone}`}>{state.label}</span> },
        health: { content: serviceNow ? HEALTH_LABELS[source.health] : '—' },
        lastSuccess: { content: serviceNow ? formatTime(source.lastSuccessAt) : '—' },
        lastError: { content: <span className="ownership-wrap">{source.lastError ?? '—'}</span> },
        actions: { content: serviceNow ? actions(source) : <span>Not configured here</span> }
      }
    };
  });

  function actions(source: IdentitySource) {
    const buttons: React.ReactNode[] = [];
    const add = (label: string, onClick: () => void) =>
      buttons.push(<button key={label} type="button" className="btn btn-ghost btn-sm" onClick={onClick}>{label}</button>);
    if (canConfigure) {
      add('Edit', () => setEditing(source));
      add('Test', () => openCheck({ source, mode: 'test' }));
      if (source.state === 'DISABLED') add('Preview and enable', () => openCheck({ source, mode: 'preview' }));
      if (source.state === 'ENABLED') {
        add('Sync now', () => ask(source, 'sync'));
        add('Complete scan', () => ask(source, 'fullScan'));
      }
      if (source.state === 'PAUSED') add('Resume', () => ask(source, 'resume'));
    }
    if (canPause && (source.state === 'ENABLED' || source.state === 'ERROR')) add('Pause', () => ask(source, 'pause'));
    if (canConfigure && source.state !== 'DISABLED') add('Disable', () => ask(source, 'disable'));
    return buttons.length > 0 ? <div className="button-row">{buttons}</div> : <span>—</span>;
  }

  const state = sources.isPending ? 'pending' : sources.isError && !sources.data ? 'error' : rows.length > 0 ? 'ready' : 'empty';
  const copy = pending ? ACTION_COPY[pending.action] : null;

  return (
    <div className="ownership-panel">
      <div className="ownership-toolbar">
        <p>
          Directory sources bring people, groups and memberships into the directory. A ServiceNow source starts disabled and
          is enabled only after a connection test and a preview.
        </p>
        {canConfigure && (
          <button type="button" className="btn btn-primary" onClick={() => setEditing('new')}>Add ServiceNow source</button>
        )}
      </div>
      {message && <div className="notice success" role="status">{message}</div>}
      <AsyncSection
        state={state}
        loadingLabel="Loading identity sources…"
        errorMessage={ownershipErrorText(sources.error, 'Identity sources could not be loaded.')}
        onRetry={() => void sources.refetch()}
        retrying={sources.isFetching}
        emptyTitle="No identity sources yet"
        emptyMessage={canConfigure ? 'Add a ServiceNow source to sync the directory.' : 'A tenant admin can add a ServiceNow source.'}
        refreshError={sources.isError && sources.data ? 'The latest sources could not be loaded; showing the previous result.' : undefined}
        isRefreshing={sources.isFetching && !sources.isPending}
      >
        <DataTable storageKey="ownership-identity-sources" columns={COLUMNS} rows={rows} label="Identity sources" />
      </AsyncSection>

      {editing !== null && (
        <SourceFormDialog
          key={editing === 'new' ? 'new' : editing.id}
          source={editing}
          onClose={() => setEditing(null)}
          onSaved={(saved) => { setEditing(null); setMessage(`Source ${saved.displayName} saved.`); }}
        />
      )}

      <SourceCheckDialog
        check={check}
        run={runCheck}
        canEnable={canConfigure}
        onClose={closeCheck}
        onEnabled={(enabled) => { closeCheck(); setMessage(`Source ${enabled.displayName} enabled. The baseline load is queued.`); }}
      />

      <ConfirmDialog
        isOpen={pending !== null}
        title={copy && pending ? `${copy.title}: ${pending.source.displayName}?` : ''}
        message={
          <>
            {copy?.message}
            {action.isError && <div className="notice error" role="alert">{ownershipErrorText(action.error, 'The source could not be updated.')}</div>}
          </>
        }
        confirmLabel={copy?.confirm ?? 'Confirm'}
        busy={action.isPending}
        busyMessage="Updating the source…"
        onConfirm={() => pending && action.mutate({ sourceId: pending.source.id, action: pending.action }, {
          onSuccess: () => { setMessage(copy?.done ?? 'Done.'); setPending(null); }
        })}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}
