import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { DataTable, type DataTableColumn } from '../../components/DataTable';
import { ownershipErrorText } from './errors';
import { OrganizationsRoleDialog } from './OrganizationsRoleDialog';
import { type CloudSourceAction, useCloudOwnershipSourcesQuery, useCloudSourceActionMutation } from './queries';
import type { CloudOwnershipSettingsRequest, CloudOwnershipSource } from './types';

const COLUMNS: DataTableColumn[] = [
  { id: 'provider', label: 'Producer', header: 'Producer', priority: 'essential', initialSize: 200, minWidth: 160 },
  { id: 'state', label: 'State', header: 'State', priority: 'essential', initialSize: 200 },
  { id: 'inputs', label: 'Inputs', header: 'Inputs', initialSize: 300, minWidth: 220 },
  { id: 'claims', label: 'Active claims', header: 'Active claims', initialSize: 130 },
  { id: 'actions', label: 'Actions', header: 'Actions', priority: 'essential', initialSize: 200, minWidth: 140 }
];

const NAMES: Record<CloudOwnershipSource['provider'], { name: string; key: string; account: string }> = {
  AWS: { name: 'AWS resource and account tags', key: 'tag', account: 'Account tags (AWS Organizations)' },
  GCP: { name: 'GCP labels', key: 'label', account: 'Project labels' }
};

/** The one-line state of a producer, in the order its gates apply (Phase 0B §2.1). */
function stateOf(source: CloudOwnershipSource): { label: string; tone: string; detail?: string } {
  if (!source.configured) return { label: 'Not configured', tone: 'status-unknown', detail: 'Configure the connector on the Connect page.' };
  if (!source.deploymentEnabled) return { label: 'Off', tone: 'status-unknown', detail: 'Cloud ownership is not enabled for this deployment.' };
  if (source.domainState === 'LEGACY') return { label: 'Not started', tone: 'status-unknown', detail: 'Cloud ownership is still legacy for this workspace.' };
  if (source.paused) {
    const anomaly = source.pauseReason?.startsWith('ANOMALY');
    return {
      label: anomaly ? 'Paused: anomaly' : 'Paused',
      tone: 'status-warning',
      detail: anomaly ? 'A run would have changed too many owners. Review it, then resume to apply it.' : source.pauseReason ?? undefined
    };
  }
  if (!source.intervalValid) return { label: 'Interval out of range', tone: 'status-warning', detail: 'The connector interval must be between 15 minutes and 7 days.' };
  if (source.domainState === 'DARK') return { label: 'Collecting (dark)', tone: 'status-success', detail: 'Claims are recorded but do not change owners yet.' };
  return { label: 'Publishing', tone: 'status-success' };
}

type Props = { canConfigure: boolean; canPause: boolean };

/**
 * AWS and GCP ownership producers (Phase 0B §2). They run after their discovery connector and read its assets, so the
 * credentials stay on the connector. Admins switch the owner/team keys and the account input, and pause or resume
 * the producer; resuming after an anomaly pause approves the held run. The server enforces every action.
 */
export function CloudSourcesSection({ canConfigure, canPause }: Props) {
  const sources = useCloudOwnershipSourcesQuery();
  const action = useCloudSourceActionMutation();
  const [pending, setPending] = React.useState<CloudSourceAction | null>(null);
  const [message, setMessage] = React.useState('');
  const [rolesOpen, setRolesOpen] = React.useState(false);

  const ask = (next: CloudSourceAction) => {
    action.reset();
    setPending(next);
  };

  const toggle = (source: CloudOwnershipSource, field: keyof CloudOwnershipSettingsRequest, value: boolean) =>
    ask({ kind: 'settings', provider: source.provider, settings: { [field]: value } });

  const rows = (sources.data ?? []).map((source) => {
    const names = NAMES[source.provider];
    const state = stateOf(source);
    const settings = source.settings;
    const switchFor = (field: keyof CloudOwnershipSettingsRequest, label: string, checked: boolean, note?: string) => (
      <label key={field} className="ownership-wrap">
        <input type="checkbox" checked={checked} disabled={!canConfigure || !settings}
          onChange={(event) => toggle(source, field, event.target.checked)} />{' '}
        {label}{note ? <span> — {note}</span> : null}
      </label>
    );
    return {
      id: source.provider,
      cells: {
        provider: { content: <strong>{names.name}</strong> },
        state: {
          content: (
            <div>
              <span className={`status-pill ${state.tone}`}>{state.label}</span>
              {state.detail && <div className="ownership-wrap">{state.detail}</div>}
            </div>
          )
        },
        inputs: {
          content: settings ? (
            <div>
              {switchFor('ownerKeyEnabled', `owner ${names.key}`, settings.ownerKey)}
              {switchFor('teamKeyEnabled', `team ${names.key}`, settings.teamKey)}
              {switchFor('accountInputEnabled', names.account, settings.accountInput,
                source.accountTagsConfigured ? undefined : 'not configured on the connector')}
            </div>
          ) : '—'
        },
        claims: { content: String(source.activeClaims) },
        actions: { content: actions(source) }
      }
    };
  });

  function actions(source: CloudOwnershipSource) {
    const configureRole = canConfigure && source.provider === 'AWS' && source.configured;
    if ((!canPause || !source.configured) && !configureRole) return <span>—</span>;
    return (
      <div className="button-row">
        {configureRole && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setRolesOpen(true)}>Account tags role</button>
        )}
        {!canPause ? null : source.paused
          ? <button type="button" className="btn btn-ghost btn-sm" onClick={() => ask({ kind: 'resume', provider: source.provider })}>Resume</button>
          : <button type="button" className="btn btn-ghost btn-sm" onClick={() => ask({ kind: 'pause', provider: source.provider })}>Pause</button>}
      </div>
    );
  }

  const state = sources.isPending ? 'pending' : sources.isError && !sources.data ? 'error' : rows.length > 0 ? 'ready' : 'empty';
  const copy = pending ? confirmCopy(pending) : null;

  return (
    <section className="ownership-panel" aria-label="Cloud ownership producers">
      <h3>Cloud ownership</h3>
      <p>
        Owner and team tags from AWS and labels from GCP become ownership claims after each discovery run. Values map only to an
        existing team name or alias; anything else goes to Review.
      </p>
      {message && <div className="notice success" role="status">{message}</div>}
      <AsyncSection
        state={state}
        loadingLabel="Loading cloud ownership producers…"
        errorMessage={ownershipErrorText(sources.error, 'Cloud ownership producers could not be loaded.')}
        onRetry={() => void sources.refetch()}
        retrying={sources.isFetching}
        emptyTitle="No cloud producers"
        emptyMessage="Cloud ownership producers are not available."
        isRefreshing={sources.isFetching && !sources.isPending}
      >
        <DataTable storageKey="ownership-cloud-sources" columns={COLUMNS} rows={rows} label="Cloud ownership producers" />
      </AsyncSection>

      <OrganizationsRoleDialog isOpen={rolesOpen} onClose={() => setRolesOpen(false)}
        onSaved={(text) => { setRolesOpen(false); setMessage(text); }} />

      <ConfirmDialog
        isOpen={pending !== null}
        title={copy?.title ?? ''}
        message={
          <>
            {copy?.message}
            {action.isError && <div className="notice error" role="alert">{ownershipErrorText(action.error, 'The producer could not be updated.')}</div>}
          </>
        }
        confirmLabel={copy?.confirm ?? 'Confirm'}
        busy={action.isPending}
        busyMessage="Updating the producer…"
        onConfirm={() => pending && action.mutate(pending, {
          onSuccess: () => { setMessage(copy?.done ?? 'Done.'); setPending(null); }
        })}
        onCancel={() => setPending(null)}
      />
    </section>
  );
}

function confirmCopy(action: CloudSourceAction): { title: string; message: string; confirm: string; done: string } {
  const name = NAMES[action.provider].name;
  if (action.kind === 'pause') {
    return { title: `Pause ${name}?`, message: 'Its claims stop counting at once and no new claims are written until you resume.', confirm: 'Pause', done: 'Producer paused.' };
  }
  if (action.kind === 'resume') {
    return {
      title: `Resume ${name}?`,
      message: 'Its claims count again. If it was paused by an anomaly, resuming approves it: the next run applies the held changes.',
      confirm: 'Resume',
      done: 'Producer resumed.'
    };
  }
  if (action.kind !== 'settings') throw new Error('unreachable');
  const turningOff = Object.values(action.settings).some((value) => value === false);
  return {
    title: `Change ${name} inputs?`,
    message: turningOff
      ? 'Switching an input off ends its active claims now; the affected owners are re-resolved.'
      : 'The input is read again from the next discovery run.',
    confirm: 'Save',
    done: 'Inputs saved.'
  };
}
