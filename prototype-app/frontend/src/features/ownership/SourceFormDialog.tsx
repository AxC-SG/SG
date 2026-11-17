import React from 'react';
import { ownershipErrorText } from './errors';
import { OwnershipFormDialog } from './OwnershipFormDialog';
import { useSaveIdentitySourceMutation } from './queries';
import type { IdentitySource, IdentitySourceRequest, IdentitySourceTable } from './types';

const TABLES: Array<{ table: IdentitySourceTable; label: string }> = [
  { table: 'sys_user', label: 'People filter (sys_user)' },
  { table: 'sys_user_group', label: 'Groups filter (sys_user_group)' },
  { table: 'sys_user_grmember', label: 'Memberships filter (sys_user_grmember)' }
];

type Props = {
  /** null closes the dialog; 'new' adds a source; otherwise the source to edit. */
  source: IdentitySource | 'new' | null;
  onClose: () => void;
  onSaved: (source: IdentitySource) => void;
};

/**
 * Add or edit a ServiceNow identity source (Phase 0B contract §1.1–§1.2). The password or token is write-only: it is
 * never shown, and leaving it blank keeps the stored one unless the instance URL, auth type or username changes.
 * Changing the URL or a filter returns an enabled source to Disabled, because enabling needs a preview of the new scope.
 */
export function SourceFormDialog({ source, onClose, onSaved }: Props) {
  const editing = source !== null && source !== 'new' ? source : null;
  const save = useSaveIdentitySourceMutation();
  const nameRef = React.useRef<HTMLInputElement>(null);
  const [form, setForm] = React.useState<IdentitySourceRequest>(() => initial(editing));
  const set = <K extends keyof IdentitySourceRequest>(key: K, value: IdentitySourceRequest[K]) => setForm((f) => ({ ...f, [key]: value }));

  const valid = form.displayName.trim() !== '' && form.instanceUrl.trim() !== ''
    && (form.authType === 'BEARER' || (form.username ?? '').trim() !== '')
    && (editing !== null || (form.secret ?? '').trim() !== '');

  const submit = () => {
    const filters = Object.fromEntries(Object.entries(form.filters).filter(([, value]) => (value ?? '').trim() !== ''));
    save.mutate({
      sourceId: editing?.id ?? null,
      payload: {
        ...form,
        displayName: form.displayName.trim(),
        instanceUrl: form.instanceUrl.trim(),
        username: form.authType === 'BASIC' ? (form.username ?? '').trim() : null,
        secret: (form.secret ?? '').trim() === '' ? null : form.secret,
        schedule: (form.schedule ?? '').trim() === '' ? null : (form.schedule ?? '').trim(),
        filters
      }
    }, { onSuccess: onSaved });
  };

  return (
    <OwnershipFormDialog
      isOpen={source !== null}
      title={editing ? `Edit ${editing.displayName}` : 'Add ServiceNow source'}
      description={editing
        ? 'Stored credentials are never shown: enter the username again, and leave the password or token blank to keep it. Changing the instance URL, authentication or username needs the secret again. Changing the instance URL or a filter disables the source until it is previewed and enabled again.'
        : 'Use a dedicated integration account with read access to sys_user, sys_user_group and sys_user_grmember only. The source starts disabled.'}
      submitLabel={editing ? 'Save source' : 'Add source'}
      busy={save.isPending}
      busyMessage="Saving the source…"
      error={save.isError ? ownershipErrorText(save.error, 'The source could not be saved.') : null}
      submitDisabled={!valid}
      onSubmit={submit}
      onClose={onClose}
      initialFocusRef={nameRef}
    >
      <label>
        <span>Name</span>
        <input ref={nameRef} required value={form.displayName} onChange={(event) => set('displayName', event.target.value)} />
      </label>
      <label>
        <span>Instance URL</span>
        <input required type="url" placeholder="https://acme.service-now.com" value={form.instanceUrl}
          onChange={(event) => set('instanceUrl', event.target.value)} />
      </label>
      <label>
        <span>Authentication</span>
        <select value={form.authType} onChange={(event) => set('authType', event.target.value as 'BASIC' | 'BEARER')}>
          <option value="BASIC">Username and password</option>
          <option value="BEARER">Bearer token</option>
        </select>
      </label>
      {form.authType === 'BASIC' && (
        <label>
          <span>Integration account username</span>
          <input required autoComplete="off" value={form.username ?? ''} onChange={(event) => set('username', event.target.value)} />
        </label>
      )}
      <label>
        <span>{form.authType === 'BASIC' ? 'Password' : 'Token'}{editing ? ' (leave blank to keep)' : ''}</span>
        <input type="password" autoComplete="new-password" required={editing === null} value={form.secret ?? ''}
          onChange={(event) => set('secret', event.target.value)} />
      </label>
      <label>
        <span>Schedule (ISO-8601, PT15M to P7D)</span>
        <input placeholder="PT24H" value={form.schedule ?? ''} onChange={(event) => set('schedule', event.target.value)} />
      </label>
      {TABLES.map(({ table, label }) => (
        <label key={table}>
          <span>{label}</span>
          <input placeholder="Optional encoded query, e.g. active=true" value={form.filters[table] ?? ''}
            onChange={(event) => set('filters', { ...form.filters, [table]: event.target.value })} />
        </label>
      ))}
    </OwnershipFormDialog>
  );
}

function initial(source: IdentitySource | null): IdentitySourceRequest {
  return {
    displayName: source?.displayName ?? '',
    instanceUrl: source?.instanceUrl ?? '',
    authType: source?.authType ?? 'BASIC',
    username: null,
    secret: null,
    filters: { ...(source?.filters ?? {}) },
    schedule: source?.schedule ?? 'PT24H',
    ...(source ? { version: source.version } : {})
  };
}
