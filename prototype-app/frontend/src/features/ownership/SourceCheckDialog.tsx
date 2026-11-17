import { Dialog } from '../../components/Dialog';
import { ownershipErrorText } from './errors';
import { type SourceCheck, useEnableIdentitySourceMutation, type useSourceCheckMutation } from './queries';
import type { IdentitySource } from './types';

const TABLE_LABELS: Record<string, string> = { sys_user: 'People', sys_user_group: 'Groups', sys_user_grmember: 'Memberships' };
const SAMPLE_FIELDS: Record<string, string[]> = {
  sys_user: ['name', 'email', 'user_name', 'active'],
  sys_user_group: ['name', 'active'],
  sys_user_grmember: ['group', 'user']
};

type Props = {
  check: SourceCheck | null;
  run: ReturnType<typeof useSourceCheckMutation>;
  canEnable: boolean;
  onClose: () => void;
  onEnabled: (source: IdentitySource) => void;
};

/**
 * Connection test or preview of an identity source (Phase 0B contract §1.2, §1.6). Preview samples show full names and
 * emails to tenant admins; they live only in the request's state and are cleared when the dialog closes. A disabled
 * source is enabled only with the token from a preview where every table was readable.
 */
export function SourceCheckDialog({ check, run, canEnable, onClose, onEnabled }: Props) {
  const enable = useEnableIdentitySourceMutation();
  if (!check) return null;
  const result = run.data;
  const preview = check.mode === 'preview' && result && 'previewToken' in result ? result : null;
  const busy = run.isPending || enable.isPending;
  const offerEnable = canEnable && check.source.state === 'DISABLED' && preview?.previewToken;

  return (
    <Dialog
      isOpen
      title={check.mode === 'test' ? `Connection test: ${check.source.displayName}` : `Preview: ${check.source.displayName}`}
      onClose={onClose}
      busy={busy}
      busyMessage={run.isPending ? 'Contacting ServiceNow…' : 'Enabling the source…'}
      className="confirm-dialog confirm-dialog-content ownership-dialog"
    >
      <div className="ownership-dialog-form">
        {run.isPending && <p role="status">Reading the directory tables with the stored credentials…</p>}
        {run.isError && <div className="notice error" role="alert">{ownershipErrorText(run.error, 'The check could not be run.')}</div>}
        {result && (
          <>
            <div className={`notice ${result.succeeded ? 'success' : 'warning'}`} role="status">
              {result.message}{result.failure ? ` (${result.failure})` : ''}
            </div>
            <dl className="ownership-counts">
              {result.tables.map((table) => (
                <div key={table.table}>
                  <dt>{TABLE_LABELS[table.table] ?? table.table}</dt>
                  <dd>{table.outcome === 'DENIED' ? 'Access denied' : table.rowCount === null ? 'Readable' : table.rowCount.toLocaleString()}</dd>
                </div>
              ))}
            </dl>
            {preview && preview.tables.some((table) => table.samples.length > 0) && (
              <details>
                <summary>Sample rows (full values; not stored)</summary>
                {preview.tables.filter((table) => table.samples.length > 0).map((table) => (
                  <div key={table.table} className="ownership-wrap">
                    <h3>{TABLE_LABELS[table.table] ?? table.table}</h3>
                    <ul>
                      {table.samples.map((sample, index) => (
                        <li key={sample.sys_id ?? index}>
                          {(SAMPLE_FIELDS[table.table] ?? []).map((field) => sample[field]).filter(Boolean).join(' · ') || sample.sys_id}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </details>
            )}
            {check.mode === 'preview' && !preview?.previewToken && (
              <p>Fix the failure above and preview again before enabling.</p>
            )}
          </>
        )}
        {enable.isError && <div className="notice error" role="alert">{ownershipErrorText(enable.error, 'The source could not be enabled.')}</div>}
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>Close</button>
          {offerEnable && (
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => enable.mutate({ sourceId: check.source.id, previewToken: preview.previewToken as string }, { onSuccess: onEnabled })}
            >
              Enable and run baseline load
            </button>
          )}
        </div>
      </div>
    </Dialog>
  );
}
