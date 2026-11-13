import React from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import { DataTable, type DataTableColumn } from '../../components/DataTable';
import { ownershipErrorText } from './errors';
import { ownershipKeys } from './queries';
import type { DirectoryImportKind, DirectoryImportOutcome, DirectoryImportReport } from './types';

const KINDS: Array<[DirectoryImportKind, string, string]> = [
  ['USERS', 'People', 'external_id, display_name, email, manager_external_id, status'],
  ['GROUPS', 'Groups', 'external_id, display_name, status'],
  ['MEMBERSHIPS', 'Group memberships', 'group_external_id, user_external_id, operation'],
  ['TEAMS', 'Teams', 'name, parent_team, ticket_assignment_group'],
  ['TEAM_ALIASES', 'Team aliases', 'source_kind, alias, team_name']
];

const OUTCOMES: Array<[DirectoryImportOutcome, string]> = [
  ['CREATE', 'Create'], ['UPDATE', 'Update'], ['UNCHANGED', 'Unchanged'],
  ['DUPLICATE', 'Duplicate'], ['AMBIGUOUS', 'Ambiguous'], ['REJECTED', 'Rejected']
];

const ROW_COLUMNS: DataTableColumn[] = [
  { id: 'row', label: 'Row', header: 'Row', priority: 'essential', initialSize: 80 },
  { id: 'outcome', label: 'Outcome', header: 'Outcome', priority: 'essential', initialSize: 120 },
  { id: 'message', label: 'Message', header: 'Message', initialSize: 420, minWidth: 200 }
];

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

/**
 * CSV import (plan §6.3): download a template, run a dry run that changes nothing, then commit the same file. The
 * server binds the commit to the dry run's file hash, tenant and importer for 30 minutes and skips rejected rows.
 */
export function ImportsPanel() {
  const client = useQueryClient();
  const [kind, setKind] = React.useState<DirectoryImportKind>('USERS');
  const [file, setFile] = React.useState<File | null>(null);
  const [preview, setPreview] = React.useState<DirectoryImportReport | null>(null);
  const [result, setResult] = React.useState<DirectoryImportReport | null>(null);
  const fileRef = React.useRef<HTMLInputElement>(null);

  const template = useMutation({ mutationFn: () => api.downloadDirectoryImportTemplate(kind), onSuccess: ({ blob, filename }) => saveBlob(blob, filename) });
  const dryRun = useMutation({ mutationFn: (f: File) => api.previewDirectoryImport(kind, f), onSuccess: setPreview });
  const commit = useMutation({
    mutationFn: ({ token, f }: { token: string; f: File }) => api.commitDirectoryImport(token, f),
    onSuccess: (report) => {
      setResult(report);
      setPreview(null);
      void client.invalidateQueries({ queryKey: ownershipKeys.all });
    }
  });
  const busy = dryRun.isPending || commit.isPending;

  const reset = (nextKind = kind) => {
    setKind(nextKind);
    setFile(null);
    setPreview(null);
    setResult(null);
    dryRun.reset();
    commit.reset();
    if (fileRef.current) fileRef.current.value = '';
  };

  const report = result ?? preview;
  const committable = preview && (preview.counts.CREATE ?? 0) + (preview.counts.UPDATE ?? 0) > 0;
  const headers = KINDS.find(([value]) => value === kind)?.[2];

  return (
    <div className="ownership-panel">
      <div className="form-grid">
        <label>
          <span>What to import</span>
          <select value={kind} disabled={busy} onChange={(event) => reset(event.target.value as DirectoryImportKind)}>
            {KINDS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
        <label>
          <span>CSV file (UTF-8)</span>
          <input
            ref={fileRef}
            type="file"
            accept=".csv,text/csv"
            disabled={busy}
            onChange={(event) => { setFile(event.target.files?.[0] ?? null); setPreview(null); setResult(null); dryRun.reset(); commit.reset(); }}
          />
        </label>
      </div>
      <p className="panel-caption">Columns: <span className="mono">{headers}</span>. Values starting with =, +, - or @ are treated as text.</p>
      <div className="button-row">
        <button type="button" className="btn btn-secondary" disabled={template.isPending} onClick={() => template.mutate()}>
          {template.isPending ? 'Downloading…' : 'Download template'}
        </button>
        <button type="button" className="btn btn-primary" disabled={!file || busy} onClick={() => file && dryRun.mutate(file)}>
          {dryRun.isPending ? 'Checking…' : 'Run dry run'}
        </button>
        {preview && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={!committable || busy || !file}
            onClick={() => file && commit.mutate({ token: preview.runId, f: file })}
          >
            {commit.isPending ? 'Importing…' : 'Import valid rows'}
          </button>
        )}
        {(preview || result) && <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => reset()}>Start over</button>}
      </div>

      {template.isError && <div className="notice error" role="alert">{ownershipErrorText(template.error, 'The template could not be downloaded.')}</div>}
      {dryRun.isError && <div className="notice error" role="alert">{ownershipErrorText(dryRun.error, 'The file could not be checked.')}</div>}
      {commit.isError && (
        <div className="notice error" role="alert">
          {ownershipErrorText(commit.error, 'The import failed.')} Run the dry run again if the file or the 30-minute window changed.
        </div>
      )}
      {result && <div className="notice success" role="status">Import finished ({result.state.toLowerCase()}). Nothing was changed for rejected rows.</div>}
      {preview && !result && (
        <div className="notice" role="status">
          Dry run complete — nothing has been changed yet.{!committable && ' No rows would create or update anything.'}
        </div>
      )}

      {report && (
        <section className="ownership-import-report" aria-label={result ? 'Import result' : 'Dry run result'}>
          <dl className="ownership-counts">
            {OUTCOMES.map(([outcome, label]) => (
              <div key={outcome}>
                <dt>{label}</dt>
                <dd>{(report.counts[outcome] ?? 0).toLocaleString()}</dd>
              </div>
            ))}
          </dl>
          {[...report.rows, ...report.warnings].length > 0 && (
            <DataTable
              storageKey="ownership-import-rows"
              label="Rows needing attention"
              columns={ROW_COLUMNS}
              rows={[...report.rows, ...report.warnings].map((row, index) => ({
                id: `${row.row}-${row.outcome}-${index}`,
                cells: {
                  row: { content: row.row },
                  outcome: { content: row.outcome },
                  message: { content: row.message ?? '' }
                }
              }))}
            />
          )}
        </section>
      )}
    </div>
  );
}
