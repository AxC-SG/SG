import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { formatDate, newIdempotencyKey, titleCase } from './labels';
import type { CbomReport } from './types';

const UNSIGNED = 'Unsigned report — checksum verifies content consistency, not authenticity';
const PENDING: CbomReport['status'][] = ['QUEUED', 'GENERATING'];

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

/** Persisted assessment reports for one CBOM: request, generation status, audited download and regeneration. */
export function CbomReportsPanel({ bomId }: { bomId: string }) {
  const client = useQueryClient();
  const [message, setMessage] = React.useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const assessmentsQuery = useQuery({ queryKey: ['cbom-assessments', bomId], queryFn: () => api.listCbomAssessments(bomId) });
  const reportsQuery = useQuery({
    queryKey: ['cbom-reports', bomId],
    queryFn: () => api.listCbomReports(bomId),
    refetchInterval: (query) => (query.state.data ?? []).some((report) => PENDING.includes(report.status)) ? 2000 : false,
  });
  const latest = (assessmentsQuery.data ?? []).find((run) => run.status === 'SUCCEEDED');
  const refresh = () => void client.invalidateQueries({ queryKey: ['cbom-reports', bomId] });

  const requestReport = useMutation({
    mutationFn: (format: 'JSON' | 'HTML') => api.requestCbomReport(bomId, latest!.id, format, newIdempotencyKey('report')),
    onSuccess: (report) => { setMessage({ tone: 'success', text: `${report.format} report requested.` }); refresh(); },
    onError: (error) => setMessage({ tone: 'error', text: error instanceof Error ? error.message : 'The report could not be requested.' }),
  });
  const regenerate = useMutation({
    mutationFn: (report: CbomReport) => api.regenerateCbomReport(bomId, report.id, newIdempotencyKey('regen')),
    onSuccess: () => { setMessage({ tone: 'success', text: 'Report regeneration requested.' }); refresh(); },
    onError: (error) => setMessage({ tone: 'error', text: error instanceof Error ? error.message : 'The report could not be regenerated.' }),
  });
  const download = useMutation({
    mutationFn: (report: CbomReport) => api.downloadCbomReport(bomId, report.id),
    onSuccess: (file) => { saveBlob(file.blob, file.filename); setMessage({ tone: 'success', text: `Downloaded ${file.filename}. SHA-256 ${file.checksum ?? 'unavailable'}.` }); refresh(); },
    onError: (error) => setMessage({ tone: 'error', text: error instanceof Error ? error.message : 'The report could not be downloaded.' }),
  });

  const reports = reportsQuery.data ?? [];
  const state = reportsQuery.isPending ? 'pending' : reportsQuery.isError ? 'error' : reports.length === 0 ? 'empty' : 'ready';
  const busy = requestReport.isPending;

  return (
    <div className="panel cbom-reports-panel">
      <div className="panel-header">
        <h3>Assessment reports</h3>
        <span className="panel-caption">{UNSIGNED}</span>
      </div>
      <div className="cbom-report-actions">
        <button type="button" className="btn btn-primary btn-sm" disabled={!latest || busy} onClick={() => requestReport.mutate('HTML')}>Generate HTML report</button>
        <button type="button" className="btn btn-secondary btn-sm" disabled={!latest || busy} onClick={() => requestReport.mutate('JSON')}>Generate JSON record</button>
        {!latest && !assessmentsQuery.isPending && <span className="panel-caption">Reports need a successful assessment of this CBOM.</span>}
      </div>
      {message && <div className={`notice ${message.tone === 'error' ? 'error' : 'success'}`} role={message.tone === 'error' ? 'alert' : 'status'}>{message.text}</div>}
      <AsyncSection state={state} loadingLabel="Loading reports…" errorMessage="Reports could not be loaded."
        onRetry={() => void reportsQuery.refetch()} retryLabel="Retry reports" retrying={reportsQuery.isFetching}
        emptyMessage="No reports have been generated for this CBOM.">
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th>Requested</th><th>Format</th><th>Status</th><th>Checksum (SHA-256)</th><th>Expires</th><th>Downloads</th><th>Actions</th></tr></thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id}>
                  <td>{formatDate(report.createdAt)}<div className="panel-caption">{report.requestedBy}{report.regeneratedFrom ? ' · regenerated' : ''}</div></td>
                  <td>{report.format}</td>
                  <td>{titleCase(report.status)}{report.errorMessage ? <div className="panel-caption">{report.errorMessage}</div> : null}</td>
                  <td className="monospace cbom-wrap">{report.checksumSha256 ?? '—'}</td>
                  <td>{formatDate(report.expiresAt)}</td>
                  <td>{report.downloadCount}</td>
                  <td>
                    <div className="cbom-row-actions">
                      <button type="button" className="btn btn-secondary btn-sm" disabled={report.status !== 'READY' || download.isPending}
                        onClick={() => download.mutate(report)} aria-label={`Download ${report.format} report from ${formatDate(report.createdAt)}`}>Download</button>
                      <button type="button" className="btn btn-ghost btn-sm" disabled={PENDING.includes(report.status) || regenerate.isPending}
                        onClick={() => regenerate.mutate(report)} aria-label={`Regenerate ${report.format} report from ${formatDate(report.createdAt)}`}>Regenerate</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AsyncSection>
    </div>
  );
}
