import React from 'react';
import { api } from '../api/client';
import { pathForTab } from '../app/routes';

type Props = {
  title?: string;
  caption?: string;
};

type JobDef = {
  key: string;
  label: string;
  description: string;
  trigger: () => Promise<unknown>;
};

const JOBS: JobDef[] = [
  {
    key: 'full',
    label: 'Run Full EOL Refresh',
    description: 'Fetch product catalog → release cycles → resolve mappings → denormalize status. Runs all 4 steps in sequence.',
    trigger: () => api.triggerEolFullRefresh()
  },
  {
    key: 'catalog',
    label: 'Refresh Product Catalog',
    description: 'Pull all product slugs and CPE/PURL identifiers from endoflife.date. Step 1 of 4.',
    trigger: () => api.triggerEolCatalogRefresh()
  },
  {
    key: 'releases',
    label: 'Refresh Release Cycles',
    description: 'Fetch EOL dates and lifecycle data for products matched in your inventory. Step 2 of 4.',
    trigger: () => api.triggerEolReleaseRefresh()
  },
  {
    key: 'mappings',
    label: 'Resolve Inventory Mappings',
    description: 'Match software identities from inventory to EOL product slugs using CPE, PURL, and name heuristics. Step 3 of 4.',
    trigger: () => api.triggerEolMappingResolve()
  },
  {
    key: 'denormalize',
    label: 'Denormalize EOL Status',
    description: 'Update is_eol, eol_days_remaining, and eol_cycle on inventory components for fast dashboard queries. Step 4 of 4.',
    trigger: () => api.triggerEolDenormalize()
  }
];

export function EolSourcePanel({
  title = 'endoflife.date Feed',
  caption = ''
}: Props) {
  const [busy, setBusy] = React.useState<string | null>(null);
  const [message, setMessage] = React.useState('');
  const eolCatalogHref = pathForTab('end-of-life');

  const runJob = async (job: JobDef): Promise<void> => {
    setBusy(job.key);
    setMessage(`${job.label} starting...`);
    try {
      const response = await job.trigger();
      if (response && typeof response === 'object' && 'runId' in response) {
        const typed = response as { runId?: string; status?: string; message?: string };
        setMessage(`Queued: run ${typed.runId ?? 'n/a'} — ${typed.message ?? typed.status ?? 'running'}`);
      } else {
        setMessage(`${job.label} completed`);
      }
    } catch (e) {
      setMessage(`${job.label} failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="vi-source-section">
      <div className="vi-source-header">
        <span className="vi-source-icon" aria-hidden="true">📅</span>
        <span className="vi-source-name">{title}</span>
        <span className="connect-source-dot connect-source-dot--ok" />
      </div>
      {caption && <p className="vi-source-note">{caption}</p>}

      {message && (
        <div className={`notice${message.includes('failed') ? ' error' : ''}`}>
          {message}
        </div>
      )}

      <div className="vi-source-config">
        <div className="vi-source-filters">
          <div className="vi-source-filters-header">
            <span className="vi-source-filters-title">Lifecycle Refresh Jobs</span>
          </div>
          <div className="eol-source-jobs">
            {JOBS.map((job) => (
              <div key={job.key} className="eol-source-job">
                <div className="eol-source-job-copy">
                  <div className="eol-source-job-title">{job.label}</div>
                  <div className="field-hint">{job.description}</div>
                </div>
                <button
                  type="button"
                  className={job.key === 'full' ? 'btn btn-primary' : 'btn btn-secondary'}
                  disabled={busy !== null}
                  onClick={() => runJob(job)}
                >
                  {busy === job.key ? 'Running...' : job.label}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="vi-source-actions">
        <a
          href={eolCatalogHref}
          className="btn btn-secondary"
        >
          Open EOL Catalog
        </a>
      </div>
    </div>
  );
}
