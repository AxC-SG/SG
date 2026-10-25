import React from 'react';
import type { VulnIntelSourceStatus } from '../api/client';
import { VulnIntelConnectorPage } from './VulnIntelConnectorPage';

type Props = { lastRun?: VulnIntelSourceStatus };

export function AdvisoryConnectorPage({ lastRun }: Props) {
  const configFields = (
    <div className="form-grid">
      <div className="inline-note">
        Advisory imports allow curated vendor advisories to be ingested manually via the API
        (<code>POST /api/ingestion/advisories</code>). Use this feed to supplement NVD/GHSA with
        vendor-specific package mappings and applicability overrides.
        No scheduled sync is needed — advisories are imported on demand.
      </div>
    </div>
  );

  return (
    <VulnIntelConnectorPage
      config={{
        title: 'Advisory Imports',
        sourceKey: 'ADVISORY',
        triggerSync: () => Promise.resolve({ runId: '', status: 'queued', message: 'Advisory imports are triggered via the API directly.' }),
        configFields
      }}
      lastRun={lastRun}
    />
  );
}
