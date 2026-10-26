import React from 'react';
import { api } from '../api/client';
import type { VulnIntelSourceStatus } from '../api/client';
import { VulnIntelConnectorPage } from './VulnIntelConnectorPage';

type Props = { lastRun?: VulnIntelSourceStatus };

export function RedhatCsafConnectorPage({ lastRun }: Props) {
  const configFields = (
    <div className="form-grid">
      <div className="inline-note">
        Ingests Red Hat CSAF advisories and VEX applicability data from the Red Hat Security Data
        API. No credentials are required — the feed is publicly accessible.
        Advisories are correlated against inventory via CPE matching.
      </div>
    </div>
  );

  return (
    <VulnIntelConnectorPage
      config={{
        title: 'Red Hat CSAF + VEX',
        sourceKey: 'CSAF_REDHAT',
        triggerSync: () => api.syncRedhatCsaf(),
        configFields
      }}
      lastRun={lastRun}
    />
  );
}
