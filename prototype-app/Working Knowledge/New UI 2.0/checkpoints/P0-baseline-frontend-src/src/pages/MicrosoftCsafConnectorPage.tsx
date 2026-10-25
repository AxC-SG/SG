import React from 'react';
import { api } from '../api/client';
import type { VulnIntelSourceStatus } from '../api/client';
import { VulnIntelConnectorPage } from './VulnIntelConnectorPage';

type Props = { lastRun?: VulnIntelSourceStatus };

export function MicrosoftCsafConnectorPage({ lastRun }: Props) {
  const configFields = (
    <div className="form-grid">
      <div className="inline-note">
        Ingests Microsoft CSAF advisories and VEX applicability data from the Microsoft Security
        Response Center (MSRC) feed. No credentials are required — the feed is publicly accessible.
        Advisories are correlated against inventory via CPE matching.
      </div>
    </div>
  );

  return (
    <VulnIntelConnectorPage
      config={{
        title: 'Microsoft CSAF + VEX',
        sourceKey: 'CSAF_MICROSOFT',
        triggerSync: () => api.syncMicrosoftCsaf(),
        configFields
      }}
      lastRun={lastRun}
    />
  );
}
