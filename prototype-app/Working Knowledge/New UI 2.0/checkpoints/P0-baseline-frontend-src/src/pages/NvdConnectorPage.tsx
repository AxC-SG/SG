import React from 'react';
import { api } from '../api/client';
import type { VulnIntelSourceStatus } from '../api/client';
import { InfoTooltip } from '../components/InfoTooltip';
import { VulnIntelConnectorPage } from './VulnIntelConnectorPage';

type Props = { lastRun?: VulnIntelSourceStatus };

export function NvdConnectorPage({ lastRun }: Props) {
  const [apiKey, setApiKey] = React.useState('');
  const [showKey, setShowKey] = React.useState(false);
  const hasApiKeyOverride = apiKey.trim().length > 0;

  const configFields = (
    <div className="form-grid">
      <label>
        <span>
          NVD API Key (optional){' '}
          <InfoTooltip text="Requests without a key are rate-limited to 5 req/30s. A free key raises the limit to 50 req/30s." />
        </span>
        <div className="secure-input-row">
          <input
            type={showKey ? 'text' : 'password'}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="Leave blank to use anonymous rate limits"
            autoComplete="off"
          />
          <button
            type="button"
            className="btn btn-secondary btn-inline"
            onClick={() => setShowKey((v) => !v)}
          >
            {showKey ? 'Hide' : 'Show'}
          </button>
        </div>
        <span className="field-hint">
          Leave blank to run the standard incremental sync. Provide a key to queue a full NVD sync using this one-time override.
        </span>
      </label>
    </div>
  );

  return (
    <VulnIntelConnectorPage
      config={{
        title: 'NVD Vulnerability Feed',
        sourceKey: 'NVD',
        triggerSync: () => hasApiKeyOverride
          ? api.syncNvdFull({ apiKey: apiKey.trim() })
          : api.syncNvd(),
        configFields,
        triggerLabel: hasApiKeyOverride ? 'Run Full Sync' : 'Run Incremental Sync',
        runNote: hasApiKeyOverride
          ? 'The API key is only sent with this full-sync request. Incremental syncs continue to use the server default configuration.'
          : 'Incremental sync uses the default 24-hour lookback. Enter an API key above if you need a full historical NVD sync.'
      }}
      lastRun={lastRun}
    />
  );
}
