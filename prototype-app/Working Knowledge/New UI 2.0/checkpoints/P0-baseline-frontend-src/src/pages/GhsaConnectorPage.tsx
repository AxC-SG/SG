import React from 'react';
import { api } from '../api/client';
import type { VulnIntelSourceStatus } from '../api/client';
import { InfoTooltip } from '../components/InfoTooltip';
import { VulnIntelConnectorPage } from './VulnIntelConnectorPage';

type Props = { lastRun?: VulnIntelSourceStatus };

export function GhsaConnectorPage({ lastRun }: Props) {
  const configFields = (
    <div className="form-grid">
      <div className="inline-note">
        GitHub Advisory Database (GHSA) is fetched using the GitHub GraphQL API.
        The GitHub token is configured server-side in{' '}
        <code>backend/secrets/github-api-token</code> or via the{' '}
        <code>GITHUB_API_TOKEN</code> environment variable.{' '}
        <InfoTooltip text="The token requires no special scopes — public advisory data is accessible with any valid token." />
      </div>
    </div>
  );

  return (
    <VulnIntelConnectorPage
      config={{
        title: 'GitHub Advisory Database (GHSA)',
        sourceKey: 'GHSA',
        triggerSync: () => api.syncGhsa(),
        configFields
      }}
      lastRun={lastRun}
    />
  );
}
