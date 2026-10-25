import { api } from '../api/client';
import type { VulnIntelSourceStatus } from '../api/client';
import { VulnIntelConnectorPage } from './VulnIntelConnectorPage';

type Props = { lastRun?: VulnIntelSourceStatus };

export function KevConnectorPage({ lastRun }: Props) {
  return (
    <VulnIntelConnectorPage
      config={{
        title: 'CISA KEV Feed',
        sourceKey: 'KEV',
        triggerSync: () => api.syncKev()
      }}
      lastRun={lastRun}
    />
  );
}
