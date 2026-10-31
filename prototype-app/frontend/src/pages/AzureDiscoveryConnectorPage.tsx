import { Link } from 'react-router-dom';
import { pathForInventoryView } from '../app/routes';
import { useAzureDiscoveryConfigQuery, useAzureDiscoveryTargetsQuery } from '../features/connect/queries';

export function AzureDiscoveryConnectorPage() {
  const configQuery = useAzureDiscoveryConfigQuery();
  const config = configQuery.data;
  const targetsQuery = useAzureDiscoveryTargetsQuery(Boolean(config?.configured));
  return (
    <section className="panel">
      <h2>Azure Cloud Discovery</h2>
      {/* Paused for the pilot (N11): unavailable by policy, which is different from a failed load below. */}
      <div className="notice warning">
        <p role="status">Disabled for the pilot. Existing inventory and saved settings are retained.</p>
        <p>Connection tests, configuration changes and discovery runs are unavailable while collection is paused.</p>
      </div>
      {configQuery.isPending && <p className="muted">Loading saved Azure settings…</p>}
      {configQuery.isError && <p className="notice error" role="alert">Saved Azure settings could not be loaded.</p>}
      {config && !config.configured && <p>No Azure settings were saved before collection was paused.</p>}
      {config?.azureTenantId && <p>Saved directory: {config.azureTenantId}</p>}
      {targetsQuery.isError && <p className="notice error" role="alert">Saved subscriptions could not be loaded.</p>}
      {(targetsQuery.data ?? []).length > 0 && (
        <div>
          <h3>Saved subscriptions</h3>
          <ul>{targetsQuery.data?.map((target) => (
            <li key={target.id}>{target.subscriptionName || target.subscriptionId} — {target.subscriptionId}</li>
          ))}</ul>
        </div>
      )}
      <p>
        <Link className="btn-link" to={pathForInventoryView('cloud-resources')}>View retained cloud inventory →</Link>
      </p>
    </section>
  );
}
