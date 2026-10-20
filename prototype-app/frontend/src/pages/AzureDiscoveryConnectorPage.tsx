import { useAzureDiscoveryConfigQuery, useAzureDiscoveryTargetsQuery } from '../features/connect/queries';

export function AzureDiscoveryConnectorPage() {
  const configQuery = useAzureDiscoveryConfigQuery();
  const config = configQuery.data;
  const targetsQuery = useAzureDiscoveryTargetsQuery(Boolean(config?.configured));
  return (
    <section className="panel">
      <h2>Azure Cloud Discovery</h2>
      <p role="status">Disabled for the pilot. Existing inventory and saved settings are retained.</p>
      <p>Connection tests, configuration changes and discovery runs are unavailable while collection is paused.</p>
      {configQuery.isError && <p role="alert">Saved Azure settings could not be loaded.</p>}
      {config?.azureTenantId && <p>Saved directory: {config.azureTenantId}</p>}
      {targetsQuery.isError && <p role="alert">Saved subscriptions could not be loaded.</p>}
      {(targetsQuery.data ?? []).length > 0 && (
        <div>
          <h3>Saved subscriptions</h3>
          <ul>{targetsQuery.data?.map((target) => (
            <li key={target.id}>{target.subscriptionName || target.subscriptionId} — {target.subscriptionId}</li>
          ))}</ul>
        </div>
      )}
    </section>
  );
}
